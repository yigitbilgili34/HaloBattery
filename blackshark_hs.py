"""Razer BlackShark V2 HyperSpeed (2.4 GHz dongle 1532:0565): the MediaTek protocol.

Unlike the BlackShark V2 Pro (2023, "PA"/MXIC protocol, see blackshark.py) this
headset answers 64-byte vendor reports of its own, on the interface-3 collection with
Usage Page 0xFF14 (0xFF00 as a fallback), Report ID 0x02. The format comes from the
reverse-engineered, hardware-verified notes of
https://github.com/justik13/razer-blackshark-v2-hyperspeed-webhid (MIT) and
openrazer/openrazer#2316 / #2974.

Report (report id 0x02 + 63 payload bytes; offsets below are payload offsets):
    [0]  0x00
    [1]  0x60 | seq        rolling 5-bit counter
    [5]  0x04              length of a query
    [8]  0x80              domain: 2.4 GHz RF (headset)
    [9]  command id        0x21 = battery level, 0x2A = charging state
    [10] ack flag          0x00 in a request, 0x01 in a reply
    [11] parameter count   0 in a query
    [12..] data            the value, in a reply
    [61] XOR checksum      0x02 ^ payload[0] ^ ... ^ payload[60]
"""
from __future__ import annotations

import time
from typing import List, Optional, Tuple

import hid

from .base import hexdump

PID = 0x0565
REPORT_ID = 0x02
REPORT_LEN = 64              # report id + 63 payload bytes

CMD_BATTERY = 0x21
CMD_CHARGING = 0x2A

ATTEMPTS = 3
REPLY_TIMEOUT_MS = 400

_seq = 0


def frame_query(cmd_id: int, seq: int = 0) -> bytes:
    f = bytearray(REPORT_LEN)
    f[0] = REPORT_ID
    p = bytearray(63)
    p[1] = 0x60 | (seq & 0x1F)
    p[5] = 0x04
    p[8] = 0x80
    p[9] = cmd_id
    chk = REPORT_ID
    for b in p[:61]:
        chk ^= b
    p[61] = chk
    f[1:] = p
    return bytes(f)


def parse_reply(data, cmd_id: int) -> Optional[List[int]]:
    """The data bytes of a reply to cmd_id, or None for any other report."""
    d = list(data or [])
    # hidapi on Windows hands the report id back as the first byte; the variant
    # without it is accepted too.
    if len(d) >= REPORT_LEN and d[0] == REPORT_ID:
        d = d[1:]
    if len(d) < 13 or d[9] != cmd_id:
        return None
    n = d[11]
    return d[12:12 + max(n, 1)]


def is_candidate(info: dict) -> bool:
    return info.get("usage_page") in (0xFF14, 0xFF00)


def _query(dev, cmd_id: int, diag: List[str]) -> Optional[List[int]]:
    global _seq
    try:                                   # throw away anything that is still queued
        for _ in range(32):
            if not dev.read(REPORT_LEN, 5):
                break
    except (OSError, ValueError):
        pass
    for attempt in range(ATTEMPTS):
        _seq = (_seq + 1) & 0x1F
        try:
            n = dev.write(frame_query(cmd_id, _seq))
        except (OSError, ValueError) as e:
            diag.append(f"    write: {e}")
            return None
        if n is None or n < 0:
            err = ""
            try:
                err = dev.error() or ""
            except Exception:
                pass
            diag.append(f"    write -> {n} {err}".rstrip())
            return None
        deadline = time.time() + REPLY_TIMEOUT_MS / 1000
        while time.time() < deadline:
            try:
                data = dev.read(REPORT_LEN, 50)
            except (OSError, ValueError) as e:
                diag.append(f"    read: {e}")
                break
            if not data:
                continue
            payload = parse_reply(data, cmd_id)
            if payload is not None:
                diag.append(f"    cmd {cmd_id:02x} attempt {attempt + 1}: {hexdump(data, 20)}")
                return payload
            diag.append(f"    other report: {hexdump(data, 20)}")
        diag.append(f"    cmd {cmd_id:02x} attempt {attempt + 1}: no reply")
    return None


def read_battery(path: bytes, diag: List[str]) -> Tuple[str, Optional[int], bool]:
    """-> ('ok'|'offline'|'fail', level, charging)

    'ok'      - a reading.
    'offline' - the collection accepted the request and nothing answered: headset off.
    'fail'    - the collection could not be opened or written to.
    """
    dev = hid.device()
    try:
        dev.open_path(path)
    except (OSError, IOError) as e:
        diag.append(f"    open: {e}")
        return "fail", None, False
    try:
        bat = _query(dev, CMD_BATTERY, diag)
        if bat is None:
            return "offline", None, False
        level = bat[0]
        if level > 100:
            diag.append(f"    unexpected battery value: {level}")
            level = min(level, 100)
        chg = _query(dev, CMD_CHARGING, diag)
        return "ok", level, bool(chg and chg[0])
    finally:
        try:
            dev.close()
        except Exception:
            pass
