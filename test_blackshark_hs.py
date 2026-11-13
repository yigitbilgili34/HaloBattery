"""BlackShark V2 HyperSpeed (1532:0565): MediaTek protocol frames and replies.

The frame layout comes from the hardware-verified notes of
razer-blackshark-v2-hyperspeed-webhid; the replies here are built from that layout,
not captured from a headset in this repository.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from providers import blackshark, blackshark_hs, razer  # noqa: E402


def reply(cmd: int, value: int, with_report_id: bool = True) -> bytes:
    p = bytearray(63)
    p[1] = 0x60
    p[5] = 0x05
    p[8] = 0x80
    p[9] = cmd
    p[10] = 0x01
    p[11] = 0x01
    p[12] = value
    return bytes(([blackshark_hs.REPORT_ID] if with_report_id else []) + list(p))


class FakeDevice:
    def __init__(self, battery=None, charging=0):
        self.battery = battery
        self.charging = charging
        self.written = []
        self.queue = []

    def open_path(self, path):
        pass

    def close(self):
        pass

    def write(self, data):
        self.written.append(bytes(data))
        cmd = data[10]          # report id + payload offset 9
        if cmd == blackshark_hs.CMD_BATTERY and self.battery is not None:
            self.queue.append(reply(cmd, self.battery))
        elif cmd == blackshark_hs.CMD_CHARGING and self.battery is not None:
            self.queue.append(reply(cmd, self.charging))
        return len(data)

    def read(self, n, timeout=0):
        return list(self.queue.pop(0)) if self.queue else []


class FrameTests(unittest.TestCase):
    def test_battery_query_layout(self):
        f = blackshark_hs.frame_query(blackshark_hs.CMD_BATTERY, seq=3)
        self.assertEqual(len(f), 64)
        self.assertEqual(f[0], 0x02)
        self.assertEqual(f[2], 0x63)       # 0x60 | seq
        self.assertEqual(f[6], 0x04)       # length
        self.assertEqual(f[9], 0x80)       # domain: 2.4 GHz
        self.assertEqual(f[10], 0x21)      # battery command
        self.assertEqual(f[11], 0x00)      # ack flag
        self.assertEqual(f[12], 0x00)      # parameter count

    def test_checksum_is_xor_of_report_id_and_first_61_payload_bytes(self):
        for cmd in (0x21, 0x2A):
            f = blackshark_hs.frame_query(cmd, seq=5)
            x = 0x02
            for b in f[1:62]:
                x ^= b
            self.assertEqual(f[62], x)
            self.assertEqual(f[63], 0x00)

    def test_parse_reply_with_and_without_report_id(self):
        self.assertEqual(blackshark_hs.parse_reply(reply(0x21, 77), 0x21), [77])
        self.assertEqual(blackshark_hs.parse_reply(reply(0x21, 77, False), 0x21), [77])

    def test_parse_reply_ignores_other_commands(self):
        self.assertIsNone(blackshark_hs.parse_reply(reply(0x2A, 1), 0x21))
        self.assertIsNone(blackshark_hs.parse_reply([], 0x21))
        self.assertIsNone(blackshark_hs.parse_reply(None, 0x21))


class ReadBatteryTests(unittest.TestCase):
    def read(self, dev):
        with mock.patch.object(blackshark_hs.hid, "device", return_value=dev), \
                mock.patch.object(blackshark_hs, "REPLY_TIMEOUT_MS", 20), \
                mock.patch.object(blackshark_hs.time, "sleep", lambda s: None):
            return blackshark_hs.read_battery(b"path", [])

    def test_level_and_charging(self):
        self.assertEqual(self.read(FakeDevice(battery=64, charging=0)), ("ok", 64, False))
        self.assertEqual(self.read(FakeDevice(battery=100, charging=1)), ("ok", 100, True))

    def test_no_reply_means_offline(self):
        self.assertEqual(self.read(FakeDevice(battery=None)), ("offline", None, False))

    def test_level_is_capped(self):
        self.assertEqual(self.read(FakeDevice(battery=200))[1], 100)


class WiringTests(unittest.TestCase):
    def test_pid_is_known_and_not_a_pa_headset(self):
        self.assertEqual(blackshark_hs.PID, 0x0565)
        self.assertIn(0x0565, razer.KNOWN)
        self.assertNotIn(0x0565, blackshark.PA_PIDS)

    def test_candidate_pages(self):
        self.assertTrue(blackshark_hs.is_candidate({"usage_page": 0xFF14}))
        self.assertTrue(blackshark_hs.is_candidate({"usage_page": 0xFF00}))
        self.assertFalse(blackshark_hs.is_candidate({"usage_page": 0xFF13}))
        self.assertFalse(blackshark_hs.is_candidate({"usage_page": 0x000C}))


if __name__ == "__main__":
    unittest.main()
