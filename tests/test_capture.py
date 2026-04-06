"""
tests/test_capture.py — Unit tests for capture/tshark_runner.py

Uses unittest.mock to simulate TShark subprocess output so tests
run without TShark installed.
"""

import subprocess
import unittest
from unittest.mock import patch, MagicMock

from capture.tshark_runner import (
    build_tshark_command,
    parse_tshark_output,
    run_tshark,
    start_capture,
)
from config.settings import TSHARK_FIELDS


class TestBuildTsharkCommand(unittest.TestCase):
    """Tests for build_tshark_command()."""

    def test_live_capture_basic(self):
        """Live mode produces -i <interface> and field flags."""
        cmd = build_tshark_command(interface="eth0", duration=30)
        self.assertEqual(cmd[0], "tshark")
        self.assertIn("-i", cmd)
        self.assertEqual(cmd[cmd.index("-i") + 1], "eth0")
        self.assertIn("-T", cmd)
        self.assertEqual(cmd[cmd.index("-T") + 1], "fields")

    def test_live_capture_duration(self):
        """Duration is set via -a duration:<n>."""
        cmd = build_tshark_command(interface="wlan0", duration=60)
        self.assertIn("-a", cmd)
        self.assertEqual(cmd[cmd.index("-a") + 1], "duration:60")

    def test_pcap_mode(self):
        """Offline mode uses -r <file> and no -i flag."""
        cmd = build_tshark_command(pcap_file="data/sample.pcap")
        self.assertIn("-r", cmd)
        self.assertEqual(cmd[cmd.index("-r") + 1], "data/sample.pcap")
        self.assertNotIn("-i", cmd)

    def test_custom_tshark_path(self):
        """Custom tshark binary path is used as cmd[0]."""
        cmd = build_tshark_command(
            interface="eth0", tshark_path="/usr/local/bin/tshark"
        )
        self.assertEqual(cmd[0], "/usr/local/bin/tshark")

    def test_all_fields_included(self):
        """All default TSHARK_FIELDS appear as -e arguments."""
        cmd = build_tshark_command(interface="eth0")
        for field in TSHARK_FIELDS:
            self.assertIn(field, cmd)

    def test_raises_without_source(self):
        """ValueError when neither interface nor pcap_file is given."""
        with self.assertRaises(ValueError):
            build_tshark_command()

    def test_separator_flag(self):
        """Tab separator is set via -E separator=\\t."""
        cmd = build_tshark_command(interface="eth0")
        self.assertIn("separator=\t", " ".join(cmd))


class TestParseTsharkOutput(unittest.TestCase):
    """Tests for parse_tshark_output()."""

    MOCK_OUTPUT = (
        "192.168.1.10\t10.0.0.1\t128\t1700000000.123\t0x0018\t6\n"
        "10.0.0.1\t192.168.1.10\t256\t1700000000.456\t0x0010\t6\n"
        "172.16.0.5\t8.8.8.8\t64\t1700000000.789\t\t17\n"
    )

    def test_parses_correct_count(self):
        """Three lines produce three packet dicts."""
        packets = parse_tshark_output(self.MOCK_OUTPUT)
        self.assertEqual(len(packets), 3)

    def test_packet_keys(self):
        """Each packet dict has all expected field keys."""
        packets = parse_tshark_output(self.MOCK_OUTPUT)
        for pkt in packets:
            for field in TSHARK_FIELDS:
                self.assertIn(field, pkt)

    def test_packet_values(self):
        """First packet has correct field values."""
        packets = parse_tshark_output(self.MOCK_OUTPUT)
        first = packets[0]
        self.assertEqual(first["ip.src"], "192.168.1.10")
        self.assertEqual(first["ip.dst"], "10.0.0.1")
        self.assertEqual(first["frame.len"], "128")
        self.assertEqual(first["tcp.flags"], "0x0018")
        self.assertEqual(first["ip.proto"], "6")

    def test_empty_output(self):
        """Empty string returns empty list."""
        self.assertEqual(parse_tshark_output(""), [])

    def test_whitespace_only_output(self):
        """Whitespace-only input returns empty list."""
        self.assertEqual(parse_tshark_output("   \n  \n"), [])

    def test_malformed_line_skipped(self):
        """Lines with wrong field count are skipped."""
        bad_output = "192.168.1.1\t10.0.0.1\n"  # only 2 fields
        packets = parse_tshark_output(bad_output)
        self.assertEqual(len(packets), 0)

    def test_empty_field_preserved(self):
        """Empty fields (e.g. missing tcp.flags) are preserved as ''."""
        packets = parse_tshark_output(self.MOCK_OUTPUT)
        third = packets[2]
        self.assertEqual(third["tcp.flags"], "")


class TestRunTshark(unittest.TestCase):
    """Tests for run_tshark() — mocked subprocess."""

    @patch("capture.tshark_runner.shutil.which", return_value=None)
    def test_missing_tshark_raises(self, _mock_which):
        """FileNotFoundError when tshark is not installed."""
        with self.assertRaises(FileNotFoundError):
            run_tshark(["tshark", "-r", "test.pcap"])

    @patch("capture.tshark_runner.shutil.which", return_value="/usr/bin/tshark")
    @patch("capture.tshark_runner.subprocess.run")
    def test_nonzero_exit_raises(self, mock_run, _mock_which):
        """RuntimeError on non-zero exit code."""
        mock_run.return_value = MagicMock(
            returncode=2, stdout="", stderr="permission denied"
        )
        with self.assertRaises(RuntimeError):
            run_tshark(["tshark", "-i", "eth0"])

    @patch("capture.tshark_runner.shutil.which", return_value="/usr/bin/tshark")
    @patch("capture.tshark_runner.subprocess.run")
    def test_success_returns_stdout(self, mock_run, _mock_which):
        """Successful run returns stdout string."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="line1\nline2\n", stderr=""
        )
        output = run_tshark(["tshark", "-r", "test.pcap"])
        self.assertEqual(output, "line1\nline2\n")


class TestStartCapture(unittest.TestCase):
    """Integration-level test for start_capture() — full pipeline mocked."""

    MOCK_STDOUT = (
        "192.168.1.10\t10.0.0.1\t128\t1700000000.123\t0x0018\t6\n"
        "10.0.0.1\t192.168.1.10\t256\t1700000000.456\t0x0010\t6\n"
    )

    @patch("capture.tshark_runner.shutil.which", return_value="/usr/bin/tshark")
    @patch("capture.tshark_runner.subprocess.run")
    def test_end_to_end(self, mock_run, _mock_which):
        """start_capture returns parsed packet dicts."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout=self.MOCK_STDOUT, stderr=""
        )
        packets = start_capture(pcap_file="data/sample.pcap")

        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0]["ip.src"], "192.168.1.10")
        self.assertEqual(packets[1]["frame.len"], "256")

    @patch("capture.tshark_runner.shutil.which", return_value="/usr/bin/tshark")
    @patch("capture.tshark_runner.subprocess.run")
    def test_empty_capture(self, mock_run, _mock_which):
        """start_capture returns [] when no packets captured."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        packets = start_capture(interface="eth0", duration=5)
        self.assertEqual(packets, [])


if __name__ == "__main__":
    unittest.main()
