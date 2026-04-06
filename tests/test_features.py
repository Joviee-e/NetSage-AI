"""
tests/test_features.py — Unit tests for features/extractor.py

Tests cover:
    - raw_to_dataframe: dict→DataFrame conversion, empty input
    - cast_numeric_columns: type casting, NaN handling
    - engineer_features: derived columns, TCP flag parsing
    - select_model_features: column selection, missing columns
    - extract_features: full pipeline integration
"""

import unittest

import pandas as pd

from features.extractor import (
    MODEL_FEATURES,
    _parse_tcp_flags,
    cast_numeric_columns,
    engineer_features,
    extract_features,
    raw_to_dataframe,
    select_model_features,
)


# ── Shared test fixtures ─────────────────────────────────────────────────────

SAMPLE_PACKETS = [
    {
        "ip.src": "192.168.1.10",
        "ip.dst": "10.0.0.1",
        "frame.len": "128",
        "frame.time_epoch": "1700000000.123",
        "tcp.flags": "0x0018",  # PSH + ACK
        "ip.proto": "6",       # TCP
    },
    {
        "ip.src": "10.0.0.1",
        "ip.dst": "192.168.1.10",
        "frame.len": "256",
        "frame.time_epoch": "1700000000.456",
        "tcp.flags": "0x0002",  # SYN only
        "ip.proto": "6",       # TCP
    },
    {
        "ip.src": "172.16.0.5",
        "ip.dst": "8.8.8.8",
        "frame.len": "64",
        "frame.time_epoch": "1700000000.789",
        "tcp.flags": "",        # No flags (UDP)
        "ip.proto": "17",      # UDP
    },
]


class TestRawToDataframe(unittest.TestCase):
    """Tests for raw_to_dataframe()."""

    def test_correct_shape(self):
        """3 packets → 3 rows."""
        df = raw_to_dataframe(SAMPLE_PACKETS)
        self.assertEqual(len(df), 3)
        self.assertEqual(len(df.columns), 6)

    def test_column_names(self):
        """DataFrame columns match packet dict keys."""
        df = raw_to_dataframe(SAMPLE_PACKETS)
        for key in SAMPLE_PACKETS[0]:
            self.assertIn(key, df.columns)

    def test_empty_raises(self):
        """Empty list raises ValueError."""
        with self.assertRaises(ValueError):
            raw_to_dataframe([])


class TestCastNumericColumns(unittest.TestCase):
    """Tests for cast_numeric_columns()."""

    def test_frame_len_is_numeric(self):
        """frame.len should be float64 after casting."""
        df = raw_to_dataframe(SAMPLE_PACKETS)
        df = cast_numeric_columns(df)
        self.assertTrue(pd.api.types.is_numeric_dtype(df["frame.len"]))

    def test_ip_proto_is_numeric(self):
        """ip.proto should be numeric after casting."""
        df = raw_to_dataframe(SAMPLE_PACKETS)
        df = cast_numeric_columns(df)
        self.assertTrue(pd.api.types.is_numeric_dtype(df["ip.proto"]))

    def test_missing_value_filled_zero(self):
        """Empty string fields are filled with 0."""
        packets = [
            {
                "ip.src": "1.1.1.1",
                "ip.dst": "2.2.2.2",
                "frame.len": "",
                "frame.time_epoch": "",
                "tcp.flags": "",
                "ip.proto": "",
            }
        ]
        df = raw_to_dataframe(packets)
        df = cast_numeric_columns(df)
        self.assertEqual(df["frame.len"].iloc[0], 0.0)
        self.assertEqual(df["ip.proto"].iloc[0], 0.0)


class TestParseTcpFlags(unittest.TestCase):
    """Tests for _parse_tcp_flags() helper."""

    def test_hex_parsing(self):
        """0x0018 → 24 (PSH + ACK)."""
        self.assertEqual(_parse_tcp_flags("0x0018"), 0x0018)

    def test_syn_only(self):
        """0x0002 → 2 (SYN)."""
        self.assertEqual(_parse_tcp_flags("0x0002"), 2)

    def test_empty_string(self):
        """Empty string → 0."""
        self.assertEqual(_parse_tcp_flags(""), 0)

    def test_none_value(self):
        """None → 0."""
        self.assertEqual(_parse_tcp_flags(None), 0)

    def test_invalid_hex(self):
        """Non-hex string → 0."""
        self.assertEqual(_parse_tcp_flags("not_a_number"), 0)


class TestEngineerFeatures(unittest.TestCase):
    """Tests for engineer_features()."""

    def setUp(self):
        self.df = raw_to_dataframe(SAMPLE_PACKETS)
        self.df = cast_numeric_columns(self.df)
        self.df = engineer_features(self.df)

    def test_is_tcp_flag(self):
        """First two packets are TCP (proto=6), third is UDP."""
        self.assertEqual(self.df["is_tcp"].iloc[0], 1)
        self.assertEqual(self.df["is_tcp"].iloc[1], 1)
        self.assertEqual(self.df["is_tcp"].iloc[2], 0)

    def test_is_udp_flag(self):
        """Third packet is UDP (proto=17)."""
        self.assertEqual(self.df["is_udp"].iloc[0], 0)
        self.assertEqual(self.df["is_udp"].iloc[2], 1)

    def test_tcp_flag_psh_ack(self):
        """First packet (0x0018) has PSH and ACK set."""
        self.assertEqual(self.df["tcp_flag_psh"].iloc[0], 1)
        self.assertEqual(self.df["tcp_flag_ack"].iloc[0], 1)
        self.assertEqual(self.df["tcp_flag_syn"].iloc[0], 0)

    def test_tcp_flag_syn(self):
        """Second packet (0x0002) has only SYN set."""
        self.assertEqual(self.df["tcp_flag_syn"].iloc[1], 1)
        self.assertEqual(self.df["tcp_flag_ack"].iloc[1], 0)
        self.assertEqual(self.df["tcp_flag_fin"].iloc[1], 0)

    def test_udp_no_flags(self):
        """UDP packet has all TCP flags = 0."""
        self.assertEqual(self.df["tcp_flag_syn"].iloc[2], 0)
        self.assertEqual(self.df["tcp_flag_ack"].iloc[2], 0)
        self.assertEqual(self.df["tcp_flag_fin"].iloc[2], 0)
        self.assertEqual(self.df["tcp_flag_rst"].iloc[2], 0)
        self.assertEqual(self.df["tcp_flag_psh"].iloc[2], 0)

    def test_frame_len_renamed(self):
        """frame_len column exists with correct values."""
        self.assertEqual(self.df["frame_len"].iloc[0], 128.0)
        self.assertEqual(self.df["frame_len"].iloc[2], 64.0)

    def test_hour_of_day_valid_range(self):
        """hour_of_day is between 0 and 23."""
        for h in self.df["hour_of_day"]:
            self.assertGreaterEqual(h, 0)
            self.assertLessEqual(h, 23)


class TestSelectModelFeatures(unittest.TestCase):
    """Tests for select_model_features()."""

    def setUp(self):
        self.df = raw_to_dataframe(SAMPLE_PACKETS)
        self.df = cast_numeric_columns(self.df)
        self.df = engineer_features(self.df)

    def test_default_columns(self):
        """Default selection includes MODEL_FEATURES + IP addresses."""
        selected = select_model_features(self.df)
        for feat in MODEL_FEATURES:
            self.assertIn(feat, selected.columns)
        self.assertIn("ip.src", selected.columns)
        self.assertIn("ip.dst", selected.columns)

    def test_custom_features(self):
        """Custom feature list is respected."""
        selected = select_model_features(self.df, features=["frame_len", "is_tcp"])
        self.assertIn("frame_len", selected.columns)
        self.assertIn("is_tcp", selected.columns)
        self.assertIn("ip.src", selected.columns)  # always kept
        self.assertNotIn("tcp_flag_syn", selected.columns)

    def test_missing_column_warning(self):
        """Missing columns are excluded without crashing."""
        selected = select_model_features(self.df, features=["nonexistent_col"])
        self.assertNotIn("nonexistent_col", selected.columns)


class TestExtractFeatures(unittest.TestCase):
    """Integration test for the full extract_features() pipeline."""

    def test_end_to_end(self):
        """Full pipeline produces expected shape and columns."""
        df = extract_features(SAMPLE_PACKETS)
        self.assertEqual(len(df), 3)
        for feat in MODEL_FEATURES:
            self.assertIn(feat, df.columns)

    def test_empty_raises(self):
        """Empty packet list raises ValueError."""
        with self.assertRaises(ValueError):
            extract_features([])

    def test_values_correct(self):
        """Spot-check values through the full pipeline."""
        df = extract_features(SAMPLE_PACKETS)
        # First row: TCP, 128 bytes, PSH+ACK
        self.assertEqual(df["frame_len"].iloc[0], 128.0)
        self.assertEqual(df["is_tcp"].iloc[0], 1)
        self.assertEqual(df["tcp_flag_psh"].iloc[0], 1)
        self.assertEqual(df["tcp_flag_ack"].iloc[0], 1)


if __name__ == "__main__":
    unittest.main()
