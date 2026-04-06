"""
features/extractor.py — Feature engineering from raw packet dictionaries.

Converts the List[Dict[str, str]] output of capture/tshark_runner.py
into a pandas DataFrame with ML-ready numeric columns.

Pipeline:
    raw_to_dataframe()      → dict list to DataFrame (strings)
    cast_numeric_columns()  → coerce numeric fields, fill NaN with 0
    engineer_features()     → derive is_tcp, is_udp, flags bitmask, hour, etc.
    select_model_features() → return only the columns the model expects
    extract_features()      → high-level orchestrator called by main.py
"""

from typing import Dict, List, Optional

import pandas as pd

from utils.logger import setup_logger

logger = setup_logger("features.extractor")

# ── Column groups ────────────────────────────────────────────────────────────

# Raw TShark field names (must match capture/tshark_runner.py output keys)
RAW_FIELDS = [
    "ip.src",
    "ip.dst",
    "frame.len",
    "frame.time_epoch",
    "tcp.flags",
    "ip.proto",
]

# Columns that should be cast to numeric after import
NUMERIC_COLUMNS = ["frame.len", "frame.time_epoch", "ip.proto"]

# Final feature columns expected by the ML models
MODEL_FEATURES = [
    "frame_len",
    "ip_proto",
    "is_tcp",
    "is_udp",
    "tcp_flag_syn",
    "tcp_flag_ack",
    "tcp_flag_fin",
    "tcp_flag_rst",
    "tcp_flag_psh",
    "hour_of_day",
]


# ── Public API ───────────────────────────────────────────────────────────────


def raw_to_dataframe(packets: List[Dict[str, str]]) -> pd.DataFrame:
    """Convert a list of packet dicts into a pandas DataFrame.

    All values arrive as strings from TShark.  This function creates
    the DataFrame without any type casting — that is handled separately
    by cast_numeric_columns().

    Args:
        packets: List of dicts from capture/tshark_runner.parse_tshark_output().

    Returns:
        DataFrame with one row per packet and string-typed columns.

    Raises:
        ValueError: If the packet list is empty.
    """
    if not packets:
        logger.error("Received empty packet list — cannot build DataFrame.")
        raise ValueError("Cannot create DataFrame from an empty packet list.")

    df = pd.DataFrame(packets)
    logger.info("Created DataFrame: %d rows × %d columns.", len(df), len(df.columns))
    return df


def cast_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Cast known numeric columns from string to float, filling blanks with 0.

    TShark emits every field as a string.  Missing or empty fields
    (e.g. tcp.flags on a UDP packet) become empty strings, which must
    be handled gracefully.

    Args:
        df: DataFrame with raw string columns.

    Returns:
        DataFrame with numeric columns cast to float64.
    """
    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    logger.debug("Numeric columns cast: %s", NUMERIC_COLUMNS)
    return df


def _parse_tcp_flags(flag_str: str) -> int:
    """Convert a TShark TCP flags string to an integer bitmask.

    TShark outputs tcp.flags as a hex string like "0x0018".
    Empty or invalid values return 0.

    Args:
        flag_str: Hex string from TShark (e.g. "0x0018").

    Returns:
        Integer bitmask of the TCP flags.
    """
    if not flag_str or not isinstance(flag_str, str):
        return 0
    flag_str = flag_str.strip()
    if not flag_str:
        return 0
    try:
        return int(flag_str, 16)
    except ValueError:
        return 0


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive ML-ready features from raw packet columns.

    New columns created:
        frame_len      — packet length (renamed from frame.len)
        ip_proto       — IP protocol number (renamed from ip.proto)
        is_tcp         — 1 if protocol == 6, else 0
        is_udp         — 1 if protocol == 17, else 0
        tcp_flag_syn   — 1 if SYN bit set
        tcp_flag_ack   — 1 if ACK bit set
        tcp_flag_fin   — 1 if FIN bit set
        tcp_flag_rst   — 1 if RST bit set
        tcp_flag_psh   — 1 if PSH bit set
        hour_of_day    — hour extracted from epoch timestamp (0-23)

    Args:
        df: DataFrame after cast_numeric_columns().

    Returns:
        DataFrame with derived feature columns appended.
    """
    # ── Rename raw columns to ML-friendly names ──────────────────────────────
    df["frame_len"] = df["frame.len"]
    df["ip_proto"] = df["ip.proto"]

    # ── Protocol flags ───────────────────────────────────────────────────────
    df["is_tcp"] = (df["ip_proto"] == 6).astype(int)
    df["is_udp"] = (df["ip_proto"] == 17).astype(int)

    # ── TCP flag bitmask parsing ─────────────────────────────────────────────
    flags_int = df["tcp.flags"].apply(_parse_tcp_flags)

    # TCP flag bit positions (RFC 793)
    df["tcp_flag_fin"] = ((flags_int & 0x01) != 0).astype(int)
    df["tcp_flag_syn"] = ((flags_int & 0x02) != 0).astype(int)
    df["tcp_flag_rst"] = ((flags_int & 0x04) != 0).astype(int)
    df["tcp_flag_psh"] = ((flags_int & 0x08) != 0).astype(int)
    df["tcp_flag_ack"] = ((flags_int & 0x10) != 0).astype(int)

    # ── Timestamp features ───────────────────────────────────────────────────
    df["hour_of_day"] = (
        pd.to_datetime(df["frame.time_epoch"], unit="s", errors="coerce")
        .dt.hour
        .fillna(0)
        .astype(int)
    )

    logger.info(
        "Engineered %d feature columns: %s",
        len(MODEL_FEATURES),
        ", ".join(MODEL_FEATURES),
    )
    return df


def select_model_features(
    df: pd.DataFrame,
    features: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Return only the columns the ML model expects.

    Also retains ip.src and ip.dst for traceability in downstream
    modules (detection / classification / visualization).

    Args:
        df:       DataFrame with all raw + engineered columns.
        features: Column names to select (default: MODEL_FEATURES).

    Returns:
        DataFrame containing only model feature columns plus IP addresses.
    """
    features = features or list(MODEL_FEATURES)

    # Always keep IP addresses for report context
    keep_cols = ["ip.src", "ip.dst"] + features

    # Only select columns that actually exist
    available = [c for c in keep_cols if c in df.columns]
    missing = set(keep_cols) - set(available)
    if missing:
        logger.warning("Requested columns not found in DataFrame: %s", missing)

    selected = df[available].copy()
    logger.info(
        "Selected %d columns for model input (%d feature + IP context).",
        len(available),
        len([c for c in available if c in features]),
    )
    return selected


def extract_features(
    packets: List[Dict[str, str]],
    features: Optional[List[str]] = None,
) -> pd.DataFrame:
    """High-level pipeline: raw packets → ML-ready DataFrame.

    This is the function called by main.py.

    Args:
        packets:  List of dicts from start_capture().
        features: Optional list of model feature column names.

    Returns:
        pandas DataFrame ready for anomaly detection / classification.

    Raises:
        ValueError: If the packet list is empty.
    """
    logger.info("Feature extraction pipeline started — %d packets.", len(packets))

    # 1. Dict list → DataFrame
    df = raw_to_dataframe(packets)

    # 2. Cast numeric columns
    df = cast_numeric_columns(df)

    # 3. Engineer derived features
    df = engineer_features(df)

    # 4. Select model columns
    df = select_model_features(df, features=features)

    logger.info(
        "Feature extraction complete — output shape: %d × %d.",
        df.shape[0],
        df.shape[1],
    )
    return df
