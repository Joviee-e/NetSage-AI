"""
models/dataset_loader.py - CICIDS2017 loading and preprocessing helpers.

Responsibilities:
    - Load and concatenate all CSV files from a directory
    - Normalize column names
    - Clean invalid values (inf -> NaN, drop NaN rows)
    - Build numeric feature matrix and normalized label series
"""

from __future__ import annotations

import os
from glob import glob
from typing import List, Tuple

import numpy as np
import pandas as pd

from utils.logger import setup_logger

logger = setup_logger("models.dataset_loader")

DROP_COLUMNS = {
    "flow_id",
    "source_ip",
    "destination_ip",
    "timestamp",
}


def normalize_column_name(name: str) -> str:
    """Normalize raw column names to snake_case lowercase."""
    return str(name).strip().lower().replace("/", "_").replace(" ", "_")


def _read_csv_files(data_dir: str) -> List[pd.DataFrame]:
    """Read all CSV files under the given directory."""
    pattern = os.path.join(data_dir, "*.csv")
    csv_paths = sorted(glob(pattern))
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in: {data_dir}")

    logger.info("Loading CICIDS2017 CSV files from %s", data_dir)
    logger.info("CSV files found: %d", len(csv_paths))

    frames: List[pd.DataFrame] = []
    for path in csv_paths:
        logger.info("Reading %s", os.path.basename(path))
        frames.append(pd.read_csv(path, low_memory=False))
    return frames


def load_cicids_dataframe(data_dir: str) -> pd.DataFrame:
    """Load and clean CICIDS2017 CSV files into one DataFrame."""
    if not data_dir or not isinstance(data_dir, str):
        raise ValueError("data_dir must be a non-empty string.")

    if not os.path.isdir(data_dir):
        raise FileNotFoundError(f"Dataset directory not found: {data_dir}")

    frames = _read_csv_files(data_dir)
    df = pd.concat(frames, ignore_index=True)

    df.columns = [normalize_column_name(c) for c in df.columns]
    if "label" not in df.columns:
        raise ValueError("Required column 'label' was not found in CICIDS dataset.")

    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(axis=0, how="any")
    dropped = before - len(df)
    if dropped:
        logger.info("Dropped rows with NaN/inf values: %d", dropped)

    logger.info("Dataset loaded. Rows: %d | Columns: %d", len(df), len(df.columns))
    return df


def prepare_features_and_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Create numeric feature matrix and normalized labels."""
    if "label" not in df.columns:
        raise ValueError("Input DataFrame must include a 'label' column.")

    labels = (
        df["label"]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
    )
    labels = labels.where(labels != "benign", "normal")

    feature_df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns] + ["label"])
    feature_df = feature_df.select_dtypes(include=["number"]).copy()

    if feature_df.empty:
        raise ValueError("No numeric features available after CICIDS preprocessing.")

    logger.info("Numeric features selected: %d", feature_df.shape[1])
    return feature_df, labels


def load_cicids_features_labels(data_dir: str) -> Tuple[pd.DataFrame, pd.Series]:
    """Load CICIDS data from disk and return (X, y)."""
    df = load_cicids_dataframe(data_dir)
    return prepare_features_and_labels(df)
