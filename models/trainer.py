"""
models/trainer.py - Training entrypoint for synthetic and CICIDS2017 data.
"""

from __future__ import annotations

import os
import pickle
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from models.dataset_loader import load_cicids_features_labels
from models.feature_schema import FEATURES_SCHEMA_PATH, save_feature_schema
from utils.logger import setup_logger

logger = setup_logger("models.trainer")

MODEL_DIR = os.path.join("models", "saved")
ISOLATION_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
CLASSIFIER_PATH = os.path.join(MODEL_DIR, "random_forest.pkl")
DEFAULT_CICIDS_PATH = os.path.join("data", "raw", "cicids2017")
MAX_NORMAL_ROWS = 300_000
MAX_CLASSIFIER_ROWS = 500_000

FEATURE_COLUMNS: List[str] = [
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


def generate_synthetic_data(n_rows: int = 1000, random_state: int = 42) -> pd.DataFrame:
    """Generate a simple synthetic packet dataset with attack labels."""
    rng = np.random.default_rng(random_state)

    labels = rng.choice(
        ["normal", "port_scan", "ddos"],
        size=n_rows,
        p=[0.7, 0.15, 0.15],
    )

    rows = []
    for label in labels:
        if label == "normal":
            frame_len = int(np.clip(rng.normal(700, 120), 60, 1500))
            ip_proto = int(rng.choice([6, 17], p=[0.8, 0.2]))
            tcp_flag_syn = int(rng.choice([0, 1], p=[0.85, 0.15]))
            tcp_flag_ack = int(rng.choice([0, 1], p=[0.25, 0.75]))
            tcp_flag_fin = int(rng.choice([0, 1], p=[0.95, 0.05]))
            tcp_flag_rst = int(rng.choice([0, 1], p=[0.97, 0.03]))
            tcp_flag_psh = int(rng.choice([0, 1], p=[0.80, 0.20]))
            hour_of_day = int(rng.integers(6, 23))

        elif label == "port_scan":
            frame_len = int(np.clip(rng.normal(90, 30), 40, 300))
            ip_proto = 6
            tcp_flag_syn = 1
            tcp_flag_ack = int(rng.choice([0, 1], p=[0.9, 0.1]))
            tcp_flag_fin = 0
            tcp_flag_rst = int(rng.choice([0, 1], p=[0.7, 0.3]))
            tcp_flag_psh = 0
            hour_of_day = int(rng.integers(0, 24))

        else:  # ddos
            frame_len = int(np.clip(rng.normal(1400, 80), 800, 1600))
            ip_proto = int(rng.choice([6, 17], p=[0.6, 0.4]))
            tcp_flag_syn = int(rng.choice([0, 1], p=[0.3, 0.7]))
            tcp_flag_ack = int(rng.choice([0, 1], p=[0.4, 0.6]))
            tcp_flag_fin = 0
            tcp_flag_rst = int(rng.choice([0, 1], p=[0.8, 0.2]))
            tcp_flag_psh = int(rng.choice([0, 1], p=[0.6, 0.4]))
            hour_of_day = int(rng.integers(0, 24))

        is_tcp = int(ip_proto == 6)
        is_udp = int(ip_proto == 17)

        rows.append(
            {
                "frame_len": frame_len,
                "ip_proto": ip_proto,
                "is_tcp": is_tcp,
                "is_udp": is_udp,
                "tcp_flag_syn": tcp_flag_syn,
                "tcp_flag_ack": tcp_flag_ack,
                "tcp_flag_fin": tcp_flag_fin,
                "tcp_flag_rst": tcp_flag_rst,
                "tcp_flag_psh": tcp_flag_psh,
                "hour_of_day": hour_of_day,
                "attack_type": label,
            }
        )

    return pd.DataFrame(rows)


def train_isolation_forest(df: pd.DataFrame, feature_columns: List[str]) -> IsolationForest:
    """Train IsolationForest on feature columns only."""
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(df[feature_columns])
    return model


def train_random_forest(df: pd.DataFrame, feature_columns: List[str]) -> RandomForestClassifier:
    """Train RandomForestClassifier on labeled attack_type values."""
    model = RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=1)
    model.fit(df[feature_columns], df["attack_type"])
    return model


def save_model(model, path: str) -> None:
    """Save a model using pickle, ensuring directory exists."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(model, f)


def run_training(n_rows: int = 1000) -> Tuple[str, str]:
    """Generate synthetic data, train both models, and save them."""
    logger.info("Training started.")

    df = generate_synthetic_data(n_rows=n_rows)

    isolation_model = train_isolation_forest(df, FEATURE_COLUMNS)
    classifier_model = train_random_forest(df, FEATURE_COLUMNS)

    save_model(isolation_model, ISOLATION_PATH)
    save_model(classifier_model, CLASSIFIER_PATH)

    save_feature_schema(FEATURE_COLUMNS, FEATURES_SCHEMA_PATH)
    logger.info(
        "Models saved (synthetic): %s, %s | schema: %s",
        ISOLATION_PATH,
        CLASSIFIER_PATH,
        FEATURES_SCHEMA_PATH,
    )
    logger.info("Training completed.")
    return ISOLATION_PATH, CLASSIFIER_PATH


def train_from_cicids(data_path: str = DEFAULT_CICIDS_PATH) -> Dict[str, str]:
    """Train models using CICIDS2017 and save model artifacts + feature schema."""
    logger.info("CICIDS training started. Dataset path: %s", data_path)
    X, y = load_cicids_features_labels(data_path)

    feature_columns = list(X.columns)
    df = X.copy()
    df["attack_type"] = y

    normal_df = df[df["attack_type"] == "normal"]
    if normal_df.empty:
        raise ValueError("No 'normal' rows found in CICIDS dataset for IsolationForest.")

    if len(normal_df) > MAX_NORMAL_ROWS:
        normal_df = normal_df.sample(n=MAX_NORMAL_ROWS, random_state=42)
        logger.info("Downsampled normal rows for anomaly training to %d", len(normal_df))

    if len(df) > MAX_CLASSIFIER_ROWS:
        sampled_parts = []
        for _, group in df.groupby("attack_type", group_keys=False):
            frac = MAX_CLASSIFIER_ROWS / len(df)
            n_group = max(1, int(len(group) * frac))
            sampled_parts.append(group.sample(n=min(len(group), n_group), random_state=42))
        df = pd.concat(sampled_parts, ignore_index=True)
        logger.info("Downsampled rows for classifier training to %d", len(df))

    logger.info(
        "Dataset ready. Rows for classifier: %d | Rows for anomaly: %d | Features: %d",
        len(df),
        len(normal_df),
        len(feature_columns),
    )

    isolation_model = train_isolation_forest(normal_df, feature_columns)
    classifier_model = train_random_forest(df, feature_columns)

    save_model(isolation_model, ISOLATION_PATH)
    save_model(classifier_model, CLASSIFIER_PATH)
    save_feature_schema(feature_columns, FEATURES_SCHEMA_PATH)

    logger.info("CICIDS models saved: %s, %s", ISOLATION_PATH, CLASSIFIER_PATH)
    logger.info("CICIDS feature schema saved: %s", FEATURES_SCHEMA_PATH)

    return {
        "isolation_model_path": ISOLATION_PATH,
        "classifier_model_path": CLASSIFIER_PATH,
        "features_schema_path": FEATURES_SCHEMA_PATH,
    }


if __name__ == "__main__":
    if os.path.isdir(DEFAULT_CICIDS_PATH):
        train_from_cicids(DEFAULT_CICIDS_PATH)
    else:
        logger.warning(
            "CICIDS dataset directory not found at %s. Falling back to synthetic training.",
            DEFAULT_CICIDS_PATH,
        )
        run_training()
