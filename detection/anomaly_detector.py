"""
detection/anomaly_detector.py - Isolation Forest inference for packet anomalies.

Loads a trained Isolation Forest model from disk, scores each row of a feature
DataFrame, and appends:
    - is_anomaly    (1 = anomaly, 0 = normal)
    - anomaly_score (float from decision_function)

Functions:
    load_anomaly_model()  - deserialize model from .pkl
    score_packets()       - predict anomaly labels + scores per row
    filter_anomalies()    - return only anomalous rows
    detect_anomalies()    - high-level entrypoint
"""

from __future__ import annotations

import os
import pickle
import tempfile
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest

from utils.logger import setup_logger

logger = setup_logger("detection.anomaly_detector")


def load_anomaly_model(model_path: str) -> IsolationForest:
    """Load a trained IsolationForest model from disk.

    Args:
        model_path: Path to the pickled IsolationForest model file.

    Returns:
        Loaded IsolationForest instance.

    Raises:
        FileNotFoundError: If model_path does not exist.
        ValueError: If model_path is empty or loaded object is not IsolationForest.
    """
    if not model_path or not isinstance(model_path, str):
        raise ValueError("model_path must be a non-empty string.")

    if not os.path.exists(model_path):
        logger.error("Anomaly model file not found: %s", model_path)
        raise FileNotFoundError(f"Anomaly model file not found: {model_path}")

    with open(model_path, "rb") as f:
        model = pickle.load(f)

    if not isinstance(model, IsolationForest):
        raise ValueError(
            "Loaded anomaly model is invalid: expected sklearn IsolationForest."
        )

    logger.info("Loaded IsolationForest model from %s", model_path)
    return model


def score_packets(df: pd.DataFrame, model: IsolationForest) -> pd.DataFrame:
    """Score packets and append anomaly columns.

    Mapping:
        model.predict() -> -1 (anomaly), 1 (normal)
        output is_anomaly -> 1 (anomaly), 0 (normal)

    anomaly_score is taken from model.decision_function().

    Args:
        df: Feature DataFrame with one row per packet.
        model: Trained IsolationForest model.

    Returns:
        Copy of df with added columns: is_anomaly, anomaly_score.

    Raises:
        ValueError: If df is invalid/empty or has no numeric feature columns.
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if df.empty:
        raise ValueError("Input DataFrame is empty; cannot score packets.")

    if model is None or not hasattr(model, "predict") or not hasattr(
        model, "decision_function"
    ):
        raise ValueError("model must support predict() and decision_function().")

    # Exclude output columns if the DataFrame is rescored.
    excluded_cols = {"is_anomaly", "anomaly_score"}
    feature_df = df.drop(columns=[c for c in excluded_cols if c in df.columns])

    numeric_features = feature_df.select_dtypes(include=["number", "bool"])
    if numeric_features.empty:
        raise ValueError("Input DataFrame has no numeric feature columns to score.")

    predictions = model.predict(numeric_features)
    scores = model.decision_function(numeric_features)

    result = df.copy()
    result["is_anomaly"] = (predictions == -1).astype(int)
    result["anomaly_score"] = pd.Series(scores, index=result.index, dtype="float64")

    logger.info("Scored %d packets. Anomalies flagged: %d", len(result), result["is_anomaly"].sum())
    return result


def filter_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Return only anomalous rows (is_anomaly == 1).

    Args:
        df: Scored DataFrame containing is_anomaly column.

    Returns:
        DataFrame containing only anomalous rows.

    Raises:
        ValueError: If df is invalid or missing is_anomaly column.
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if "is_anomaly" not in df.columns:
        raise ValueError("Missing required column: is_anomaly")

    anomalies = df[df["is_anomaly"] == 1].copy()
    logger.info("Filtered anomalies: %d rows.", len(anomalies))
    return anomalies


def detect_anomalies(df: pd.DataFrame, model_path: str) -> pd.DataFrame:
    """High-level anomaly detection entrypoint.

    Args:
        df: Feature DataFrame to score.
        model_path: Path to saved IsolationForest model file.

    Returns:
        DataFrame with appended columns: is_anomaly, anomaly_score.
    """
    model = load_anomaly_model(model_path)
    return score_packets(df, model)


def _mock_dataframe_test() -> pd.DataFrame:
    """Run a small local mock test and return scored output.

    This helper exists to provide a quick sanity test and example output.
    """
    train_df = pd.DataFrame(
        {
            "frame_len": [60, 62, 64, 66, 68, 70, 72, 74],
            "ip_proto": [6, 6, 6, 17, 17, 6, 17, 6],
            "is_tcp": [1, 1, 1, 0, 0, 1, 0, 1],
            "is_udp": [0, 0, 0, 1, 1, 0, 1, 0],
            "tcp_flag_syn": [1, 0, 1, 0, 0, 1, 0, 0],
            "tcp_flag_ack": [0, 1, 0, 0, 0, 0, 0, 1],
            "tcp_flag_fin": [0, 0, 0, 0, 0, 0, 0, 0],
            "tcp_flag_rst": [0, 0, 0, 0, 0, 0, 0, 0],
            "tcp_flag_psh": [0, 1, 0, 0, 0, 0, 0, 1],
            "hour_of_day": [9, 9, 10, 10, 11, 11, 12, 12],
        }
    )

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(train_df)

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        with open(tmp_path, "wb") as f:
            pickle.dump(model, f)

        mock_df = pd.DataFrame(
            {
                "frame_len": [64, 1500, 66],
                "ip_proto": [6, 6, 17],
                "is_tcp": [1, 1, 0],
                "is_udp": [0, 0, 1],
                "tcp_flag_syn": [1, 1, 0],
                "tcp_flag_ack": [0, 0, 0],
                "tcp_flag_fin": [0, 0, 0],
                "tcp_flag_rst": [0, 0, 0],
                "tcp_flag_psh": [0, 0, 0],
                "hour_of_day": [9, 3, 11],
            }
        )
        return detect_anomalies(mock_df, tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    demo = _mock_dataframe_test()
    logger.info("Mock test output:\n%s", demo.to_string(index=False))
