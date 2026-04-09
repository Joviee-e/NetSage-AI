"""
classification/attack_classifier.py - Attack type inference for anomalous packets.

Loads a trained RandomForestClassifier, classifies only anomaly-flagged rows
(is_anomaly == 1), and appends:
    - attack_type
    - attack_confidence

Normal rows are always labeled:
    - attack_type = "normal"
    - attack_confidence = 1.0

Functions:
    load_classifier()      - deserialize classifier from .pkl
    predict_attack_types() - classify anomaly rows and merge into full DataFrame
    get_attack_summary()   - return attack label counts
    classify_attacks()     - high-level entrypoint
"""

from __future__ import annotations

import os
import pickle
import tempfile
from typing import Dict, List, Optional

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from models.feature_schema import load_feature_schema
from utils.logger import setup_logger

logger = setup_logger("classification.attack_classifier")


def load_classifier(model_path: str) -> RandomForestClassifier:
    """Load a trained RandomForestClassifier model from disk.

    Args:
        model_path: Path to the pickled RandomForestClassifier.

    Returns:
        Loaded RandomForestClassifier instance.

    Raises:
        FileNotFoundError: If model_path does not exist.
        ValueError: If path is invalid or loaded object type is incorrect.
    """
    if not model_path or not isinstance(model_path, str):
        raise ValueError("model_path must be a non-empty string.")

    if not os.path.exists(model_path):
        logger.error("Classifier model file not found: %s", model_path)
        raise FileNotFoundError(f"Classifier model file not found: {model_path}")

    with open(model_path, "rb") as f:
        model = pickle.load(f)

    if not isinstance(model, RandomForestClassifier):
        raise ValueError(
            "Loaded classifier is invalid: expected sklearn RandomForestClassifier."
        )

    logger.info("Loaded RandomForestClassifier from %s", model_path)
    return model


def _resolve_feature_columns(
    anomalies_df: pd.DataFrame,
    model: RandomForestClassifier,
    feature_columns: Optional[List[str]] = None,
) -> List[str]:
    """Resolve classification feature columns from schema/model/fallback."""
    if feature_columns:
        return list(feature_columns)

    schema_features = load_feature_schema()
    if schema_features:
        return list(schema_features)

    if hasattr(model, "feature_names_in_"):
        return [str(c) for c in model.feature_names_in_]

    excluded = {
        "is_anomaly",
        "anomaly_score",
        "attack_type",
        "attack_confidence",
    }
    numeric = anomalies_df.select_dtypes(include=["number", "bool"])
    return [c for c in numeric.columns if c not in excluded]


def _select_classifier_features(
    anomalies_df: pd.DataFrame,
    model: RandomForestClassifier,
    feature_columns: Optional[List[str]] = None,
    strict_schema: bool = False,
) -> Optional[pd.DataFrame]:
    """Select classifier input features, optionally falling back on schema mismatch."""
    needed = _resolve_feature_columns(anomalies_df, model, feature_columns)
    if not needed:
        raise ValueError("No feature columns resolved for classification.")

    missing = [c for c in needed if c not in anomalies_df.columns]
    if missing:
        message = (
            "Missing required feature columns for classifier: "
            f"{missing}. This usually indicates packet-level vs flow-level schema mismatch."
        )
        if strict_schema:
            raise ValueError(message)
        logger.warning("%s Falling back to anomaly-only labels.", message)
        return None

    return anomalies_df[needed]


def predict_attack_types(
    df: pd.DataFrame,
    model: RandomForestClassifier,
    feature_columns: Optional[List[str]] = None,
    strict_schema: bool = False,
) -> pd.DataFrame:
    """Predict attack labels and confidence for anomalous rows only.

    Rules:
        - Only rows where is_anomaly == 1 are passed to the model.
        - Normal rows remain: attack_type="normal", attack_confidence=1.0

    Args:
        df: Input DataFrame containing at least is_anomaly column.
        model: Trained RandomForestClassifier.
        feature_columns: Optional explicit feature list.
        strict_schema: Raise on feature mismatch when True.

    Returns:
        DataFrame with attack_type and attack_confidence columns added.

    Raises:
        ValueError: If DataFrame/model is invalid or strict schema mismatch occurs.
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if df.empty:
        raise ValueError("Input DataFrame is empty; cannot classify attacks.")
    if "is_anomaly" not in df.columns:
        raise ValueError("Missing required column: is_anomaly")
    if model is None or not hasattr(model, "predict") or not hasattr(
        model, "predict_proba"
    ):
        raise ValueError("model must support predict() and predict_proba().")

    result = df.copy()

    # Defaults for normal packets.
    result["attack_type"] = "normal"
    result["attack_confidence"] = 1.0

    anomaly_mask = result["is_anomaly"] == 1
    anomalies = result.loc[anomaly_mask]

    # Safe no-op when no anomalies were detected.
    if anomalies.empty:
        logger.info("No anomalies found; skipped classifier model inference.")
        return result

    features = _select_classifier_features(
        anomalies,
        model,
        feature_columns=feature_columns,
        strict_schema=strict_schema,
    )

    # Compatibility fallback: anomaly detected but classifier model cannot run.
    if features is None:
        result.loc[anomaly_mask, "attack_type"] = "anomaly"
        result.loc[anomaly_mask, "attack_confidence"] = 0.0
        return result

    predicted_labels = model.predict(features)
    proba = model.predict_proba(features)

    # Confidence = probability of the predicted class for each row.
    class_to_idx = {label: idx for idx, label in enumerate(model.classes_)}
    confidences = [
        float(proba[row_idx, class_to_idx[label]])
        for row_idx, label in enumerate(predicted_labels)
    ]

    result.loc[anomaly_mask, "attack_type"] = predicted_labels.astype(str)
    result.loc[anomaly_mask, "attack_confidence"] = pd.Series(
        confidences,
        index=anomalies.index,
        dtype="float64",
    )

    logger.info(
        "Classified %d anomalous packets across %d total rows.",
        len(anomalies),
        len(result),
    )
    return result


def get_attack_summary(df: pd.DataFrame) -> Dict[str, int]:
    """Return count summary for attack_type labels.

    Args:
        df: DataFrame containing attack_type column.

    Returns:
        Dict mapping label -> count.

    Raises:
        ValueError: If df is invalid or missing attack_type.
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if "attack_type" not in df.columns:
        raise ValueError("Missing required column: attack_type")

    summary = df["attack_type"].value_counts(dropna=False).to_dict()
    logger.info("Attack summary: %s", summary)
    return {str(k): int(v) for k, v in summary.items()}


def classify_attacks(df: pd.DataFrame, model_path: str) -> pd.DataFrame:
    """High-level attack classification entrypoint.

    Args:
        df: DataFrame containing is_anomaly labels and model features.
        model_path: Path to saved RandomForestClassifier model.

    Returns:
        DataFrame with attack_type and attack_confidence columns.
    """
    model = load_classifier(model_path)
    return predict_attack_types(df, model)


def _mock_dataframe_test() -> pd.DataFrame:
    """Run a small local mock test and return classified output."""
    train_features = pd.DataFrame(
        {
            "frame_len": [1200, 1400, 80, 60, 75, 1500],
            "ip_proto": [6, 6, 6, 17, 17, 6],
            "is_tcp": [1, 1, 1, 0, 0, 1],
            "is_udp": [0, 0, 0, 1, 1, 0],
            "tcp_flag_syn": [1, 1, 0, 0, 0, 1],
            "tcp_flag_ack": [0, 0, 1, 0, 0, 0],
            "tcp_flag_fin": [0, 0, 0, 0, 0, 0],
            "tcp_flag_rst": [0, 0, 1, 0, 0, 0],
            "tcp_flag_psh": [0, 0, 1, 0, 0, 0],
            "hour_of_day": [2, 3, 15, 16, 17, 1],
        }
    )
    train_labels = ["DoS", "DoS", "PortScan", "BruteForce", "BruteForce", "DoS"]

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(train_features, train_labels)

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        with open(tmp_path, "wb") as f:
            pickle.dump(model, f)

        mock_df = pd.DataFrame(
            {
                "frame_len": [64, 1500, 72, 1300],
                "ip_proto": [6, 6, 17, 6],
                "is_tcp": [1, 1, 0, 1],
                "is_udp": [0, 0, 1, 0],
                "tcp_flag_syn": [1, 1, 0, 1],
                "tcp_flag_ack": [0, 0, 0, 0],
                "tcp_flag_fin": [0, 0, 0, 0],
                "tcp_flag_rst": [0, 0, 0, 0],
                "tcp_flag_psh": [0, 0, 0, 0],
                "hour_of_day": [10, 3, 20, 2],
                "is_anomaly": [0, 1, 0, 1],
            }
        )
        return classify_attacks(mock_df, tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    demo = _mock_dataframe_test()
    print(
        demo[
            [
                "is_anomaly",
                "attack_type",
                "attack_confidence",
            ]
        ].to_string(index=False)
    )
    print("Summary:", get_attack_summary(demo))
