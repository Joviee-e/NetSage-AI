"""
models/feature_schema.py - Shared feature schema helpers.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import List, Optional

from utils.logger import setup_logger

logger = setup_logger("models.feature_schema")

MODEL_DIR = os.path.join("models", "saved")
FEATURES_SCHEMA_PATH = os.path.join(MODEL_DIR, "features.json")


def save_feature_schema(features: List[str], path: str = FEATURES_SCHEMA_PATH) -> str:
    """Persist feature names as a JSON list."""
    unique = [str(c) for c in features]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2)
    load_feature_schema.cache_clear()
    logger.info("Feature schema saved: %s (%d features)", path, len(unique))
    return path


@lru_cache(maxsize=4)
def load_feature_schema(path: str = FEATURES_SCHEMA_PATH) -> Optional[List[str]]:
    """Load feature schema from JSON if present."""
    if not os.path.exists(path):
        logger.warning("Feature schema not found at %s", path)
        return None

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, dict):
        payload = payload.get("feature_columns")

    if not isinstance(payload, list) or not all(isinstance(x, str) for x in payload):
        raise ValueError(
            f"Invalid feature schema format in {path}. Expected JSON list[str]."
        )

    logger.info("Loaded feature schema from %s (%d features)", path, len(payload))
    return payload
