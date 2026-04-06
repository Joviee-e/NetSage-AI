"""
config/settings.py - Centralized configuration for the anomaly detection system.

All tunable parameters live here as dataclasses.
Never hardcode paths, interfaces, or thresholds in other modules.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


# TShark fields extracted from every packet
TSHARK_FIELDS: List[str] = [
    "ip.src",
    "ip.dst",
    "frame.len",
    "frame.time_epoch",
    "tcp.flags",
    "ip.proto",
]


@dataclass
class CaptureConfig:
    """Settings for the TShark capture stage."""

    interface: str = "5"
    duration: int = 60  # seconds
    pcap_file: Optional[str] = None
    tshark_path: str = "tshark"
    fields: List[str] = field(default_factory=lambda: list(TSHARK_FIELDS))
    field_separator: str = "\t"


@dataclass
class ModelConfig:
    """Paths to saved ML model artefacts."""

    anomaly_model_path: str = os.path.join("models", "saved", "isolation_forest.pkl")
    classifier_model_path: str = os.path.join("models", "saved", "random_forest.pkl")
    scaler_path: str = os.path.join("models", "saved", "scaler.pkl")


@dataclass
class OutputConfig:
    """Settings for generated reports and logs."""

    report_dir: str = os.path.join("output", "reports")


@dataclass
class AppConfig:
    """Top-level application configuration."""

    mode: str = "realtime"  # "batch" or "realtime"
    log_level: str = "INFO"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    models: ModelConfig = field(default_factory=ModelConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config() -> AppConfig:
    """Build an AppConfig, applying environment-variable overrides.

    Supported env vars:
        APP_MODE           - pipeline mode: batch or realtime
        CAPTURE_INTERFACE  - network interface name
        CAPTURE_DURATION   - capture length in seconds
        CAPTURE_PCAP       - path to a .pcap file for offline mode
        LOG_LEVEL          - Python log level string

    Returns:
        Fully initialized AppConfig instance.
    """
    config = AppConfig()

    # --- environment overrides ------------------------------------------------
    if mode := os.environ.get("APP_MODE"):
        mode = mode.strip().lower()
        if mode in {"batch", "realtime"}:
            config.mode = mode

    if iface := os.environ.get("CAPTURE_INTERFACE"):
        config.capture.interface = iface

    if dur := os.environ.get("CAPTURE_DURATION"):
        config.capture.duration = int(dur)

    if pcap := os.environ.get("CAPTURE_PCAP"):
        config.capture.pcap_file = pcap
        # PCAP replay is part of batch mode.
        config.mode = "realtime"

    if lvl := os.environ.get("LOG_LEVEL"):
        config.log_level = lvl.upper()

    return config
