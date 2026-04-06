"""
config/settings.py — Centralised configuration for the anomaly detection system.

All tunable parameters live here as dataclasses.
Never hardcode paths, interfaces, or thresholds in other modules.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


# ── TShark fields extracted from every packet ────────────────────────────────
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

    interface: str = "4"
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

    mode: str = "live"  # "live" or "pcap"
    log_level: str = "INFO"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    models: ModelConfig = field(default_factory=ModelConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config() -> AppConfig:
    """Build an AppConfig, applying environment-variable overrides.

    Supported env vars:
        CAPTURE_INTERFACE  — network interface name  (default: eth0)
        CAPTURE_DURATION   — capture length in seconds (default: 60)
        CAPTURE_PCAP       — path to a .pcap file for offline mode
        LOG_LEVEL          — Python log level string   (default: INFO)

    Returns:
        Fully initialised AppConfig instance.
    """
    config = AppConfig()

    # --- environment overrides ------------------------------------------------
    if iface := os.environ.get("CAPTURE_INTERFACE"):
        config.capture.interface = iface

    if dur := os.environ.get("CAPTURE_DURATION"):
        config.capture.duration = int(dur)

    if pcap := os.environ.get("CAPTURE_PCAP"):
        config.capture.pcap_file = pcap
        config.mode = "pcap"

    if lvl := os.environ.get("LOG_LEVEL"):
        config.log_level = lvl.upper()

    return config
