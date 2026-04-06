#!/usr/bin/env python3
"""
main.py - Entry point for the Network Anomaly Detection System.

Modes:
  - batch: existing batch pipeline
  - realtime: live streaming pipeline
"""

import os

from config.settings import load_config
from capture.tshark_runner import start_capture
from features.extractor import extract_features
from detection.anomaly_detector import detect_anomalies
from classification.attack_classifier import classify_attacks
from pipeline.realtime_pipeline import run_realtime_pipeline
from visualization.report_generator import generate_report
from utils.logger import setup_logger


def run_batch_pipeline(config):
    """Execute the existing batch detection pipeline end-to-end."""
    logger = setup_logger("pipeline.batch", config.log_level)
    logger.info("Batch pipeline started.")

    # Step 1: Capture
    logger.info("Step 1/5 - Capturing packets via TShark...")
    raw_packets = start_capture(
        interface=config.capture.interface,
        duration=config.capture.duration,
        pcap_file=config.capture.pcap_file,
    )

    if not raw_packets:
        logger.warning("No packets captured. Exiting batch pipeline.")
        return None

    # Step 2: Feature Extraction
    logger.info("Step 2/5 - Extracting features...")
    feature_df = extract_features(raw_packets)

    # Step 3: Anomaly Detection
    logger.info("Step 3/5 - Running anomaly detection...")
    anomaly_df = detect_anomalies(
        feature_df,
        model_path=config.models.anomaly_model_path,
    )

    # Step 4: Attack Classification
    logger.info("Step 4/5 - Classifying attacks...")
    result_df = classify_attacks(
        anomaly_df,
        model_path=config.models.classifier_model_path,
    )

    # Step 5: Output
    logger.info("Step 5/5 - Generating report...")
    generate_report(
        result_df,
        base_output_dir=config.output.report_dir,
    )

    logger.info("Batch pipeline complete.")
    return result_df


def run_pipeline(config):
    """Run batch or realtime pipeline based on config.mode."""
    mode = (
        getattr(config, "mode", None)
        or os.environ.get("APP_MODE")
        or "batch"
    ).strip().lower()
    logger = setup_logger("pipeline", config.log_level)
    logger.info("Pipeline mode selected: %s", mode)

    if mode == "realtime":
        return run_realtime_pipeline(config)

    return run_batch_pipeline(config)


if __name__ == "__main__":
    run_pipeline(load_config())
