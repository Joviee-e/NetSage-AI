"""Realtime packet processing pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

import pandas as pd

from capture.tshark_runner import stream_packets
from classification.attack_classifier import load_classifier, predict_attack_types
from detection.anomaly_detector import load_anomaly_model, score_packets
from features.extractor import extract_features
from utils.logger import setup_logger
from visualization.report_generator import generate_report

logger = setup_logger("pipeline.realtime")

BUFFER_SIZE = 1


def _format_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _process_packet_buffer(
    packet_buffer: List[Dict[str, str]],
    anomaly_model,
    classifier_model,
) -> pd.DataFrame:
    """Process a small packet buffer through feature/detection/classification."""
    if not packet_buffer:
        return pd.DataFrame()

    features_df = extract_features(packet_buffer)
    scored_df = score_packets(features_df, anomaly_model)
    classified_df = predict_attack_types(scored_df, classifier_model)
    return classified_df


def _emit_live_logs(result_df: pd.DataFrame) -> None:
    """Emit concise per-packet realtime logs for CLI visibility."""
    for _, row in result_df.iterrows():
        src_ip = row.get("ip.src", "unknown")
        dst_ip = row.get("ip.dst", "unknown")
        stamp = _format_ts()

        if int(row.get("is_anomaly", 0)) == 1:
            attack = str(row.get("attack_type", "anomaly"))
            conf = float(row.get("attack_confidence", 0.0))
            if attack and attack.lower() != "normal":
                logger.warning(
                    "%s | [ALERT] %s detected (confidence: %.2f) | %s -> %s",
                    stamp,
                    attack.upper(),
                    conf,
                    src_ip,
                    dst_ip,
                )
            else:
                logger.warning(
                    "%s | [ALERT] Anomaly detected | %s -> %s",
                    stamp,
                    src_ip,
                    dst_ip,
                )
        else:
            logger.info(
                "%s | [INFO] Packet processed: %s -> %s",
                stamp,
                src_ip,
                dst_ip,
            )


def run_realtime_pipeline(config) -> pd.DataFrame:
    """Run realtime streaming pipeline with graceful Ctrl+C shutdown.

    Behavior:
        - Loads models once at startup
        - Streams packets from TShark
        - Processes in small buffers for better throughput
        - Emits live normal/anomaly/attack logs
        - Generates final report on shutdown when data exists
    """
    logger.info("Realtime pipeline started.")
    logger.info("Streaming packets...")

    anomaly_model = load_anomaly_model(config.models.anomaly_model_path)
    classifier_model = load_classifier(config.models.classifier_model_path)

    results: List[pd.DataFrame] = []
    packet_buffer: List[Dict[str, str]] = []
    processed_packets = 0

    try:
        for packet in stream_packets(
            interface=config.capture.interface,
            fields=config.capture.fields,
            tshark_path=config.capture.tshark_path,
        ):
            packet_buffer.append(packet)

            if len(packet_buffer) >= BUFFER_SIZE:
                batch_df = _process_packet_buffer(
                    packet_buffer,
                    anomaly_model,
                    classifier_model,
                )
                if not batch_df.empty:
                    _emit_live_logs(batch_df)
                    results.append(batch_df)
                    processed_packets += len(batch_df)
                    logger.info("Packets processed: %d", processed_packets)
                packet_buffer = []

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Stopping realtime capture...")
    finally:
        # Flush remaining packets in the buffer
        if packet_buffer:
            batch_df = _process_packet_buffer(
                packet_buffer,
                anomaly_model,
                classifier_model,
            )
            if not batch_df.empty:
                _emit_live_logs(batch_df)
                results.append(batch_df)
                processed_packets += len(batch_df)
                logger.info("Packets processed: %d", processed_packets)

    if not results:
        logger.warning(
            "Realtime mode stopped with no processed packets. Skipping report generation."
        )
        return pd.DataFrame()

    final_df = pd.concat(results, ignore_index=True)
    generate_report(final_df, base_output_dir=config.output.report_dir)
    logger.info("Realtime pipeline completed. Processed packets: %d", len(final_df))
    return final_df
