"""Realtime packet processing pipeline."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Deque, Dict, List

import colorama
import pandas as pd

from capture.tshark_runner import stream_packets
from classification.attack_classifier import load_classifier, predict_attack_types
from detection.anomaly_detector import load_anomaly_model, score_packets
from features.extractor import extract_features
from utils.logger import setup_logger
from visualization.report_generator import generate_report

logger = setup_logger("pipeline.realtime")

BUFFER_SIZE = 1
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

colorama.init()

ANOMALY_WINDOW_SECONDS = 10
ANOMALY_THRESHOLD = 5
TRAFFIC_WINDOW_SECONDS = 1
TRAFFIC_THRESHOLD = 200


class AlertFilter:
    """Stateful threshold gate for realtime alert suppression."""

    def __init__(
        self,
        anomaly_window_seconds: int = ANOMALY_WINDOW_SECONDS,
        anomaly_threshold: int = ANOMALY_THRESHOLD,
        traffic_window_seconds: int = TRAFFIC_WINDOW_SECONDS,
        traffic_threshold: int = TRAFFIC_THRESHOLD,
    ) -> None:
        self.anomaly_window_seconds = anomaly_window_seconds
        self.anomaly_threshold = anomaly_threshold
        self.traffic_window_seconds = traffic_window_seconds
        self.traffic_threshold = traffic_threshold
        self.packet_timestamps: Deque[float] = deque()
        self.anomaly_timestamps: Deque[float] = deque()

    @staticmethod
    def _trim_window(window: Deque[float], now_ts: float, max_age_seconds: int) -> None:
        cutoff = now_ts - max_age_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def register_packet(self, is_anomaly: bool, now_ts: float | None = None) -> None:
        """Track packet/anomaly timestamps in sliding windows."""
        timestamp = datetime.now().timestamp() if now_ts is None else now_ts
        self.packet_timestamps.append(timestamp)
        self._trim_window(self.packet_timestamps, timestamp, self.traffic_window_seconds)

        if is_anomaly:
            self.anomaly_timestamps.append(timestamp)
        self._trim_window(self.anomaly_timestamps, timestamp, self.anomaly_window_seconds)

    def evaluate_and_alert(self) -> None:
        """Emit aggregated alerts only when thresholds are exceeded.

        Cooldown behavior: relevant counters are reset immediately after alert
        emission to prevent repetitive warning spam.
        """
        anomaly_count = len(self.anomaly_timestamps)
        packets_per_second = len(self.packet_timestamps) / max(
            self.traffic_window_seconds,
            1,
        )

        if anomaly_count > self.anomaly_threshold:
            logger.warning("🚨 HIGH ANOMALY RATE DETECTED")
            self.anomaly_timestamps.clear()

        if packets_per_second > self.traffic_threshold:
            logger.warning("🚨 TRAFFIC SPIKE DETECTED")
            self.packet_timestamps.clear()


def _format_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _apply_realtime_rule_fallback(df: pd.DataFrame) -> pd.DataFrame:
    """Apply realtime-only rule fallback without replacing ML decisions.

    Rule:
        if frame_len > 1200 and packet is not already flagged by ML:
            is_anomaly = 1
            attack_type = suspicious_traffic
            attack_confidence = 0.9
    """
    if df.empty or "frame_len" not in df.columns:
        return df

    result = df.copy()
    rule_mask = (result["frame_len"] > 1200) & (result["is_anomaly"] != 1)
    if rule_mask.any():
        result.loc[rule_mask, "is_anomaly"] = 1
        result.loc[rule_mask, "attack_type"] = "suspicious_traffic"
        result.loc[rule_mask, "attack_confidence"] = 0.9
        logger.info("Realtime rule fallback flagged %d packets.", int(rule_mask.sum()))

    return result


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
    return _apply_realtime_rule_fallback(classified_df)


def _emit_live_logs(result_df: pd.DataFrame, alert_filter: AlertFilter) -> None:
    """Emit realtime visibility logs and threshold-gated aggregate alerts."""
    for _, row in result_df.iterrows():
        src_ip = row.get("ip.src", "unknown")
        dst_ip = row.get("ip.dst", "unknown")
        stamp = _format_ts()
        is_anomaly = int(row.get("is_anomaly", 0)) == 1
        alert_filter.register_packet(is_anomaly=is_anomaly)

        if is_anomaly:
            attack = str(row.get("attack_type", "anomaly"))
            conf = float(row.get("attack_confidence", 0.0))
            if attack and attack.lower() != "normal":
                attack_type = attack
                confidence = conf
                logger.info(
                    f"{stamp} | {YELLOW}[ANOMALY] {attack_type} detected (confidence: {confidence:.2f}){RESET} | {src_ip} -> {dst_ip}"
                )
            else:
                logger.info(
                    f"{stamp} | {YELLOW}[ANOMALY] Anomaly detected{RESET} | {src_ip} -> {dst_ip}"
                )
        else:
            # Keep realtime CLI focused on alerts; progress is logged periodically.
            pass

        alert_filter.evaluate_and_alert()


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
    alert_filter = AlertFilter()

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
                    _emit_live_logs(batch_df, alert_filter)
                    results.append(batch_df)
                    processed_packets += len(batch_df)
                    if processed_packets % 50 == 0:
                        logger.info(
                            "%s[INFO] Packets processed: %d%s",
                            GREEN,
                            processed_packets,
                            RESET,
                        )
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
                _emit_live_logs(batch_df, alert_filter)
                results.append(batch_df)
                processed_packets += len(batch_df)
                if processed_packets % 50 == 0:
                    logger.info(
                        "%s[INFO] Packets processed: %d%s",
                        GREEN,
                        processed_packets,
                        RESET,
                    )

    if not results:
        logger.warning(
            "Realtime mode stopped with no processed packets. Skipping report generation."
        )
        return pd.DataFrame()

    final_df = pd.concat(results, ignore_index=True)
    generate_report(final_df, base_output_dir=config.output.report_dir)
    logger.info("Realtime pipeline completed. Processed packets: %d", len(final_df))
    return final_df
