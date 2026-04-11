"""Small tests for realtime pipeline behavior."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd

from pipeline.realtime_pipeline import AlertFilter, run_realtime_pipeline


class TestRealtimePipeline(unittest.TestCase):
    def _make_config(self):
        return SimpleNamespace(
            mode="realtime",
            capture=SimpleNamespace(interface="eth0", fields=None, tshark_path="tshark"),
            models=SimpleNamespace(
                anomaly_model_path="models/saved/isolation_forest.pkl",
                classifier_model_path="models/saved/random_forest.pkl",
            ),
            output=SimpleNamespace(report_dir="output/reports"),
        )

    @patch("pipeline.realtime_pipeline.load_anomaly_model")
    @patch("pipeline.realtime_pipeline.load_classifier")
    @patch("pipeline.realtime_pipeline.generate_report")
    @patch("pipeline.realtime_pipeline.stream_packets")
    def test_no_packets_no_crash(self, mock_stream, mock_report, mock_load_clf, mock_load_anom):
        config = self._make_config()
        mock_stream.return_value = iter([])

        df = run_realtime_pipeline(config)

        self.assertTrue(df.empty)
        mock_report.assert_not_called()

    @patch("pipeline.realtime_pipeline.load_anomaly_model")
    @patch("pipeline.realtime_pipeline.load_classifier")
    @patch("pipeline.realtime_pipeline._emit_live_logs")
    @patch("pipeline.realtime_pipeline._process_packet_buffer")
    @patch("pipeline.realtime_pipeline.generate_report")
    @patch("pipeline.realtime_pipeline.stream_packets")
    def test_generates_report_when_results_exist(
        self,
        mock_stream,
        mock_report,
        mock_process,
        _mock_emit,
        _mock_load_clf,
        _mock_load_anom,
    ):
        config = self._make_config()
        mock_stream.return_value = iter([
            {
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
                "frame.len": "80",
                "frame.time_epoch": "1710000000.0",
                "tcp.flags": "0x0002",
                "ip.proto": "6",
            }
        ])

        mock_process.return_value = pd.DataFrame(
            [
                {
                    "ip.src": "10.0.0.1",
                    "ip.dst": "10.0.0.2",
                    "is_anomaly": 1,
                    "attack_type": "ddos",
                    "attack_confidence": 0.92,
                }
            ]
        )

        df = run_realtime_pipeline(config)

        self.assertEqual(len(df), 1)
        mock_report.assert_called_once()

    @patch("pipeline.realtime_pipeline.logger.warning")
    def test_anomaly_alert_threshold_and_cooldown_reset(self, mock_warning):
        alert_filter = AlertFilter(anomaly_threshold=5, anomaly_window_seconds=10)
        base_ts = 1000.0

        for offset in range(6):
            alert_filter.register_packet(is_anomaly=True, now_ts=base_ts + offset)

        alert_filter.evaluate_and_alert()
        mock_warning.assert_any_call("🚨 HIGH ANOMALY RATE DETECTED")
        self.assertEqual(len(alert_filter.anomaly_timestamps), 0)

        mock_warning.reset_mock()
        for offset in range(5):
            alert_filter.register_packet(is_anomaly=True, now_ts=base_ts + 20 + offset)

        alert_filter.evaluate_and_alert()
        mock_warning.assert_not_called()

    @patch("pipeline.realtime_pipeline.logger.warning")
    def test_traffic_alert_threshold_and_cooldown_reset(self, mock_warning):
        alert_filter = AlertFilter(traffic_threshold=200, traffic_window_seconds=1)
        base_ts = 2000.0

        for _ in range(201):
            alert_filter.register_packet(is_anomaly=False, now_ts=base_ts)

        alert_filter.evaluate_and_alert()
        mock_warning.assert_any_call("🚨 TRAFFIC SPIKE DETECTED")
        self.assertEqual(len(alert_filter.packet_timestamps), 0)

        mock_warning.reset_mock()
        for _ in range(200):
            alert_filter.register_packet(is_anomaly=False, now_ts=base_ts + 2.0)

        alert_filter.evaluate_and_alert()
        mock_warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
