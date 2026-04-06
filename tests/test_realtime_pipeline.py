"""Small tests for realtime pipeline behavior."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd

from pipeline.realtime_pipeline import run_realtime_pipeline


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


if __name__ == "__main__":
    unittest.main()
