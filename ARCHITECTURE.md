# Project Architecture — AI-Based Network Anomaly Detection and Attack Classification System

## System Overview

```
TShark (Live/PCAP)
      │
      ▼
┌─────────────┐
│   capture/  │  ← Invokes TShark, collects raw packet data
└──────┬──────┘
       │  raw JSON/CSV fields
       ▼
┌─────────────┐
│  features/  │  ← Parses packets, engineers ML-ready features
└──────┬──────┘
       │  Pandas DataFrame
       ▼
┌──────────────┐
│  detection/  │  ← Isolation Forest → anomaly scores
└──────┬───────┘
       │  flagged rows
       ▼
┌──────────────────┐
│ classification/  │  ← Random Forest → attack type labels
└────────┬─────────┘
         │  labeled results
         ▼
┌──────────────────┐
│ visualization/   │  ← HTML reports, charts, structured logs
└──────────────────┘
```

## Module Responsibility Map

| Module | Responsibility | Input | Output |
|---|---|---|---|
| `capture/` | Run TShark, parse raw output | Interface / PCAP file | Raw packet dicts |
| `features/` | Extract & normalize ML features | Raw packet dicts | DataFrame |
| `models/` | Train and persist ML models | DataFrame | `.pkl` model files |
| `detection/` | Anomaly scoring at inference | DataFrame | Anomaly-flagged DataFrame |
| `classification/` | Attack type labeling | Flagged DataFrame | Labeled DataFrame |
| `visualization/` | Charts and HTML output | Labeled DataFrame | HTML report + JSON log |
| `utils/` | Shared helpers | Various | Various |
| `config/` | System-wide settings | — | Config objects |
| `data/` | Sample data, labels, PCAP files | — | — |
| `logs/` | Runtime and event logs | — | `.log` files |

---

## Realtime Streaming Path

In realtime mode (`APP_MODE=realtime`), the pipeline follows a streaming path:

```
TShark (Popen stream)
      |
      v
capture.stream_packets()   -> yields packet dicts line-by-line
      |
      v
pipeline.realtime_pipeline -> micro-batch buffer (default: 5)
      |
      +--> features.extract_features()
      +--> detection.score_packets()      [models loaded once]
      +--> classification.predict_attack_types()
      |
      v
Live CLI logs (INFO / ALERT)
      |
Ctrl+C
      v
visualization.generate_report() -> JSON + PNG charts + HTML report
```

This path is additive and does not replace the existing batch pipeline.
