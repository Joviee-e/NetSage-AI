# 🔍 AI-Based Network Anomaly Detection and Attack Classification System

> Capture live network traffic with TShark, detect anomalies using Isolation Forest,
> classify attack types using Random Forest, and output HTML reports — all in a clean,
> modular Python pipeline.

---

## 📌 Table of Contents

1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Folder Structure](#folder-structure)
4. [Module Descriptions](#module-descriptions)
5. [Data Flow](#data-flow)
6. [Setup Instructions](#setup-instructions)
7. [How to Run](#how-to-run)
8. [Output](#output)
9. [Coding Style Guidelines](#coding-style-guidelines)
10. [Future Scope](#future-scope)

---

## 📖 Project Overview

This system is designed to automatically detect and classify malicious network activity
by analysing packet-level traffic captured through **TShark** (the CLI version of Wireshark).

**What it does, step by step:**

1. **Captures** network packets from a live interface or a `.pcap` file using TShark
2. **Extracts** ML-ready features from packet fields (ports, protocols, flags, sizes, etc.)
3. **Detects anomalies** using Isolation Forest — an unsupervised algorithm that identifies
   packets that deviate significantly from normal patterns
4. **Classifies** each anomalous packet into an attack category (e.g., DoS, Port Scan,
   Brute Force) using a trained Random Forest classifier
5. **Generates** a visual HTML report and a structured JSON log file

**Who this is for:**  
Students, security researchers, and engineers building network monitoring tools who want
a clean, understandable pipeline they can extend with their own models or data.

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        main.py (Orchestrator)                    │
└──────────┬───────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────┐     subprocess      ┌─────────────┐
│  capture/        │ ─────────────────►  │   TShark    │
│  tshark_runner   │ ◄─────────────────  │  (OS-level) │
└────────┬─────────┘   tab-sep output    └─────────────┘
         │  List[Dict]
         ▼
┌──────────────────┐
│  features/       │  ← Type-cast fields, engineer derived features
│  extractor       │    (ports, flags, protocol dummies, timestamps)
└────────┬─────────┘
         │  pandas.DataFrame
         ▼
┌──────────────────┐
│  detection/      │  ← Isolation Forest
│  anomaly_detector│    scores each packet
└────────┬─────────┘    adds: is_anomaly, anomaly_score
         │
         ▼
┌──────────────────┐
│  classification/ │  ← Random Forest
│  attack_classifier    labels anomalous packets
└────────┬─────────┘    adds: attack_type, attack_confidence
         │
         ▼
┌──────────────────┐
│  visualization/  │  ← HTML report + JSON log + PNG charts
│  report_generator│
└──────────────────┘
```

**Configuration** flows from `config/settings.py` into every module.  
**Logging** is handled by `utils/logger.py` and writes to `logs/app.log`.  
**Models** are trained once by `models/trainer.py` and saved to `models/saved/`.

---

## 📁 Folder Structure

```
netanomaly/
│
├── main.py                          # Pipeline entry point
│
├── config/
│   ├── __init__.py
│   └── settings.py                  # All tunable parameters (interface, paths, etc.)
│
├── capture/
│   ├── __init__.py
│   └── tshark_runner.py             # TShark subprocess control + output parsing
│
├── features/
│   ├── __init__.py
│   └── extractor.py                 # Feature engineering from raw packet dicts
│
├── models/
│   ├── __init__.py
│   ├── trainer.py                   # Train and save Isolation Forest + Random Forest
│   └── saved/
│       ├── isolation_forest.pkl     # Trained anomaly detection model
│       ├── random_forest.pkl        # Trained attack classifier
│       └── scaler.pkl               # StandardScaler used during training
│
├── detection/
│   ├── __init__.py
│   └── anomaly_detector.py          # Load model, score packets, flag anomalies
│
├── classification/
│   ├── __init__.py
│   └── attack_classifier.py         # Load classifier, label attack types
│
├── visualization/
│   ├── __init__.py
│   └── report_generator.py          # HTML report, JSON log, matplotlib charts
│
├── utils/
│   ├── __init__.py
│   ├── logger.py                    # Centralised logging with rotation
│   ├── validators.py                # Input/data sanity checks
│   └── file_helpers.py              # CSV, JSON, directory helpers
│
├── data/
│   ├── labeled_traffic.csv          # Training dataset (features + labels)
│   ├── sample_capture.pcap          # Sample PCAP for offline testing
│   └── README.md                    # Data format documentation
│
├── logs/
│   └── app.log                      # Runtime log (auto-created)
│
├── output/
│   └── reports/                     # Generated HTML, JSON, PNG output
│
├── tests/
│   ├── test_capture.py
│   ├── test_features.py
│   ├── test_detection.py
│   └── test_classification.py
│
├── requirements.txt
├── .gitignore
├── ARCHITECTURE.md
├── DEVLOG.md
└── README.md
```

---

## 📦 Module Descriptions

### `config/settings.py`
Central configuration dataclasses for the entire system.  
Contains: capture interface, TShark fields, model paths, output directories, log level.  
**Extend here** when adding new tunable parameters. Never hardcode values elsewhere.

### `capture/tshark_runner.py`
Builds and executes TShark subprocess commands. Parses tab-separated output into
Python dicts. Supports both live interface capture and offline PCAP file replay.

Key functions:
- `build_tshark_command()` — constructs the CLI argument list
- `run_tshark()` — executes subprocess, handles timeouts and errors
- `parse_tshark_output()` — maps raw output lines to field dicts
- `start_capture()` — high-level entrypoint used by main.py

### `features/extractor.py`
Converts raw packet dicts to a pandas DataFrame with ML-ready columns.

Key functions:
- `raw_to_dataframe()` — dict list → DataFrame
- `cast_numeric_columns()` — handle TShark string output, fill missing as 0
- `engineer_features()` — derive is_tcp, src_port, hour_of_day, TCP flags, etc.
- `select_model_features()` — return only columns the model expects
- `extract_features()` — high-level pipeline function

### `models/trainer.py`
Run once before the system is deployed. Trains both ML models on labeled data
and saves them as `.pkl` files. Never called by the live pipeline.

Key functions:
- `load_training_data()` — read `data/labeled_traffic.csv`
- `train_anomaly_detector()` — fit Isolation Forest + StandardScaler
- `train_attack_classifier()` — fit Random Forest, log evaluation report
- `save_model()` / `load_model()` — pickle I/O
- `run_training()` — orchestrates the full training sequence

### `detection/anomaly_detector.py`
Loads the Isolation Forest model, scores every packet, and appends
`is_anomaly` and `anomaly_score` columns to the DataFrame.

Key functions:
- `load_anomaly_model()` — deserialize model + scaler
- `score_packets()` — run predict and decision_function
- `filter_anomalies()` — return only flagged rows
- `detect_anomalies()` — high-level entrypoint

### `classification/attack_classifier.py`
Loads the Random Forest classifier and predicts attack labels for anomalous packets.
Normal packets are passed through labeled `"normal"` without calling the model.

Key functions:
- `load_classifier()` — deserialize Random Forest
- `predict_attack_types()` — classify anomaly-flagged rows
- `get_attack_summary()` — dict of label counts
- `classify_attacks()` — high-level entrypoint

### `visualization/report_generator.py`
Generates all output. Writes an HTML report with embedded charts, a structured
JSON log, and two PNG charts (traffic ratio + attack breakdown).

Key functions:
- `results_to_json()` — structured JSON log
- `generate_traffic_chart()` — bar chart: normal vs anomalous
- `generate_attack_breakdown_chart()` — pie chart: attack type distribution
- `generate_html_report()` — full HTML report
- `generate_report()` — high-level entrypoint

### `utils/`
- **`logger.py`** — `setup_logger(name)` — console + rotating file logging
- **`validators.py`** — sanity check packets, DataFrames, model files, interfaces
- **`file_helpers.py`** — CSV/JSON I/O and directory creation helpers

---

## 🔄 Data Flow

```
Step 1: TShark Capture
  - TShark runs as a subprocess
  - Outputs tab-separated packet fields to stdout
  - Each line = one packet

Step 2: Parsing
  - Lines are split by tab character
  - Mapped to field name keys (frame.time_epoch, ip.src, etc.)
  - Returned as List[Dict[str, str]]

Step 3: Feature Extraction
  - String values are cast to numeric (pd.to_numeric)
  - Derived features are engineered
  - Output: pandas DataFrame, one row per packet

Step 4: Anomaly Detection
  - Features are scaled using the saved StandardScaler
  - Isolation Forest assigns anomaly score per row
  - is_anomaly = 1 for outliers, 0 for normal traffic

Step 5: Attack Classification
  - Only is_anomaly == 1 rows are passed to Random Forest
  - Model predicts attack_type and attack_confidence
  - Results merged back into full DataFrame

Step 6: Output
  - HTML report with summary stats and charts
  - JSON log with per-packet results
  - PNG charts saved to output/reports/
```

---

## ⚙️ Setup Instructions

### 1. Install TShark

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install tshark
# Allow non-root capture (recommended for development)
sudo dpkg-reconfigure wireshark-common  # select Yes
sudo usermod -aG wireshark $USER
# Log out and back in for group change to take effect
```

**macOS:**
```bash
brew install wireshark
```

**Verify installation:**
```bash
tshark --version
```

### 2. Clone the Project

```bash
git clone https://github.com/your-username/netanomaly.git
cd netanomaly
```

### 3. Create a Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Contents of `requirements.txt`:
```
pandas>=2.0
numpy>=1.24
scikit-learn>=1.3
matplotlib>=3.7
```

### 5. Prepare Training Data

Place a labeled CSV at `data/labeled_traffic.csv`.  
Required columns: all feature columns from `features/extractor.py` plus:
- `label` — integer (0 = normal, 1 = anomalous)
- `attack_type` — string ("normal", "DoS", "PortScan", "BruteForce", etc.)

**Public datasets you can use:**
- [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

### 6. Train Models

```bash
python -m models.trainer
```

This saves three files to `models/saved/`:
- `isolation_forest.pkl`
- `random_forest.pkl`
- `scaler.pkl`

---

## ▶️ How to Run

### Live Capture Mode

```bash
# Requires root or wireshark group membership
python main.py
```

Default interface is `eth0`. Override via environment variable:
```bash
CAPTURE_INTERFACE=wlan0 CAPTURE_DURATION=120 python main.py
```

### Offline PCAP Mode

Edit `config/settings.py`:
```python
config.capture.pcap_file = "data/sample_capture.pcap"
config.mode = "pcap"
```
Then run:
```bash
python main.py
```

### Train Models Only

```bash
python -m models.trainer
```

---

## 📊 Output

After a successful run, check `output/reports/`:

| File | Description |
|------|-------------|
| `report_YYYYMMDD_HHMMSS.html` | Full visual HTML report |
| `results_YYYYMMDD_HHMMSS.json` | Structured per-packet JSON log |
| `traffic_YYYYMMDD_HHMMSS.png` | Bar chart: normal vs anomalous |
| `attacks_YYYYMMDD_HHMMSS.png` | Pie chart: attack type breakdown |

Runtime logs are written to `logs/app.log`.

---

## 🎨 Coding Style Guidelines

### Naming Conventions
- **Files**: `snake_case.py`
- **Functions**: `snake_case()`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_CASE`
- **Config keys**: `snake_case`

### Modular Principles
- One file = one responsibility
- No module imports from a module at the same level or below (no circular imports)
- Import direction: `main → config → capture → features → models → detection → classification → visualization`
- Keep functions short (< 40 lines each), single-purpose
- All functions have docstrings with Args/Returns

### Adding New Features
1. New feature column → add to `features/extractor.py:engineer_features()`
2. New ML model → add training to `models/trainer.py`, inference to `detection/` or `classification/`
3. New output format → add a function to `visualization/report_generator.py`
4. New config parameter → add to the appropriate dataclass in `config/settings.py`
5. Always add validation to `utils/validators.py` for new inputs

### What NOT to Do
- Do not hardcode paths, IPs, or parameters outside `config/settings.py`
- Do not import `main.py` from any submodule
- Do not write logic inside `__init__.py` files
- Do not use `print()` — use `logger.info()` / `logger.warning()` etc.

---

## 🚀 Future Scope

| Area | Enhancement |
|------|-------------|
| **Models** | Replace Random Forest with XGBoost or LightGBM for better accuracy |
| **Deep Learning** | Add LSTM/Autoencoder for sequential traffic anomaly detection |
| **Real-time** | Streaming pipeline using Kafka or a rolling window buffer |
| **Features** | Flow-level features (inter-arrival time, byte rates, connection state) |
| **Deployment** | Docker container + REST API endpoint for integration with SIEM tools |
| **Alerts** | Email / Slack / webhook alerts when high-confidence attacks are detected |
| **Dashboard** | Live web dashboard using Dash or Streamlit |
| **Dataset** | Active learning loop: human-confirmed labels improve model over time |
| **IPv6** | Extend feature extraction to support IPv6 traffic fields |
| **Explainability** | Add SHAP values to explain which features drove each prediction |

---

## 📄 License

MIT License — see `LICENSE` for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit with clear messages: `git commit -m "feat: add flow-level feature extraction"`
4. Open a pull request with a description of changes
5. Update `DEVLOG.md` with your changes

---

*Built for educational and research purposes. Always obtain proper authorization before
capturing network traffic on any network you do not own.*

---

## Real-Time Monitoring Mode

The system now supports a realtime streaming mode in addition to batch mode.

### How It Works

1. TShark runs in streaming mode via `subprocess.Popen`.
2. Packets are read line-by-line from stdout.
3. Packets are processed in small buffers (default: 5 packets).
4. Each buffer is passed through:
   - feature extraction
   - anomaly detection (Isolation Forest)
   - attack classification (Random Forest)
5. Live CLI logs are emitted for normal packets and alerts.
6. On Ctrl+C, capture stops gracefully and a final report is generated.

### How To Run

Use environment variable `APP_MODE`:

```bash
# Batch (default)
APP_MODE=batch python main.py

# Realtime streaming mode
APP_MODE=realtime python main.py
```

Optional capture interface override:

```bash
APP_MODE=realtime CAPTURE_INTERFACE=eth0 python main.py
```

### Example Realtime CLI Output

```text
2026-04-06 22:00:01 | [INFO] Packet processed | 10.0.0.1 -> 10.0.0.5
2026-04-06 22:00:02 | ?? [ALERT] Anomaly detected | 10.0.0.9 -> 10.0.0.3
2026-04-06 22:00:03 | ?? [ALERT] DDOS detected (confidence: 0.92) | 10.0.0.7 -> 10.0.0.2
```

### Batch vs Realtime

| Mode | Capture Pattern | Processing Pattern | Output Timing |
|------|------------------|--------------------|---------------|
| Batch | Capture first, then process | Full DataFrame pipeline | Report at end |
| Realtime | Continuous packet stream | Small buffered micro-batches | Live alerts + report on stop |

### Realtime Mode Improvements

Recent improvements for realtime mode:

- Immediate streaming responsiveness using line-buffered TShark output (`-l`).
- Packet processing buffer reduced for near-instant detection.
- Live per-packet CLI updates with timestamp and source -> destination.
- Immediate anomaly/attack alerts while capture is running.
- Graceful Ctrl+C shutdown with final report generation.

Run realtime mode:

```bash
set APP_MODE=realtime
python main.py
```

Sample CLI output:

```text
2026-04-06 23:10:12 | [INFO] Packet processed: 10.0.0.1 -> 10.0.0.5
2026-04-06 23:10:13 | [ALERT] Anomaly detected | 10.0.0.9 -> 10.0.0.3
2026-04-06 23:10:14 | [ALERT] DDOS detected (confidence: 0.91) | 10.0.0.7 -> 10.0.0.2
```
