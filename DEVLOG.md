# DEVLOG — AI-Based Network Anomaly Detection System

> **Purpose:** This file is the living development journal for this project.
> Every change, fix, addition, and decision must be recorded here.
> Append a new entry at the top (most recent first) each time you make changes.
> Never delete old entries — this is a permanent record.

---

## Entry Format Template

Copy and fill this block for every new entry:

```
---
### [YYYY-MM-DD] — Short Title of Change

**Type:** [Feature | Bugfix | Refactor | Docs | Config | Test | Infra]
**Module(s) affected:** [e.g., capture/, features/extractor.py]
**Author:** [Your name / tool name]

#### Changes Made
- 

#### Features Added
- 

#### Bugs Fixed
- 

#### Notes / Decisions
- 

---
```

---

## ── JOURNAL ──────────────────────────────────────────────────────

---
### [2026-04-06] - Implement models/trainer.py (synthetic training pipeline)

**Type:** Feature
**Module(s) affected:** models/trainer.py
**Author:** Codex (GPT-5)

#### Changes Made
- Created `models/trainer.py` with a clean training flow for two models:
  - Isolation Forest (anomaly detection)
  - Random Forest Classifier (attack classification)
- Implemented synthetic data generation (~1000 rows default) with required feature set:
  - `frame_len`, `ip_proto`, `is_tcp`, `is_udp`, `tcp_flag_syn`, `tcp_flag_ack`, `tcp_flag_fin`, `tcp_flag_rst`, `tcp_flag_psh`, `hour_of_day`
- Added synthetic labels in `attack_type`:
  - `normal`, `port_scan`, `ddos`
- Implemented model training helpers:
  - `train_isolation_forest(df)`
  - `train_random_forest(df)`
- Implemented model persistence via pickle:
  - `models/saved/isolation_forest.pkl`
  - `models/saved/random_forest.pkl`
- Added logging for:
  - training started
  - models saved
  - training completed
- Added `run_training()` orchestrator and `__main__` execution block.

#### Features Added
- Fully self-contained synthetic training workflow (no external dataset required).
- Pipeline-compatible saved model artifacts in configured `models/saved/` directory.

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- Assumption: synthetic distributions are intentionally simple and only meant to bootstrap pipeline integration.
- Assumption: no scaler artifact is required for current detector/classifier inference modules.

---
### [2026-04-06] - Refactor visualization/report_generator.py for production reporting

**Type:** Refactor
**Module(s) affected:** visualization/report_generator.py
**Author:** Codex (GPT-5)

#### Changes Made
- Rebuilt the module to remove duplicated HTML-generation logic and centralize data preparation.
- Enforced required input columns (`is_anomaly`, `attack_type`) with shared validation helpers.
- Added robust anomaly-flag normalization for bool/numeric/text-like inputs.
- Implemented JSON output schema exactly as:
  - `metadata` (timestamp, total_packets, anomalies)
  - `summary` (normal, anomaly)
  - `attack_distribution`
  - `data`
- Updated chart functions to use cleaned data consistently and added stronger labeling/styling.
- Updated HTML generation to produce a single `report.html` with:
  - timestamp
  - summary cards
  - anomaly count highlighted in red
  - attack breakdown table
  - embedded `traffic.png` and `attacks.png`
  - first 10 rows preview
- Updated `generate_report(df, base_output_dir)` to create timestamped run directory:
  - `base_output_dir/YYYY-MM-DD_HH-MM-SS/`
  - outputs fixed names: `report.html`, `results.json`, `traffic.png`, `attacks.png`
- Kept logging throughout the module and retained `__main__` mock-run block.

#### Features Added
- Timestamped run-folder output organization for cleaner artifact management.
- Deterministic output filenames within each run folder.
- Production-safe matplotlib `Agg` backend initialization for headless execution.

#### Bugs Fixed
- Removed prior path/filename inconsistency between individual generators and orchestrator.
- Removed duplicate HTML template generation paths that could diverge over time.

#### Notes / Decisions
- Assumption: `is_anomaly` may arrive as bool, numeric, or text-like values; normalization treats non-zero/true-like values as anomalies.
- Assumption: missing `attack_type` values are normalized to `"unknown"` across JSON/charts/report table.
---
### [2026-04-06] - Implement visualization/report_generator.py

**Type:** Feature
**Module(s) affected:** visualization/report_generator.py
**Author:** Codex (GPT-5)

#### Changes Made
- Implemented `results_to_json(df, output_path)`:
  - Validates DataFrame input
  - Writes structured JSON containing metadata, counts, and row-wise results
- Implemented `generate_traffic_chart(df, output_path)`:
  - Validates required `is_anomaly` column
  - Generates normal vs anomaly bar chart using matplotlib
- Implemented `generate_attack_breakdown_chart(df, output_path)`:
  - Validates required `attack_type` column
  - Generates attack-type pie chart using matplotlib
- Implemented `generate_html_report(df, output_dir)`:
  - Builds timestamped HTML report with summary statistics, chart references, and a preview table
- Implemented `generate_report(df, output_dir)`:
  - High-level orchestration that writes all artifacts with a shared timestamp:
    - `report_TIMESTAMP.html`
    - `results_TIMESTAMP.json`
    - `traffic_TIMESTAMP.png`
    - `attacks_TIMESTAMP.png`
- Added runnable mock DataFrame example in module `__main__` to generate and print produced file paths

#### Features Added
- Structured JSON export for full pipeline output
- Visualization layer with traffic and attack charts
- HTML reporting with packet totals, anomaly count, and attack-type count table
- Headless-safe matplotlib rendering via `Agg` backend

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- Assumption: report generation requires at minimum `is_anomaly` and `attack_type` columns for complete output.
- Assumption: `attack_type` may contain missing values; these are treated as `"unknown"` in summaries/charts.
- JSON serialization uses `default=str` so non-JSON-native values (if present) are still persisted safely.

---
### [2026-04-06] � Implement classification/attack_classifier.py

**Type:** Feature
**Module(s) affected:** classification/attack_classifier.py
**Author:** Codex (GPT-5)

#### Changes Made
- Implemented `load_classifier(model_path)`:
  - Validates model path input
  - Raises `FileNotFoundError` when classifier file is missing
  - Loads pickle and validates type as `sklearn.ensemble.RandomForestClassifier`
- Implemented `predict_attack_types(df, model)`:
  - Validates DataFrame, `is_anomaly` presence, and model interfaces (`predict`, `predict_proba`)
  - Initializes default labels for all packets:
    - `attack_type = "normal"`
    - `attack_confidence = 1.0`
  - Runs classifier only on `df[df["is_anomaly"] == 1]`
  - Computes confidence as the probability of the predicted class from `predict_proba()`
  - Merges anomaly predictions back into the full DataFrame
  - Safely skips model inference when anomaly set is empty
- Implemented `get_attack_summary(df)`:
  - Validates `attack_type` column
  - Returns label-count dictionary
- Implemented `classify_attacks(df, model_path)`:
  - High-level orchestration of model loading + anomaly-only classification
- Added runnable mock DataFrame test in module `__main__`:
  - Trains a tiny temporary Random Forest model
  - Saves/loads model from disk
  - Demonstrates output columns `attack_type` and `attack_confidence`

#### Features Added
- Full classification inference stage for anomalous packets only
- Standardized classification output schema (`attack_type`, `attack_confidence`)
- Safe no-anomaly behavior that preserves normal labeling without model call

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- Assumption: if `model.feature_names_in_` exists, it is treated as the required feature contract; missing feature columns raise a `ValueError`.
- Assumption: for normal packets (`is_anomaly == 0`), confidence should remain exactly `1.0` as required.
- Confidence for anomalous packets is defined as the predicted class probability, not max probability across unrelated labels.

---
### [2026-04-06] — Implement detection/anomaly_detector.py

**Type:** Feature
**Module(s) affected:** detection/anomaly_detector.py
**Author:** Codex (GPT-5)

#### Changes Made
- Implemented `load_anomaly_model(model_path)`:
  - Validates path input
  - Raises `FileNotFoundError` for missing model file
  - Loads model from pickle
  - Validates loaded object type is `sklearn.ensemble.IsolationForest`
- Implemented `score_packets(df, model)`:
  - Validates DataFrame input and empty input handling
  - Validates model exposes `predict()` and `decision_function()`
  - Scores packets using numeric columns only
  - Adds:
    - `is_anomaly` (mapped from `predict`: `-1 -> 1`, `1 -> 0`)
    - `anomaly_score` (from `decision_function()`, float)
- Implemented `filter_anomalies(df)`:
  - Validates DataFrame and required `is_anomaly` column
  - Returns only flagged anomaly rows (`is_anomaly == 1`)
- Implemented `detect_anomalies(df, model_path)`:
  - High-level orchestration of model loading + packet scoring
- Added a small runnable mock DataFrame test block in module `__main__`:
  - Trains a tiny temporary Isolation Forest
  - Saves/loads model from disk
  - Runs `detect_anomalies()`
  - Logs example output table

#### Features Added
- Full anomaly inference pipeline for detection stage
- Standardized anomaly output schema (`is_anomaly`, `anomaly_score`)
- Defensive error handling for missing model, invalid DataFrame, and empty input

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- Assumption: input DataFrame may include non-numeric context columns (e.g., IP strings), so only numeric/bool columns are used for model scoring.
- Assumption: persisted anomaly model file contains a raw `IsolationForest` object (not a wrapper dict or tuple).
- `decision_function()` values are stored as-is, where lower values indicate more anomalous samples.

---
### [2026-04-06] — Implement features/extractor.py

**Type:** Feature
**Module(s) affected:** features/extractor.py, tests/test_features.py
**Author:** Antigravity

#### Changes Made
- Created `features/__init__.py` package init
- Implemented `features/extractor.py` with all five required functions:
  - `raw_to_dataframe()` — converts List[Dict[str, str]] → pandas DataFrame
  - `cast_numeric_columns()` — uses pd.to_numeric(errors="coerce").fillna(0)
  - `engineer_features()` — derives 10 ML-ready columns from raw fields
  - `select_model_features()` — filters to MODEL_FEATURES + IP context columns
  - `extract_features()` — high-level pipeline orchestrator called by main.py
- Created `tests/test_features.py` with 24 unit tests

#### Features Added
- Protocol identification: is_tcp (proto=6), is_udp (proto=17)
- TCP flag bitmask parsing per RFC 793: SYN(0x02), ACK(0x10), FIN(0x01), RST(0x04), PSH(0x08)
- Timestamp feature: hour_of_day extracted from frame.time_epoch via pd.to_datetime
- ML feature vector: 10 numeric columns defined in MODEL_FEATURES constant
- IP addresses (ip.src, ip.dst) retained for traceability in downstream modules

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- TCP flags parsed from TShark hex strings (e.g. "0x0018") using int(str, 16), not regex
- Empty/invalid flag strings default to 0 — safe for UDP packets with no tcp.flags
- Numeric casting deferred to cast_numeric_columns() to keep responsibilities separated
- MODEL_FEATURES list is the single source of truth for which columns the ML models expect
- IP addresses are always kept in select_model_features() even though they aren't model inputs,
  because detection/ and visualization/ modules need them for reporting

---
### [2026-04-06] — Implement capture/tshark_runner.py

**Type:** Feature
**Module(s) affected:** capture/tshark_runner.py, config/settings.py, utils/logger.py, tests/test_capture.py
**Author:** Antigravity

#### Changes Made
- Created `config/settings.py` with dataclass-based configuration (CaptureConfig, ModelConfig, OutputConfig, AppConfig) and env-var overrides
- Created `utils/logger.py` with rotating-file + console logger (5 MB rotation, 3 backups)
- Implemented `capture/tshark_runner.py` with all four required functions:
  - `build_tshark_command()` — constructs TShark CLI args for live or PCAP mode
  - `run_tshark()` — executes subprocess with pre-flight binary check, timeout, and stderr handling
  - `parse_tshark_output()` — splits tab-separated lines into List[Dict[str, str]], skips malformed lines
  - `start_capture()` — high-level orchestrator called by main.py
- Created `tests/test_capture.py` with 19 unit tests using unittest.mock (no TShark required)
- Created `__init__.py` for config/, capture/, utils/, and tests/ packages

#### Features Added
- Live capture mode: `-i <interface> -a duration:<n>`
- PCAP replay mode: `-r <file>`
- Tab-separated field extraction: ip.src, ip.dst, frame.len, frame.time_epoch, tcp.flags, ip.proto
- Pre-flight `shutil.which()` check before invoking TShark
- Graceful handling of: missing binary, non-zero exit, empty output, malformed lines, timeout

#### Bugs Fixed
- N/A (initial implementation)

#### Notes / Decisions
- Used `shutil.which()` rather than try/except on subprocess to give a clear error message before execution
- Used `subprocess.run()` with `capture_output=True` (not Popen) since TShark runs to completion
- `parse_tshark_output()` silently skips malformed lines with a warning log, rather than crashing the pipeline
- All values remain as strings (`str`) — numeric casting is deferred to `features/extractor.py`
- Timeout defaults to 300s; live capture duration is separate (controlled by TShark's `-a duration:` flag)
- The `-E occurrence=f` flag tells TShark to return only the first occurrence of each field per packet

---
### [2025-04-06] — Initial Project Architecture Created

**Type:** Infra
**Module(s) affected:** All (initial scaffold)
**Author:** Antigravity / Architect

#### Changes Made
- Created full project folder structure
- Scaffolded all Python modules with function signatures and docstrings
- Created `main.py` pipeline orchestrator
- Created `config/settings.py` with dataclass-based configuration
- Created `capture/tshark_runner.py` with TShark subprocess integration
- Created `features/extractor.py` with feature engineering pipeline
- Created `models/trainer.py` with Isolation Forest + Random Forest training
- Created `detection/anomaly_detector.py` with inference scoring
- Created `classification/attack_classifier.py` with attack labeling
- Created `visualization/report_generator.py` with HTML/JSON/PNG output
- Created `utils/logger.py`, `utils/validators.py`, `utils/file_helpers.py`

#### Features Added
- Full 5-stage ML pipeline: Capture → Features → Anomaly → Classify → Report
- TShark integration via subprocess (live + PCAP mode)
- Isolation Forest anomaly detection
- Random Forest attack classification
- HTML report generation with embedded matplotlib charts
- Structured JSON log output
- Rotating file logger
- Centralized configuration via `AppConfig` dataclasses

#### Bugs Fixed
- N/A (initial scaffold)

#### Notes / Decisions
- Chose Isolation Forest (unsupervised) for anomaly detection to handle zero-day attacks
  that would be missed by purely supervised classifiers
- TShark output uses `\t` separator (`-E separator=\t`) for reliable field splitting
- All numeric fields from TShark are strings by default — `pd.to_numeric(errors="coerce")`
  is used uniformly to handle missing/empty fields without crashing
- Random Forest chosen for classification due to its robustness on tabular data,
  interpretability via feature_importances_, and low sensitivity to hyperparameters
- Model training is intentionally separated from inference (trainer.py vs detector/classifier)
  so the live pipeline never triggers retraining
- All file paths are relative to project root, configurable via `config/settings.py`

---

## ── UPCOMING TASKS ───────────────────────────────────────────────

Add new to-do items here. Move to journal when completed.

- [ ] Add `data/README.md` explaining expected training data format
- [ ] Add `tests/` unit tests for all modules
- [ ] Add `requirements.txt` with pinned versions
- [ ] Implement `train_test_split` stratification warnings for imbalanced classes
- [ ] Add `__init__.py` files to all packages
- [ ] Test TShark capture on Ubuntu 22.04 with non-root user
- [ ] Implement flow-level feature aggregation (group by src+dst IP pair)
- [ ] Add SHAP explainability to classification output

---

## ── VERSION HISTORY ─────────────────────────────────────────────

| Version | Date       | Description                     |
|---------|------------|---------------------------------|
| v0.3.0  | 2026-04-06 | Implement features/extractor     |
| v0.2.0  | 2026-04-06 | Implement capture/tshark_runner  |
| v0.1.0  | 2025-04-06 | Initial architecture scaffold   |

---

*Keep this file updated. A good devlog is the difference between a project
that can be maintained and one that has to be rewritten from scratch.*

















