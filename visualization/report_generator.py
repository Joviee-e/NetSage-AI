"""
visualization/report_generator.py - Production reporting for network analysis output.

This module generates:
    - Structured JSON output
    - Traffic distribution chart (normal vs anomaly)
    - Attack breakdown chart (by attack type)
    - Styled HTML report

Primary entrypoint:
    generate_report(df, base_output_dir)
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict

import matplotlib

# Headless backend so chart rendering works in servers/CI without GUI support.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

from utils.logger import setup_logger

logger = setup_logger("visualization.report_generator")


def _validate_dataframe(df: pd.DataFrame) -> None:
    """Validate that df is a non-empty pandas DataFrame."""
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if df.empty:
        raise ValueError("Input DataFrame is empty; cannot generate report outputs.")


def _ensure_output_dir(path: str) -> None:
    """Create output directory if needed."""
    if not path or not isinstance(path, str):
        raise ValueError("Output path must be a non-empty string.")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Unable to create output directory: {path}") from exc


def _require_columns(df: pd.DataFrame, required: list[str]) -> None:
    """Ensure required columns exist in df."""
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def _normalize_is_anomaly(series: pd.Series) -> pd.Series:
    """Normalize anomaly flags to integer 0/1 values.

    Supports boolean, numeric, and common text values.
    """
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False).astype(int)

    if pd.api.types.is_numeric_dtype(series):
        return (series.fillna(0).astype(float) != 0).astype(int)

    truthy = {"1", "true", "t", "yes", "y", "anomaly", "anomalous"}
    normalized = (
        series.astype(str)
        .str.strip()
        .str.lower()
        .map(lambda x: 1 if x in truthy else 0)
    )
    return normalized.astype(int)


def _prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Return a cleaned DataFrame copy used by all report generators."""
    _validate_dataframe(df)
    _require_columns(df, ["is_anomaly", "attack_type"])

    cleaned = df.copy()
    cleaned["is_anomaly"] = _normalize_is_anomaly(cleaned["is_anomaly"])
    cleaned["attack_type"] = cleaned["attack_type"].fillna("unknown").astype(str)
    return cleaned


def results_to_json(df: pd.DataFrame, output_path: str) -> str:
    """Write structured JSON results.

    JSON format:
    {
      "metadata": {"timestamp": ..., "total_packets": ..., "anomalies": ...},
      "summary": {"normal": ..., "anomaly": ...},
      "attack_distribution": {...},
      "data": [...]
    }
    """
    cleaned = _prepare_dataframe(df)
    out_dir = os.path.dirname(output_path) or "."
    _ensure_output_dir(out_dir)

    total_packets = int(len(cleaned))
    anomaly_count = int((cleaned["is_anomaly"] == 1).sum())
    normal_count = total_packets - anomaly_count

    payload: Dict[str, Any] = {
        "metadata": {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "total_packets": total_packets,
            "anomalies": anomaly_count,
        },
        "summary": {
            "normal": normal_count,
            "anomaly": anomaly_count,
        },
        "attack_distribution": cleaned["attack_type"].value_counts().to_dict(),
        "data": cleaned.to_dict(orient="records"),
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
    except OSError as exc:
        raise RuntimeError(f"Failed writing JSON file: {output_path}") from exc

    logger.info("JSON output written: %s", output_path)
    return output_path


def generate_traffic_chart(df: pd.DataFrame, output_path: str) -> str:
    """Generate normal-vs-anomaly traffic distribution PNG."""
    cleaned = _prepare_dataframe(df)
    out_dir = os.path.dirname(output_path) or "."
    _ensure_output_dir(out_dir)

    normal_count = int((cleaned["is_anomaly"] == 0).sum())
    anomaly_count = int((cleaned["is_anomaly"] == 1).sum())

    labels = ["Normal", "Anomaly"]
    values = [normal_count, anomaly_count]
    colors = ["#2E7D32", "#C62828"]

    plt.figure(figsize=(7.5, 4.5))
    bars = plt.bar(labels, values, color=colors)
    plt.title("Traffic Distribution (Normal vs Anomaly)")
    plt.xlabel("Traffic Type")
    plt.ylabel("Packet Count")
    plt.grid(axis="y", alpha=0.3)

    for bar in bars:
        height = int(bar.get_height())
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            str(height),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    try:
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
    except OSError as exc:
        raise RuntimeError(f"Failed writing traffic chart: {output_path}") from exc
    finally:
        plt.close()

    logger.info("Traffic chart written: %s", output_path)
    return output_path


def generate_attack_breakdown_chart(df: pd.DataFrame, output_path: str) -> str:
    """Generate attack type breakdown pie chart PNG."""
    cleaned = _prepare_dataframe(df)
    out_dir = os.path.dirname(output_path) or "."
    _ensure_output_dir(out_dir)

    distribution = cleaned["attack_type"].value_counts()

    plt.figure(figsize=(7, 6))
    plt.pie(
        distribution.values,
        labels=distribution.index.tolist(),
        autopct="%1.1f%%",
        startangle=140,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
    )
    plt.title("Attack Type Breakdown")

    try:
        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
    except OSError as exc:
        raise RuntimeError(f"Failed writing attack chart: {output_path}") from exc
    finally:
        plt.close()

    logger.info("Attack breakdown chart written: %s", output_path)
    return output_path


def generate_html_report(df: pd.DataFrame, output_dir: str) -> str:
    """Generate styled HTML report in output_dir as report.html."""
    cleaned = _prepare_dataframe(df)
    _ensure_output_dir(output_dir)

    report_path = os.path.join(output_dir, "report.html")
    timestamp = datetime.now().isoformat(timespec="seconds")

    total_packets = int(len(cleaned))
    anomaly_count = int((cleaned["is_anomaly"] == 1).sum())
    attack_distribution = cleaned["attack_type"].value_counts().to_dict()

    rows = "".join(
        f"<tr><td>{label}</td><td>{count}</td></tr>"
        for label, count in attack_distribution.items()
    )

    preview_table = cleaned.head(10).to_html(
        index=False,
        border=0,
        classes="preview-table",
    )

    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>Network Analysis Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; background: #F7F9FC; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #FFF; padding: 24px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    h1 {{ margin-bottom: 4px; }}
    .timestamp {{ color: #666; font-size: 13px; margin-top: 0; }}
    .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 18px 0; }}
    .card {{ background: #F3F6FB; border: 1px solid #D8E0EE; border-radius: 8px; padding: 12px 14px; min-width: 180px; }}
    .anomaly {{ color: #B00020; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
    th, td {{ border: 1px solid #DCE3EE; padding: 8px 10px; text-align: left; }}
    th {{ background: #EDF2FA; }}
    .charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; margin: 20px 0; }}
    .charts img {{ width: 100%; border: 1px solid #DCE3EE; border-radius: 8px; background: #FFF; }}
    .section-title {{ margin-top: 20px; margin-bottom: 10px; }}
  </style>
</head>
<body>
  <div class=\"container\">
    <h1>Network Analysis Report</h1>
    <p class=\"timestamp\">Generated: {timestamp}</p>

    <div class=\"summary\">
      <div class=\"card\"><strong>Total Packets</strong><div>{total_packets}</div></div>
      <div class=\"card\"><strong>Anomalies</strong><div class=\"anomaly\">{anomaly_count}</div></div>
      <div class=\"card\"><strong>Normal Packets</strong><div>{total_packets - anomaly_count}</div></div>
    </div>

    <h2 class=\"section-title\">Attack Breakdown</h2>
    <table>
      <thead><tr><th>Attack Type</th><th>Count</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>

    <h2 class=\"section-title\">Visualizations</h2>
    <div class=\"charts\">
      <div>
        <h3>Traffic Distribution</h3>
        <img src=\"traffic.png\" alt=\"Traffic distribution chart\" />
      </div>
      <div>
        <h3>Attack Breakdown</h3>
        <img src=\"attacks.png\" alt=\"Attack breakdown chart\" />
      </div>
    </div>

    <h2 class=\"section-title\">Data Preview (First 10 Rows)</h2>
    {preview_table}
  </div>
</body>
</html>
"""

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
    except OSError as exc:
        raise RuntimeError(f"Failed writing HTML report: {report_path}") from exc

    logger.info("HTML report written: %s", report_path)
    return report_path


def generate_report(df: pd.DataFrame, base_output_dir: str) -> Dict[str, str]:
    """Generate complete report artifacts in a timestamped subdirectory.

    Output directory format:
        base_output_dir/YYYY-MM-DD_HH-MM-SS/

    Files generated:
        report.html
        results.json
        traffic.png
        attacks.png
    """
    cleaned = _prepare_dataframe(df)
    _ensure_output_dir(base_output_dir)

    run_ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join(base_output_dir, run_ts)
    _ensure_output_dir(run_dir)

    json_path = os.path.join(run_dir, "results.json")
    traffic_path = os.path.join(run_dir, "traffic.png")
    attacks_path = os.path.join(run_dir, "attacks.png")
    html_path = os.path.join(run_dir, "report.html")

    results_to_json(cleaned, json_path)
    generate_traffic_chart(cleaned, traffic_path)
    generate_attack_breakdown_chart(cleaned, attacks_path)

    generated_html = generate_html_report(cleaned, run_dir)
    if generated_html != html_path:
        logger.warning(
            "Unexpected HTML path returned. expected=%s actual=%s",
            html_path,
            generated_html,
        )

    artifact_paths = {
        "output_dir": run_dir,
        "report_html": html_path,
        "results_json": json_path,
        "traffic_chart": traffic_path,
        "attack_chart": attacks_path,
    }

    logger.info("Report generation completed: %s", artifact_paths)
    return artifact_paths


if __name__ == "__main__":
    mock_df = pd.DataFrame(
        {
            "ip.src": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"],
            "ip.dst": ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5"],
            "is_anomaly": [0, 1, 0, 1, 0],
            "attack_type": ["normal", "DoS", None, "PortScan", "normal"],
            "attack_confidence": [1.0, 0.94, 1.0, 0.88, 1.0],
            "anomaly_score": [0.12, -0.33, 0.09, -0.41, 0.11],
        }
    )

    paths = generate_report(mock_df, os.path.join("output", "reports"))
    print("Generated file paths:")
    for key, value in paths.items():
        print(f"- {key}: {value}")
