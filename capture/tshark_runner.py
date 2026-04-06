"""
capture/tshark_runner.py — TShark subprocess control and output parsing.

Builds TShark commands, runs them via subprocess, and parses the
tab-separated stdout into a list of packet dictionaries.

Supports two capture modes:
    • Live capture  — reads from a network interface for a set duration.
    • PCAP replay   — reads from a previously saved .pcap file.

Functions:
    build_tshark_command()  — construct the CLI argument list
    run_tshark()            — execute subprocess, handle errors
    parse_tshark_output()   — map raw lines to field dicts
    start_capture()         — high-level entrypoint used by main.py
"""

import shutil
import subprocess
from typing import Dict, Generator, List, Optional

from config.settings import TSHARK_FIELDS
from utils.logger import setup_logger

logger = setup_logger("capture.tshark_runner")

# ── Constants ────────────────────────────────────────────────────────────────
FIELD_SEPARATOR = "\t"
DEFAULT_REALTIME_FILTER = "ip and (tcp port 80 or tcp port 443)"


# ── Public API ───────────────────────────────────────────────────────────────


def build_tshark_command(
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    pcap_file: Optional[str] = None,
    fields: Optional[List[str]] = None,
    capture_filter: Optional[str] = None,
    tshark_path: str = "tshark",
) -> List[str]:
    """Construct the TShark command-line argument list.

    Args:
        interface:   Network interface name for live capture (e.g. "eth0").
        duration:    Capture duration in seconds (live mode only).
        pcap_file:   Path to a .pcap file for offline replay.
        fields:      Protocol fields to extract (default: TSHARK_FIELDS).
        capture_filter: Optional BPF capture filter expression for live capture.
        tshark_path: Absolute or relative path to the tshark binary.

    Returns:
        List of string arguments suitable for subprocess.run().

    Raises:
        ValueError: If neither interface nor pcap_file is provided.
    """
    if not interface and not pcap_file:
        raise ValueError(
            "Either 'interface' (live mode) or 'pcap_file' (offline mode) "
            "must be specified."
        )

    fields = fields or list(TSHARK_FIELDS)

    cmd: List[str] = [tshark_path]
    cmd += ["-l"]  # Force line-buffered output (important for realtime mode).

    # Source: live interface or pcap file
    if pcap_file:
        cmd += ["-r", pcap_file]
    else:
        cmd += ["-i", interface]
        if capture_filter:
            cmd += ["-f", capture_filter]
        if duration and duration > 0:
            cmd += ["-a", f"duration:{duration}"]

    # Output format: fields in tab-separated columns
    cmd += ["-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", f"separator={FIELD_SEPARATOR}"]
    cmd += ["-E", "header=n"]
    cmd += ["-E", "quote=n"]
    cmd += ["-E", "occurrence=f"]

    logger.debug("Built TShark command: %s", " ".join(cmd))
    return cmd


def run_tshark(cmd: List[str], timeout: int = 300) -> str:
    """Execute a TShark command and return its stdout as a string.

    Args:
        cmd:     Command list produced by build_tshark_command().
        timeout: Maximum seconds to wait for the process (default: 300).

    Returns:
        Raw stdout output from TShark (newline-separated packet lines).

    Raises:
        FileNotFoundError:     If the tshark binary cannot be found.
        subprocess.TimeoutExpired: If the process exceeds the timeout.
        RuntimeError:          If TShark exits with a non-zero return code.
    """
    tshark_bin = cmd[0]

    # Pre-flight check: is tshark installed?
    if shutil.which(tshark_bin) is None:
        logger.error(
            "TShark binary '%s' not found. "
            "Install Wireshark/TShark and ensure it is on PATH.",
            tshark_bin,
        )
        raise FileNotFoundError(
            f"TShark binary '{tshark_bin}' not found on system PATH. "
            "Please install TShark (https://www.wireshark.org/)."
        )

    logger.info("Running TShark: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("TShark process timed out after %d seconds.", timeout)
        raise

    # Handle non-zero exit
    if result.returncode != 0:
        stderr_msg = result.stderr.strip() if result.stderr else "(no stderr)"
        logger.error(
            "TShark exited with code %d — stderr: %s",
            result.returncode,
            stderr_msg,
        )
        raise RuntimeError(
            f"TShark failed (exit code {result.returncode}): {stderr_msg}"
        )

    logger.info("TShark finished successfully.")
    return result.stdout


def parse_tshark_output(
    raw_output: str,
    fields: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Parse tab-separated TShark output into a list of packet dicts.

    Each non-empty line is split by the tab separator and zipped with the
    field names to produce one dictionary per packet.

    Args:
        raw_output: Raw stdout string from run_tshark().
        fields:     Field names matching the extraction order
                    (default: TSHARK_FIELDS).

    Returns:
        List of dicts, each representing one captured packet.
        Empty list if TShark produced no output.
    """
    fields = fields or list(TSHARK_FIELDS)
    packets: List[Dict[str, str]] = []

    lines = raw_output.strip().splitlines()

    if not lines or (len(lines) == 1 and not lines[0].strip()):
        logger.warning("TShark produced no output — 0 packets captured.")
        return packets

    for line_no, line in enumerate(lines, start=1):
        values = line.split(FIELD_SEPARATOR)

        # Guard against malformed lines
        if len(values) != len(fields):
            logger.warning(
                "Skipping malformed line %d: expected %d fields, got %d.",
                line_no,
                len(fields),
                len(values),
            )
            continue

        packet = dict(zip(fields, values))
        packets.append(packet)

    logger.info("Parsed %d packets from TShark output.", len(packets))
    return packets


def _parse_tshark_line(line: str, fields: List[str], line_no: int) -> Optional[Dict[str, str]]:
    """Parse one tab-separated TShark line into a packet dict.

    Returns None for empty/malformed lines.
    """
    # Keep trailing tab-separated empty fields intact.
    clean = line.rstrip("\r\n")
    logger.debug("Raw line: %s", clean)

    if not clean.strip():
        return None

    values = clean.split(FIELD_SEPARATOR)
    if len(values) != len(fields):
        logger.warning(
            "Skipping malformed line %d: expected %d fields, got %d.",
            line_no,
            len(fields),
            len(values),
        )
        return None

    return dict(zip(fields, values))


def stream_packets(
    interface: str,
    fields: Optional[List[str]] = None,
    capture_filter: Optional[str] = None,
    tshark_path: str = "tshark",
) -> Generator[Dict[str, str], None, None]:
    """Stream packets from TShark line-by-line using subprocess.Popen.

    Args:
        interface: Network interface name for live capture.
        fields: Optional field list to extract.
        capture_filter: Optional BPF filter. If omitted, tries config.capture.filter
                        and then falls back to DEFAULT_REALTIME_FILTER.
        tshark_path: Path to the tshark binary.

    Yields:
        Parsed packet dictionaries.

    Raises:
        ValueError: If interface is not provided.
        FileNotFoundError: If tshark is not installed.
    """
    if not interface:
        raise ValueError("interface is required for stream_packets().")

    fields = fields or list(TSHARK_FIELDS)
    filter_expr = capture_filter
    if filter_expr is None:
        try:
            from config.settings import load_config

            cfg = load_config()
            filter_expr = getattr(cfg.capture, "filter", None)
        except Exception:
            filter_expr = None
    if filter_expr is None:
        filter_expr = DEFAULT_REALTIME_FILTER

    cmd = build_tshark_command(
        interface=interface,
        duration=None,
        pcap_file=None,
        fields=fields,
        capture_filter=filter_expr,
        tshark_path=tshark_path,
    )

    tshark_bin = cmd[0]
    if shutil.which(tshark_bin) is None:
        logger.error("TShark binary '%s' not found on PATH.", tshark_bin)
        raise FileNotFoundError(
            f"TShark binary '{tshark_bin}' not found on system PATH."
        )

    logger.info("Starting TShark stream: %s", " ".join(cmd))
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        if process.stdout is None:
            raise RuntimeError("Failed to attach to TShark stdout stream.")

        for line_no, line in enumerate(process.stdout, start=1):
            if not line.strip():
                continue

            packet = _parse_tshark_line(line, fields, line_no)
            if packet is None:
                continue

            yield packet
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

        stderr_msg = ""
        if process.stderr is not None:
            stderr_msg = process.stderr.read().strip()

        if process.returncode not in (None, 0, -15):
            logger.error(
                "TShark stream exited with code %d â€” stderr: %s",
                process.returncode,
                stderr_msg or "(no stderr)",
            )
        else:
            logger.info("TShark stream stopped.")


def start_capture(
    interface: Optional[str] = None,
    duration: Optional[int] = None,
    pcap_file: Optional[str] = None,
    fields: Optional[List[str]] = None,
    tshark_path: str = "tshark",
) -> List[Dict[str, str]]:
    """High-level entrypoint: build command → run → parse → return packets.

    This is the function called by main.py.  It orchestrates the full
    capture workflow and returns a ready-to-use list of packet dicts.

    Args:
        interface:   Network interface name (live mode).
        duration:    Capture duration in seconds (live mode).
        pcap_file:   Path to .pcap file (offline mode).
        fields:      Protocol fields to extract.
        tshark_path: Path to the tshark binary.

    Returns:
        List[Dict[str, str]] — one dict per captured packet.

    Raises:
        FileNotFoundError: If tshark is not installed.
        RuntimeError:      If tshark exits with an error.
        ValueError:        If neither interface nor pcap_file is given.
    """
    mode = "pcap" if pcap_file else "live"
    source = pcap_file if pcap_file else interface
    logger.info("Starting capture — mode=%s, source=%s", mode, source)

    # 1. Build command
    cmd = build_tshark_command(
        interface=interface,
        duration=duration,
        pcap_file=pcap_file,
        fields=fields,
        tshark_path=tshark_path,
    )

    # 2. Execute TShark
    raw_output = run_tshark(cmd)

    # 3. Parse output
    packets = parse_tshark_output(raw_output, fields=fields)

    if not packets:
        logger.warning("Capture finished but no packets were returned.")

    return packets
