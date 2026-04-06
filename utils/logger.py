"""
utils/logger.py — Centralised logging with console + rotating file output.

Usage:
    from utils.logger import setup_logger
    logger = setup_logger("my_module")
    logger.info("Hello from my_module")
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Maximum log file size before rotation (5 MB)
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3

_FORMAT = "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s"


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create or retrieve a logger with console + rotating-file handlers.

    Args:
        name:  Logger name (usually the module name).
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(_FORMAT)

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Rotating file handler
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
