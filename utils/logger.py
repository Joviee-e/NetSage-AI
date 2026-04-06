"""
utils/logger.py — Centralised logging with console + rotating file output.

Usage:
    from utils.logger import setup_logger
    logger = setup_logger("my_module")
    logger.info("Hello from my_module")
"""

import logging
import os
from logging.handlers import TimedRotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

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

    if logger.hasHandlers():
        for handler in logger.handlers:
            handler.close()
        logger.handlers.clear()

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(_FORMAT)

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Timed rotating file handler
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = TimedRotatingFileHandler(
        LOG_FILE,
        when="midnight",
        interval=1,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
        delay=True,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
