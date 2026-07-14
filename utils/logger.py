"""Logging helpers for production-grade operational visibility."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from crypto.constants import DEFAULT_LOG_DIR_NAME, DEFAULT_LOG_FILE_NAME


def configure_logging(log_level: str = "INFO", verbose: bool = False, quiet: bool = False, log_directory: Path | None = None) -> logging.Logger:
    """Configure application logging with console and rotating file handlers.

    Args:
        log_level: Log level name.
        verbose: Enable verbose console logging.
        quiet: Suppress console logging.
        log_directory: Directory for log files.

    Returns:
        A configured application logger.
    """

    logger = logging.getLogger("secure_backup")
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    if verbose:
        numeric_level = logging.DEBUG
    if quiet:
        numeric_level = max(numeric_level, logging.WARNING)
    logger.setLevel(numeric_level)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s", "%Y-%m-%d %H:%M:%S")
    log_path = (log_directory or Path(DEFAULT_LOG_DIR_NAME)) / DEFAULT_LOG_FILE_NAME
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if not quiet:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(numeric_level)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger
