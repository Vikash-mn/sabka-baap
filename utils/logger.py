"""Centralized logging helpers."""

from __future__ import annotations

import logging


def configure_logging(level: int = logging.INFO):
    """Set a project-wide logging configuration once."""
    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
        return root_logger

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    return logging.getLogger()


def get_logger(name: str):
    """Return a configured module logger."""
    configure_logging()
    return logging.getLogger(name)
