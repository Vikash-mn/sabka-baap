"""Shared helper functions."""

from __future__ import annotations

import json
import os
from typing import Any, Dict


def ensure_directories(*paths: str):
    """Create folders when they do not already exist."""
    for path in paths:
        if path:
            os.makedirs(path, exist_ok=True)


def deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]):
    """Return a merged copy of two nested dictionaries."""
    merged: Dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, dict):
            merged[key] = deep_merge_dicts(value, {})
        elif isinstance(value, list):
            merged[key] = list(value)
        else:
            merged[key] = value

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge_dicts(merged[key], value)
        elif isinstance(value, list):
            merged[key] = list(value)
        else:
            merged[key] = value

    return merged


def write_json(path: str, payload: Any):
    """Write JSON data with stable formatting."""
    parent = os.path.dirname(path)
    if parent:
        ensure_directories(parent)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
