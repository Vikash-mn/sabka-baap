"""Configuration loader with environment overrides."""

from __future__ import annotations

import os

from config.environments.dev import OVERRIDES as DEV_OVERRIDES
from config.environments.prod import OVERRIDES as PROD_OVERRIDES
from config.settings import CONFIG
from utils.helpers import deep_merge_dicts

ENVIRONMENT_OVERRIDES = {
    "dev": DEV_OVERRIDES,
    "prod": PROD_OVERRIDES,
}


def load_config(environment: str | None = None):
    """Merge the selected environment overrides into the shared config."""
    selected = (environment or os.environ.get("SABKA_BAAP_ENV") or "dev").lower()
    overrides = ENVIRONMENT_OVERRIDES.get(selected, {})
    merged = deep_merge_dicts(CONFIG, overrides)
    CONFIG.clear()
    CONFIG.update(merged)
    return CONFIG
