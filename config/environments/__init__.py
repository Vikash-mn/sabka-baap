"""Environment-specific config overrides."""

from config.environments.dev import OVERRIDES as DEV_OVERRIDES
from config.environments.prod import OVERRIDES as PROD_OVERRIDES

__all__ = ["DEV_OVERRIDES", "PROD_OVERRIDES"]
