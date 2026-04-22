#!/usr/bin/env python3
"""Primary cross-platform entry point for the scanner."""

from __future__ import annotations

import os
import sys
from typing import Sequence

from cli import main as cli_main
from config.loader import load_config
from gui.app import main as gui_main
from utils.helpers import ensure_directories
from utils.logger import configure_logging


def bootstrap(environment: str | None = None):
    """Prepare config, logging, and writable output folders."""
    config = load_config(environment or os.environ.get("SABKA_BAAP_ENV"))
    configure_logging()
    try:
        ensure_directories(
            config["paths"]["output_dir"],
            config["paths"]["screenshots_dir"],
        )
    except OSError:
        fallback_dir = os.path.join(os.getcwd(), "output")
        config["paths"]["output_dir"] = fallback_dir
        config["paths"]["screenshots_dir"] = os.path.join(fallback_dir, "screenshots")
        ensure_directories(
            config["paths"]["output_dir"],
            config["paths"]["screenshots_dir"],
        )
    return config


def main(argv: Sequence[str] | None = None):
    """Dispatch to the CLI by default or the GUI when requested."""
    args = list(sys.argv[1:] if argv is None else argv)
    bootstrap()

    if "--gui" in args or (args and args[0] == "gui"):
        return gui_main()

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
