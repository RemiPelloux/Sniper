"""Logging configuration for the Sniper project."""

import logging
import sys
from typing import Optional

from src.core.config import settings


def setup_logging(level: Optional[str] = None, force_setup: bool = False) -> None:
    """Configure logging for the application.

    Args:
        level: Optional logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        force_setup: Force setup even if already configured
    """
    # Check if already configured and not forcing
    if not force_setup and len(logging.root.handlers) > 0:
        logging.warning("Logger already configured, skipping setup")
        return

    # Use provided level, or get from settings, or use default
    if level is None:
        level = settings.log_level

    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    # First clear any existing handlers if force_setup
    if force_setup:
        logging.root.handlers = []

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Set level for specific loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
