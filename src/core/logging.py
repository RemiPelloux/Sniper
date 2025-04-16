import logging
import sys
import time

from src.core.config import settings

# Define log format based on rules (ISO8601, Level, Module:Line, Message)
LOG_FORMAT = (
    "%(asctime)s.%(msecs)03dZ [%(levelname)s] [%(name)s:%(lineno)d] %(message)s"
)
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def setup_logging(force_setup: bool = False) -> None:
    """Configure the root logger based on application settings.

    Args:
        force_setup: If True, remove existing handlers before setting up.
                     Useful for testing scenarios.
    """
    log_level_name = settings.log_level.upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()

    # Check if handlers are already configured (to prevent duplicates)
    if root_logger.hasHandlers() and not force_setup:
        # Only log warning if not forcing setup (tests might force repeatedly)
        root_logger.warning("Logger already configured. Skipping setup.")
        return

    # If forcing setup, remove existing handlers first
    if force_setup:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Set level
    root_logger.setLevel(log_level)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    # Use UTC time for logs
    formatter.converter = time.gmtime

    # Set formatter and add handler
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Avoid logging during forced setup potentially within tests
    if not force_setup:
        logging.info(f"Logging configured with level: {log_level_name}")
