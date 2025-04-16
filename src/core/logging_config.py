import logging
import sys
from typing import Optional


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configures the root logger for the application.

    Args:
        log_level: The minimum logging level (e.g., "DEBUG", "INFO", "WARNING").
        log_file: Optional path to a file for logging output.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Define the format including ISO 8601 timestamp, level, module, and line number
    log_format = "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s"
    date_format = "%Y-%m-%dT%H:%M:%S%z" # ISO 8601 format

    formatter = logging.Formatter(log_format, datefmt=date_format)

    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates if this function is called multiple times
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level) # Console handler respects the overall level
    root_logger.addHandler(console_handler)

    # Configure file handler if path is provided
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='a') # Append mode
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level) # File handler also respects the overall level
            root_logger.addHandler(file_handler)
            logging.info(f"Logging configured. Level: {log_level}. Outputting to console and file: {log_file}")
        except Exception as e:
            logging.error(f"Failed to configure file logging to {log_file}: {e}", exc_info=True)
            print(f"Error: Could not open log file {log_file}. Check permissions.", file=sys.stderr)
    else:
        logging.info(f"Logging configured. Level: {log_level}. Outputting to console.")

# Basic configuration call to ensure logging is minimally functional if not explicitly set up
# This will be overridden by a call in the CLI entry point.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s:%(name)s:%(message)s") 