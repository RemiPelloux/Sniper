from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""

    # Example setting: Logging level
    log_level: str = "INFO"

    # Dictionary to hold tool-specific configurations
    # Example: {"nmap": {"scripts_path": "/opt/nmap/scripts"}, "zap": {"api_key": "..."}}
    # Pydantic can load nested dicts from env vars.
    # TOOL_CONFIGS__NMAP__SCRIPTS_PATH="/path/to/scripts"  # noqa: E501
    tool_configs: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Configuration for Pydantic-Settings
    model_config = SettingsConfigDict(
        env_file=".env",  # Load .env file if it exists
        # Prefix for environment variables (e.g., SNIPER_LOG_LEVEL)
        env_prefix="SNIPER_",
        extra="ignore",  # Ignore extra fields from environment
        case_sensitive=False,
        # Allow parsing nested dicts from env vars
        # (e.g., TOOL_CONFIGS__NMAP__API_KEY='123')
        env_nested_delimiter="__",
    )


# Create a single instance of settings to be used throughout the application
# This instance will load settings upon import.
settings = Settings()


def load_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Load configuration from a file or return the default settings.

    Args:
        config_path: Optional path to a YAML configuration file.

    Returns:
        Dict containing configuration values.
    """
    # If a config path is provided, load from the file
    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Load configuration from YAML file
        with open(path, "r") as f:
            try:
                config_data = yaml.safe_load(f)
                # Override settings with values from file
                for key, value in config_data.items():
                    if hasattr(settings, key):
                        setattr(settings, key, value)
                return config_data
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing configuration file: {e}")

    # Return a dictionary representation of the settings object
    return settings.dict()


def get_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Get configuration from a file or return the default settings.
    This is a wrapper around load_config for backward compatibility.

    Args:
        config_path: Optional path to a YAML configuration file.

    Returns:
        Dict containing configuration values.
    """
    return load_config(config_path)


def load_scan_mode_config(mode_name: Optional[str] = None) -> Dict:
    """Load scan mode configuration from YAML file.

    Args:
        mode_name: Optional name of scan mode to load

    Returns:
        Dict containing scan mode configuration(s)

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If specified mode doesn't exist
    """
    config_dir = Path(__file__).parent.parent.parent / "config"
    config_file = config_dir / "scan_modes.yaml"

    if not config_file.exists():
        if mode_name:
            raise FileNotFoundError(f"Scan mode config file not found: {config_file}")
        return {}

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    if mode_name:
        if mode_name not in config:
            raise ValueError(f"Scan mode not found: {mode_name}")
        return config[mode_name]

    return config


def get_templates_dir() -> Path:
    """
    Get the path to the templates directory.

    Returns:
        Path: Path to the templates directory
    """
    templates_dir = Path(__file__).parent.parent.parent / "templates"

    # Create directory if it doesn't exist
    if not templates_dir.exists():
        templates_dir.mkdir(parents=True)

    return templates_dir
