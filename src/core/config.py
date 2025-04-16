from typing import Any

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
