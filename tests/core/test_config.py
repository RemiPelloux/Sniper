import os
from importlib import reload
from typing import Generator
from unittest.mock import patch

import pytest

# Import needs to happen *after* environment is patched potentially
from src.core import config as core_config


@pytest.fixture(autouse=True)
def reload_config_module() -> Generator[None, None, None]:
    """Ensure config module is reloaded for each test to pick up env patches."""
    # Must reload config before each test if using the singleton instance
    # or if other tests patch the environment.
    reload(core_config)
    yield
    # Optional: Reload again after test if needed for isolation
    # reload(core_config)


def test_settings_defaults() -> None:
    """Test that settings load with default values."""
    # Fixture handles reload
    settings = core_config.settings
    assert settings.log_level == "INFO"
    assert settings.tool_configs == {}


def test_settings_override_log_level_from_env() -> None:
    """Test that log_level can be overridden by environment variables."""
    test_log_level = "DEBUG"
    env_vars = {"SNIPER_LOG_LEVEL": test_log_level}

    with patch.dict(os.environ, env_vars, clear=True):
        reload(core_config)  # Reload config to see patched env vars
        settings = core_config.settings
        assert settings.log_level == test_log_level
        assert settings.tool_configs == {}


def test_settings_override_tool_configs_from_env() -> None:
    """Test that nested tool_configs can be overridden by environment variables."""
    env_vars = {
        "SNIPER_TOOL_CONFIGS__NMAP__SCRIPTS_PATH": "/custom/nmap/scripts",
        "SNIPER_TOOL_CONFIGS__ZAP__API_KEY": "test-key-123",
        "SNIPER_TOOL_CONFIGS__NMAP__EXTRA_FLAG": "--verbose",
        "SNIPER_LOG_LEVEL": "WARNING",  # Test mixing overrides
    }
    expected_tool_configs = {
        "nmap": {"scripts_path": "/custom/nmap/scripts", "extra_flag": "--verbose"},
        "zap": {"api_key": "test-key-123"},
    }

    with patch.dict(os.environ, env_vars, clear=True):
        reload(core_config)
        settings = core_config.settings
        assert settings.log_level == "WARNING"
        assert settings.tool_configs == expected_tool_configs


# Remove old fixture if no longer needed
# @pytest.fixture(autouse=True)
# def clean_env_vars() -> None:
#     ...
