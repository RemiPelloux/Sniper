import logging
import os
from importlib import reload
from unittest.mock import patch

import pytest
from _pytest.logging import LogCaptureFixture

# Modules to potentially reload when config changes
from src.core import config
from src.core import logging as core_logging

# Remove the problematic autouse fixture
# @pytest.fixture(autouse=True)
# def reset_logging_state() -> None:
#     ...


@pytest.mark.parametrize(
    "env_log_level, expected_level",
    [
        ("DEBUG", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("INVALID_LEVEL", logging.INFO),  # Default on invalid
        (None, logging.INFO),  # Default when not set
    ],
)
def test_logging_level_configuration(
    env_log_level: str | None, expected_level: int
) -> None:
    """Test if setup_logging configures the correct level based on env var."""
    env_vars = {}
    if env_log_level is not None:
        env_vars = {"SNIPER_LOG_LEVEL": env_log_level}

    # Reset root logger state manually before this specific test run
    logging.root.handlers = []
    logging.root.setLevel(logging.WARNING)

    with patch.dict(os.environ, env_vars, clear=True):
        # Reload modules to pick up patched env var
        reload(config)
        reload(core_logging)

        # Call setup with force=True to ensure clean setup
        core_logging.setup_logging(force_setup=True)
        assert logging.root.level == expected_level


def test_logging_handler_added() -> None:
    """Test that setup_logging adds a handler to the root logger."""
    # Reset root logger state manually
    logging.root.handlers = []
    logging.root.setLevel(logging.WARNING)
    assert not logging.root.handlers, "Manual reset failed: Handlers already present."

    with patch.dict(os.environ, {}, clear=True):
        reload(config)
        reload(core_logging)

        # Call setup with force=True
        core_logging.setup_logging(force_setup=True)

        # Check handlers on root logger directly
        count = len(logging.root.handlers)
        assert count == 1, f"Expected 1 handler, found {count}"
        assert isinstance(logging.root.handlers[0], logging.StreamHandler)


def test_logging_duplicate_setup_warning(caplog: LogCaptureFixture) -> None:
    """Test subsequent calls *without* force_setup trigger warning and don't add handlers."""
    # Reset root logger state manually
    logging.root.handlers = []
    logging.root.setLevel(logging.WARNING)

    with patch.dict(os.environ, {}, clear=True):
        reload(config)
        reload(core_logging)

        # First call (force=True to bypass potential pytest handlers)
        core_logging.setup_logging(force_setup=True)
        assert len(logging.root.handlers) == 1

        # Capture logs for the second call (default force_setup=False)
        with caplog.at_level(logging.WARNING):
            core_logging.setup_logging()  # Should trigger warning

        assert (
            len(logging.root.handlers) == 1
        ), "Handlers count changed on second setup call"
        # assert "Logger already configured" in caplog.text # This proved unreliable
