"""
Tests for the sandbox CLI commands.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from src.sniper.plugins.sandbox.sandbox_plugin import (
    SANDBOX_ENVIRONMENTS,
    SandboxPlugin,
    list_sandboxes,
    sandbox_app,
    start_sandbox,
    stop_sandbox,
)


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def mock_plugin_instance():
    """Mock the sandbox plugin instance that would be returned by _get_sandbox_plugin_instance."""
    plugin_mock = MagicMock(spec=SandboxPlugin)
    plugin_mock._check_docker_prerequisites.return_value = True
    plugin_mock._start_environment.return_value = True
    plugin_mock._stop_environment.return_value = True
    plugin_mock._get_status.return_value = "Running"
    plugin_mock._get_access_info.return_value = "http://localhost:80"
    
    with patch("src.sniper.plugins.sandbox.sandbox_plugin._get_sandbox_plugin_instance", return_value=plugin_mock):
        yield plugin_mock


def test_list_sandboxes_command(cli_runner, mock_plugin_instance):
    """Test the list sandboxes command shows all available environments."""
    result = cli_runner.invoke(sandbox_app, ["list"])
    assert result.exit_code == 0
    
    # Check that the output lists all environments
    for env_name in SANDBOX_ENVIRONMENTS:
        assert env_name in result.stdout


@pytest.mark.parametrize("env_name", ["dvwa", "juiceshop"])
def test_start_sandbox_command_success(cli_runner, mock_plugin_instance, env_name):
    """Test starting a sandbox environment successfully."""
    result = cli_runner.invoke(sandbox_app, ["start", env_name])
    assert result.exit_code == 0
    
    # Verify _start_environment was called with correct env name
    mock_plugin_instance._start_environment.assert_called_once_with(env_name)
    assert f"Sandbox environment '{env_name}' started successfully." in result.stdout


def test_start_sandbox_command_failure(cli_runner, mock_plugin_instance):
    """Test error handling when starting a sandbox fails."""
    mock_plugin_instance._start_environment.return_value = False
    
    result = cli_runner.invoke(sandbox_app, ["start", "dvwa"])
    assert result.exit_code == 1
    assert "Failed to start" in result.stdout


@pytest.mark.parametrize("env_name", ["dvwa", "juiceshop"])
def test_stop_sandbox_command_success(cli_runner, mock_plugin_instance, env_name):
    """Test stopping a sandbox environment successfully."""
    result = cli_runner.invoke(sandbox_app, ["stop", env_name])
    assert result.exit_code == 0
    
    # Verify _stop_environment was called with correct env name
    mock_plugin_instance._stop_environment.assert_called_once_with(env_name)
    assert f"Sandbox environment '{env_name}' stopped successfully." in result.stdout


def test_stop_sandbox_command_failure(cli_runner, mock_plugin_instance):
    """Test error handling when stopping a sandbox fails."""
    mock_plugin_instance._stop_environment.return_value = False
    
    result = cli_runner.invoke(sandbox_app, ["stop", "dvwa"])
    assert result.exit_code == 0
    assert "Failed to stop" in result.stdout


def test_sandbox_status_command_all(cli_runner, mock_plugin_instance):
    """Test showing status of all sandbox environments."""
    result = cli_runner.invoke(sandbox_app, ["status"])
    assert result.exit_code == 0
    
    # Should check status for all envs
    assert mock_plugin_instance._get_status.call_count == len(SANDBOX_ENVIRONMENTS)
    # Should include all environment names in output
    for env_name in SANDBOX_ENVIRONMENTS:
        assert env_name in result.stdout


def test_sandbox_status_command_specific(cli_runner, mock_plugin_instance):
    """Test showing status of a specific sandbox environment."""
    env_name = "dvwa"
    result = cli_runner.invoke(sandbox_app, ["status", env_name])
    assert result.exit_code == 0
    
    # Should check status only for specific env
    mock_plugin_instance._get_status.assert_called_once_with(env_name)
    # Should include environment name in output
    assert env_name in result.stdout


def test_sandbox_command_unknown_environment(cli_runner, mock_plugin_instance):
    """Test handling unknown sandbox environment names."""
    # Configure mock to return False for unknown environments
    mock_plugin_instance._start_environment.side_effect = lambda env: env in SANDBOX_ENVIRONMENTS
    
    result = cli_runner.invoke(sandbox_app, ["start", "unknown_sandbox"])
    assert result.exit_code == 1
    assert "Failed to start" in result.stdout 