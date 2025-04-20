"""
Integration tests for the Sandbox Plugin.

These tests verify that the Sandbox Plugin is properly discovered, loaded,
and can execute commands successfully.
"""

import os
import subprocess
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from src.sniper.core.plugin_manager import PluginManager
from src.sniper.plugins.sandbox.sandbox_plugin import (
    SANDBOX_ENVIRONMENTS,
    SandboxPlugin,
    list_sandboxes,
    sandbox_app,
)


@pytest.fixture
def runner():
    """Provides a CliRunner for testing Typer CLI commands."""
    return CliRunner()


@pytest.fixture
def plugin_manager():
    """Provides a configured PluginManager for testing."""
    # Use the correct plugin directory
    manager = PluginManager(plugin_dirs=["src/sniper/plugins"])
    manager.discover_plugins()
    yield manager
    # Clean up plugins after tests
    manager.unload_all_plugins()


@pytest.mark.integration
def test_plugin_discovery(plugin_manager):
    """Test that the Sandbox plugin is properly discovered."""
    # Check that the Sandbox plugin class is discovered
    assert "Sandbox" in plugin_manager._discovered_plugin_classes
    # Instantiate the plugin
    instance = plugin_manager.instantiate_plugin("Sandbox")
    # Check by name rather than direct type comparison, which can fail due to
    # the way imports work in Python
    assert instance is not None
    assert instance.name == "Sandbox"


@pytest.mark.integration
def test_plugin_loading(plugin_manager):
    """Test that the Sandbox plugin can be loaded."""
    # Mock the Docker check to always succeed
    with patch.object(SandboxPlugin, "_check_docker_prerequisites", return_value=True):
        assert plugin_manager.load_plugin("Sandbox")
        assert "Sandbox" in plugin_manager.loaded_plugins


@pytest.mark.integration
def test_sandbox_cli_integration(runner):
    """Test the sandbox CLI commands."""
    # Mock the subprocess calls to avoid actually running Docker commands
    with patch("subprocess.run") as mock_run:
        # Configure mock to return success
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"Docker version 20.10.8\n"

        # Test list command
        result = runner.invoke(sandbox_app, ["list"])
        assert result.exit_code == 0
        assert "Available Sandbox Environments:" in result.stdout
        for name in SANDBOX_ENVIRONMENTS:
            assert name in result.stdout


@pytest.mark.integration
def test_sandbox_commands_with_mock_docker(runner):
    """Test all sandbox commands with mocked Docker interactions."""
    # Create a sandbox plugin instance for mocking
    sandbox_plugin = SandboxPlugin()

    # Mock the Docker prerequisite check to always return True
    with patch.object(SandboxPlugin, "_check_docker_prerequisites", return_value=True):
        # Mock subprocess to avoid actual Docker commands
        with patch("subprocess.run") as mock_run:
            # Configure mock to return success for all commands
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = b"Docker version 20.10.8\n"

            # Mock the _get_sandbox_plugin_instance function to return our controlled instance
            with patch(
                "src.sniper.plugins.sandbox.sandbox_plugin._get_sandbox_plugin_instance",
                return_value=sandbox_plugin,
            ):

                # Mock the internal environment handling methods
                with patch.object(
                    sandbox_plugin, "_start_environment", return_value=True
                ):
                    with patch.object(
                        sandbox_plugin, "_stop_environment", return_value=True
                    ):
                        with patch.object(
                            sandbox_plugin, "_get_status", return_value="Running"
                        ):

                            # Test environment name validation
                            env_name = "dvwa"  # Use a valid environment name

                            # Test start command
                            result = runner.invoke(sandbox_app, ["start", env_name])
                            assert result.exit_code == 0

                            # Test status command
                            result = runner.invoke(sandbox_app, ["status", env_name])
                            assert result.exit_code == 0

                            # Test stop command
                            result = runner.invoke(sandbox_app, ["stop", env_name])
                            assert result.exit_code == 0

                # Test with invalid environment name - should fail
                # We need a separate test for this as we want it to fail
                with patch.object(
                    sandbox_plugin, "_start_environment", return_value=False
                ):
                    result = runner.invoke(sandbox_app, ["start", "nonexistent"])
                    assert result.exit_code == 1


# Optional: Only run if Docker is actually available
@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SKIP_DOCKER_TESTS") == "1",
    reason="Docker tests disabled via environment variable",
)
def test_docker_prerequisite_check():
    """Test the Docker prerequisite check with actual Docker installation."""
    plugin = SandboxPlugin()
    try:
        # Try to run a simple Docker command
        subprocess.run(
            ["docker", "--version"], check=True, capture_output=True, timeout=5
        )
        # If Docker is available, the check should pass
        assert plugin._check_docker_prerequisites()
    except (subprocess.SubprocessError, FileNotFoundError):
        # If Docker is not available, the test is still valid but should be skipped
        pytest.skip("Docker not available on this system")
