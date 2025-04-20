"""
Tests for the Sandbox Plugin.
"""

import json
import logging
import os
import subprocess
import sys
from unittest.mock import MagicMock, call, patch

import pytest
import typer
from typer.testing import CliRunner

# Add project root to path for imports if necessary
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Also need the main plugin manager for context in CLI helper (Update path)
from src.sniper.core.plugin_manager import PluginManager

# Update imports
from src.sniper.plugins.sandbox.sandbox_plugin import (
    SANDBOX_ENVIRONMENTS,
    SandboxPlugin,
    sandbox_app,
)

# --- Fixtures ---


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_subprocess_run():
    """Fixture to mock subprocess.run."""
    with patch("subprocess.run") as mock_run:
        # Default success behavior
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Success", stderr="", check_returncode=lambda: None
        )
        yield mock_run


@pytest.fixture
def mock_docker_prereqs_success(mock_subprocess_run):
    """Mock subprocess to simulate docker & docker compose being present."""

    def side_effect(*args, **kwargs):
        cmd = args[0]
        if cmd == ["docker", "--version"]:
            return MagicMock(returncode=0, stdout="Docker version ...", stderr="")
        elif cmd == ["docker", "compose", "version"]:
            return MagicMock(
                returncode=0, stdout="Docker Compose version ...", stderr=""
            )
        # Default for other calls (like up, down, ps)
        return MagicMock(returncode=0, stdout="Default Mock Output", stderr="")

    mock_subprocess_run.side_effect = side_effect
    return mock_subprocess_run


@pytest.fixture
def mock_docker_prereqs_fail(mock_subprocess_run):
    """Mock subprocess to simulate docker or docker compose missing."""
    mock_subprocess_run.side_effect = FileNotFoundError("docker command not found")
    return mock_subprocess_run


@pytest.fixture
def mock_plugin_instance(mock_docker_prereqs_success):
    """Provides a mocked SandboxPlugin instance with successful prereqs."""
    # Patch the helper function used by CLI commands to return our controlled instance
    plugin = SandboxPlugin()
    # Manually set the plugin dir for consistency in tests if needed
    # plugin.plugin_dir = "/fake/plugin/dir"

    # Mock the internal check if needed, though mock_docker_prereqs_success handles it
    # plugin._check_docker_prerequisites = MagicMock(return_value=True)

    # Update patch target to the new location
    with patch(
        "src.sniper.plugins.sandbox.sandbox_plugin._get_sandbox_plugin_instance",
        return_value=plugin,
    ):
        yield plugin


# --- Plugin Unit Tests ---


def test_sandbox_plugin_load_success(mock_docker_prereqs_success):
    """Test successful loading of the SandboxPlugin."""
    plugin = SandboxPlugin()
    assert plugin.load() is True
    # Check that docker version and docker compose version were called
    assert mock_docker_prereqs_success.call_count >= 2
    calls = [
        call(["docker", "--version"], check=True, capture_output=True),
        call(["docker", "compose", "version"], check=True, capture_output=True),
    ]
    mock_docker_prereqs_success.assert_has_calls(calls, any_order=True)


def test_sandbox_plugin_load_fail(mock_docker_prereqs_fail, caplog):
    """Test loading failure when Docker prerequisites are not met."""
    plugin = SandboxPlugin()
    with caplog.at_level(logging.ERROR):
        assert plugin.load() is False
    assert "Docker or Docker Compose not found" in caplog.text


@patch("src.sniper.plugins.sandbox.sandbox_plugin.SandboxPlugin._stop_environment")
def test_sandbox_plugin_unload(mock_stop_env):
    """Test unloading the SandboxPlugin calls stop on known environments."""
    plugin = SandboxPlugin()
    assert plugin.unload() is True
    # Check _stop_environment was called for each known env
    expected_calls = [call(env_name, silent=True) for env_name in SANDBOX_ENVIRONMENTS]
    mock_stop_env.assert_has_calls(expected_calls, any_order=True)
    assert mock_stop_env.call_count == len(SANDBOX_ENVIRONMENTS)


def test_check_docker_prerequisites_success(mock_docker_prereqs_success):
    """Test _check_docker_prerequisites success path."""
    plugin = SandboxPlugin()
    assert plugin._check_docker_prerequisites() is True


def test_check_docker_prerequisites_fail(mock_docker_prereqs_fail):
    """Test _check_docker_prerequisites failure path."""
    plugin = SandboxPlugin()
    assert plugin._check_docker_prerequisites() is False


@patch("os.path.exists", return_value=True)
@patch("subprocess.run")
def test_start_environment_success(mock_run, mock_exists):
    """Test starting an environment successfully."""
    plugin = SandboxPlugin()
    plugin.plugin_dir = "/fake/path"  # Set fake path
    mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")

    env_name = "dvwa"
    compose_file = f"/fake/path/{SANDBOX_ENVIRONMENTS[env_name]}"

    assert plugin._start_environment(env_name) is True
    mock_exists.assert_called_with(compose_file)
    expected_cmd = ["docker", "compose", "-f", compose_file, "up", "-d"]
    mock_run.assert_called_once_with(
        expected_cmd, check=True, capture_output=True, text=True, cwd="/fake/path"
    )


@patch("os.path.exists", return_value=False)
def test_start_environment_compose_file_not_found(mock_exists, caplog):
    """Test starting an environment when compose file is missing."""
    plugin = SandboxPlugin()
    plugin.plugin_dir = "/fake/path"
    env_name = "dvwa"
    with caplog.at_level(logging.ERROR):
        assert plugin._start_environment(env_name) is False
    assert "Docker Compose file not found" in caplog.text


def test_start_environment_unknown(caplog):
    """Test starting an unknown environment."""
    plugin = SandboxPlugin()
    with caplog.at_level(logging.ERROR):
        assert plugin._start_environment("unknown_env") is False
    assert "Unknown sandbox environment: unknown_env" in caplog.text


@patch("os.path.exists", return_value=True)  # Assume file exists for stop attempt
@patch("subprocess.run")
def test_stop_environment_success(mock_run, mock_exists):
    """Test stopping an environment successfully."""
    plugin = SandboxPlugin()
    plugin.plugin_dir = "/fake/path"
    mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")

    env_name = "juiceshop"
    compose_file = f"/fake/path/{SANDBOX_ENVIRONMENTS[env_name]}"

    assert plugin._stop_environment(env_name) is True
    # mock_exists not necessarily called if we don't check in _stop_environment
    expected_cmd = ["docker", "compose", "-f", compose_file, "down"]
    mock_run.assert_called_once_with(
        expected_cmd, check=True, capture_output=True, text=True, cwd="/fake/path"
    )


@patch("subprocess.run", side_effect=FileNotFoundError("Docker not found"))
def test_run_docker_compose_file_not_found(mock_run, caplog):
    """Test _run_docker_compose when docker command is not found."""
    plugin = SandboxPlugin()
    with caplog.at_level(logging.ERROR):
        assert plugin._run_docker_compose(["-f", "file.yml", "up"]) is False
    assert "'docker compose' command not found" in caplog.text
    mock_run.assert_called_once()


@patch(
    "subprocess.run",
    side_effect=subprocess.CalledProcessError(
        1, ["docker", "compose"], stderr="Compose error"
    ),
)
def test_run_docker_compose_called_process_error(mock_run, caplog):
    """Test _run_docker_compose handling CalledProcessError."""
    plugin = SandboxPlugin()
    with caplog.at_level(logging.ERROR):
        assert plugin._run_docker_compose(["-f", "file.yml", "up"]) is False
    assert "Docker Compose command failed" in caplog.text
    assert "Compose error" in caplog.text
    mock_run.assert_called_once()


@patch("os.path.exists", return_value=True)
@patch("subprocess.run")
def test_get_status_parsing(mock_run, mock_exists):
    """Test parsing different docker compose ps outputs for status."""
    plugin = SandboxPlugin()
    plugin.plugin_dir = "/fake/path"
    env_name = "dvwa"
    compose_file = f"/fake/path/{SANDBOX_ENVIRONMENTS[env_name]}"
    expected_cmd = ["docker", "compose", "-f", compose_file, "ps", "--format", "json"]

    # Case 1: All running
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='{"Name":"dvwa_1","State":"running"}\n{"Name":"db_1","State":"running"}',
        stderr="",
    )
    assert plugin._get_status(env_name) == "Running"
    mock_run.assert_called_with(
        expected_cmd, check=True, capture_output=True, text=True, cwd="/fake/path"
    )

    # Case 2: Partially running
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='{"Name":"dvwa_1","State":"running"}\n{"Name":"db_1","State":"exited"}',
        stderr="",
    )
    assert plugin._get_status(env_name) == "Partially Running"

    # Case 3: All stopped / exited
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='{"Name":"dvwa_1","State":"exited"}\n{"Name":"db_1","State":"exited"}',
        stderr="",
    )
    assert plugin._get_status(env_name) == "Stopped / Issues"

    # Case 4: No services running (empty output or error)
    mock_run.return_value = MagicMock(
        returncode=0, stdout="\n \n ", stderr=""
    )  # Empty/whitespace
    assert plugin._get_status(env_name) == "Stopped"

    # Case 5: CalledProcessError (implies stopped)
    mock_run.side_effect = subprocess.CalledProcessError(1, expected_cmd)
    assert plugin._get_status(env_name) == "Stopped"
    mock_run.side_effect = None  # Reset side effect

    # Case 6: Invalid JSON
    mock_run.return_value = MagicMock(
        returncode=0, stdout='invalid json line\n{"State":"running"}', stderr=""
    )
    # If only one valid service is found and it's running, the status should be Running
    assert plugin._get_status(env_name) == "Running"


@patch("os.path.exists", return_value=False)
def test_get_status_unknown_or_not_found(mock_exists):
    """Test _get_status when compose file doesn't exist."""
    plugin = SandboxPlugin()
    assert plugin._get_status("dvwa") == "Unknown / Not Found"


# --- CLI Tests ---

# Use the mock_plugin_instance fixture to ensure the CLI commands
# interact with our controlled plugin instance and mocked subprocess


def test_cli_list_sandboxes(runner, mock_plugin_instance):
    """Test the 'sandbox list' command."""
    result = runner.invoke(sandbox_app, ["list"])
    assert result.exit_code == 0
    assert "Available Sandbox Environments:" in result.stdout
    for name, file in SANDBOX_ENVIRONMENTS.items():
        assert f"- {name}" in result.stdout
        assert file in result.stdout


def test_cli_start_sandbox_success(runner, mock_plugin_instance):
    """Test the 'sandbox start <env>' command success."""
    env_to_start = "dvwa"
    # mock_plugin_instance already patches the helper
    # Mock the specific method on the instance returned by the fixture
    mock_plugin_instance._start_environment = MagicMock(return_value=True)
    mock_plugin_instance._get_access_info = MagicMock(
        return_value="Access info for dvwa"
    )

    result = runner.invoke(sandbox_app, ["start", env_to_start])

    assert result.exit_code == 0
    assert (
        f"Sandbox environment '{env_to_start}' started successfully." in result.stdout
    )
    assert "Access info for dvwa" in result.stdout
    mock_plugin_instance._start_environment.assert_called_once_with(env_to_start)
    mock_plugin_instance._get_access_info.assert_called_once_with(env_to_start)


def test_cli_start_sandbox_fail(runner, mock_plugin_instance):
    """Test the 'sandbox start <env>' command failure."""
    env_to_start = "juiceshop"
    mock_plugin_instance._start_environment = MagicMock(return_value=False)

    result = runner.invoke(sandbox_app, ["start", env_to_start])

    assert result.exit_code == 1
    assert f"Failed to start sandbox environment '{env_to_start}'" in result.stdout
    mock_plugin_instance._start_environment.assert_called_once_with(env_to_start)


def test_cli_stop_sandbox_success(runner, mock_plugin_instance):
    """Test the 'sandbox stop <env>' command success."""
    env_to_stop = "dvwa"
    mock_plugin_instance._stop_environment = MagicMock(return_value=True)

    result = runner.invoke(sandbox_app, ["stop", env_to_stop])

    assert result.exit_code == 0
    assert f"Sandbox environment '{env_to_stop}' stopped successfully." in result.stdout
    mock_plugin_instance._stop_environment.assert_called_once_with(env_to_stop)


def test_cli_status_sandbox_all(runner, mock_plugin_instance):
    """Test the 'sandbox status' command (all environments)."""
    mock_plugin_instance._get_status = MagicMock(
        side_effect=lambda env: f"{env}_status"
    )

    result = runner.invoke(sandbox_app, ["status"])

    assert result.exit_code == 0
    assert "Sandbox Status:" in result.stdout
    for env_name in SANDBOX_ENVIRONMENTS:
        assert f"- {env_name}: {env_name}_status" in result.stdout
    assert mock_plugin_instance._get_status.call_count == len(SANDBOX_ENVIRONMENTS)


def test_cli_status_sandbox_specific(runner, mock_plugin_instance):
    """Test the 'sandbox status <env>' command."""
    env_to_check = "juiceshop"
    mock_plugin_instance._get_status = MagicMock(return_value="Running")
    mock_plugin_instance._get_access_info = MagicMock(return_value="Access info here")

    result = runner.invoke(sandbox_app, ["status", env_to_check])

    assert result.exit_code == 0
    assert "Sandbox Status:" in result.stdout
    assert f"- {env_to_check}: Running" in result.stdout
    assert "Access info here" in result.stdout
    mock_plugin_instance._get_status.assert_called_once_with(env_to_check)
    mock_plugin_instance._get_access_info.assert_called_once_with(env_to_check)


def test_cli_start_sandbox_docker_fail(runner, mock_docker_prereqs_fail):
    """Test CLI failure if docker check fails in helper."""
    # Update patch target
    with patch(
        "src.sniper.plugins.sandbox.sandbox_plugin._get_sandbox_plugin_instance"
    ) as mock_get_instance:
        # Make the helper raise the Exit exception because prereqs fail
        mock_get_instance.side_effect = typer.Exit(code=1)

        result = runner.invoke(sandbox_app, ["start", "dvwa"])

        assert result.exit_code == 1
        # The error message is echoed by the patched helper before exiting
        # runner.invoke captures stderr, but verifying exact message is tricky
        # Check exit code is sufficient here.


@patch("subprocess.run")
def test_docker_check_with_compose_missing(mock_run):
    """Test Docker check when Docker is installed but compose is missing."""
    def side_effect(*args, **kwargs):
        cmd = args[0]
        if cmd == ["docker", "--version"]:
            return MagicMock(returncode=0, stdout="Docker version 24.0.5", stderr="")
        elif cmd == ["docker", "compose", "version"]:
            raise FileNotFoundError("No docker compose")
        return MagicMock(returncode=0)

    mock_run.side_effect = side_effect
    plugin = SandboxPlugin()
    assert plugin._check_docker_prerequisites() is False


@patch("subprocess.run")
def test_docker_check_with_compose_error(mock_run):
    """Test Docker check when compose command returns error."""
    def side_effect(*args, **kwargs):
        cmd = args[0]
        if cmd == ["docker", "--version"]:
            return MagicMock(returncode=0, stdout="Docker version 24.0.5", stderr="")
        elif cmd == ["docker", "compose", "version"]:
            raise subprocess.CalledProcessError(1, ["docker", "compose"], "Error")
        return MagicMock(returncode=0)
    
    mock_run.side_effect = side_effect
    plugin = SandboxPlugin()
    assert plugin._check_docker_prerequisites() is False


@patch("subprocess.run")
def test_docker_check_with_docker_missing(mock_run):
    """Test Docker check when Docker itself is missing."""
    mock_run.side_effect = FileNotFoundError("docker command not found")
    plugin = SandboxPlugin()
    assert plugin._check_docker_prerequisites() is False


@patch("os.path.exists", return_value=True)
@patch("subprocess.run")
def test_get_access_info(mock_run, mock_exists):
    """Test getting access info for different environments."""
    plugin = SandboxPlugin()
    
    # Case 1: DVWA access info
    assert "http://localhost:80" in plugin._get_access_info("dvwa")
    
    # Case 2: Juice Shop access info
    assert "http://localhost:3000" in plugin._get_access_info("juiceshop")
    
    # Case 3: Unknown environment
    assert plugin._get_access_info("unknown") is None


@patch("os.path.join")
def test_get_compose_file_path(mock_join):
    """Test path construction for compose files."""
    plugin = SandboxPlugin()
    plugin.plugin_dir = "/fake/path"
    
    # Set up mock return values
    mock_join.side_effect = lambda *args: "/".join(args)
    
    # Case 1: Valid environment
    path = plugin._get_compose_file_path("dvwa")
    mock_join.assert_called_with("/fake/path", "docker-compose.dvwa.yml")
    
    # Case 2: Unknown environment
    path = plugin._get_compose_file_path("unknown")
    assert path is None
