import json
from typing import Any, Optional

import pytest
from typer.testing import CliRunner

# Correctly import the main app and the ToolManager
from src.cli.main import app  # Use main app for testing integration
from src.tools.manager import ToolCategory, ToolManager

runner = CliRunner()


# Mock ToolManager and its methods based on src/cli/tools.py usage
class MockToolManager:
    def __init__(self) -> None:
        # Use the structure expected by the actual ToolManager methods
        self._tools_data: dict[str, dict[str, Any]] = {
            "nmap": {
                "name": "nmap",
                "category": ToolCategory.RECONNAISSANCE.value,
                "description": "Network exploration tool and security / port scanner",
                "website": "https://nmap.org",
                "install": {"apt": "sudo apt install nmap"},
                "update": {"apt": "sudo apt update && sudo apt install nmap"},
            },
            "zap": {
                "name": "zap",
                "category": ToolCategory.VULNERABILITY_SCANNING.value,
                "description": "OWASP Zed Attack Proxy Project",
                "website": "https://www.zaproxy.org/",
                "install": {"script": "./install_zap.sh"},
                "update": {"script": "./update_zap.sh"},
            },
        }
        self._installation_status = {
            "nmap": True,
            "zap": False,
        }
        # Track install/update attempts for verification
        self.install_attempts: list[str] = []
        self.update_attempts: list[str] = []

    def get_all_tools(self) -> dict[str, dict[str, Any]]:
        # Return the dictionary as the original code expects
        return self._tools_data

    def get_installation_status(self) -> dict[str, bool]:
        return self._installation_status

    def get_tool(self, name: str) -> Optional[dict[str, Any]]:
        # Return the dictionary for the specific tool
        return self._tools_data.get(name)

    def check_tool_availability(self, name: str) -> bool:
        return self._installation_status.get(name, False)

    def get_tool_names_by_category(self, category: str) -> list[str]:
        return [
            name
            for name, data in self._tools_data.items()
            if data.get("category") == category
        ]

    # --- Mock Install/Update Methods ---
    def install_tool(self, name: str) -> bool:
        """Mock installation. Assumes success unless overridden in tests."""
        self.install_attempts.append(name)
        if name in self._tools_data:
            # Simulate successful install by changing status
            self._installation_status[name] = True
            return True
        return False  # Tool not found

    def update_tool(self, name: str, method: Optional[str] = None) -> Optional[bool]:
        """Mock update. Assumes success for known, installed tools unless overridden."""
        self.update_attempts.append(name)
        # Check if installed and has an update method
        if name in self._tools_data and self._installation_status.get(name):
            if "update" in self._tools_data[name]:
                # Simulate successful update (no status change needed)
                return True
            else:
                return None  # No update method defined
        elif name not in self._installation_status:
            return False  # Tool doesn't exist
        else:
            return False  # Tool not installed

    def add_tool(self, name: str, config: dict[str, Any], custom: bool = True) -> bool:
        """Mock add_tool method for testing."""
        self.install_attempts.append(name)
        self._tools_data[name] = config
        self._installation_status[name] = True
        return True

    def get_tool_categories(self) -> set[str]:
        """Return a set of unique categories from the loaded tools."""
        return {
            data.get("category", "miscellaneous") for data in self._tools_data.values()
        }

    def remove_tool(self, name: str) -> bool:
        """Mock implementation of remove_tool.

        Removes a custom tool from the manager.

        Args:
            name (str): The name of the tool to remove

        Returns:
            bool: True if the tool was removed successfully, False otherwise
        """
        if name in self._tools_data:
            del self._tools_data[name]
            if name in self._installation_status:
                del self._installation_status[name]
            return True
        return False

    def check_for_updates(self) -> dict[str, bool]:
        """Mock implementation of check_for_updates.

        Returns:
            dict[str, bool]: Dictionary mapping tool names to update status
            True = update available, False = up to date, None = error/not installed
        """
        # By default, pretend that installed tools are up to date
        updates = {}
        for name in self._tools_data:
            if name in self._installation_status and self._installation_status[name]:
                updates[name] = False  # Tool is installed and up to date by default
            else:
                updates[name] = None  # Tool is not installed

        # Can be overridden in tests
        return updates


@pytest.fixture(autouse=True)
def mock_tool_manager(monkeypatch):
    """Autouse fixture to replace ToolManager with a mock."""
    mock_manager = MockToolManager()
    # Patch the ToolManager where it's instantiated in src/cli/tools.py
    monkeypatch.setattr("src.cli.tools.ToolManager", lambda: mock_manager)
    return mock_manager


# Helper to strip ANSI codes for cleaner assertion checks
import re


def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


# Mark tests as skipped due to Typer/testing incompatibility
# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_list_tools_success_table() -> None:
    """Test the 'sniper tools list' command with default table output."""
    result = runner.invoke(app, ["tools", "list"])  # Reverted to main app
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    # Check table headers
    assert "Name" in output
    assert "Category" in output
    assert "Description" in output
    assert "Status" in output
    # Check tool data (exact spacing might vary, check content)
    assert "nmap" in output
    assert "reconnaissance" in output
    assert "Installed" in output
    assert "zap" in output
    assert "vulnerability_scanning" in output
    assert "Not Installed" in output
    assert "Total: 2 tools" in output


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_list_tools_success_json() -> None:
    """Test the 'sniper tools list --json' command."""
    result = runner.invoke(app, ["tools", "list", "--json"])  # Reverted to main app
    assert result.exit_code == 0
    try:
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 2
        # Check nmap data
        nmap_data = next((item for item in data if item["name"] == "nmap"), None)
        assert nmap_data is not None
        assert nmap_data["category"] == "reconnaissance"
        assert nmap_data["installed"] is True
        # Check zap data
        zap_data = next((item for item in data if item["name"] == "zap"), None)
        assert zap_data is not None
        assert zap_data["category"] == "vulnerability_scanning"
        assert zap_data["installed"] is False
    except json.JSONDecodeError:
        pytest.fail(f"Output was not valid JSON: {result.stdout}")


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_list_tools_filter_category() -> None:
    """Test 'sniper tools list --category reconnaissance'."""
    result = runner.invoke(
        app, ["tools", "list", "--category", "reconnaissance"]
    )  # Reverted to main app
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert "nmap" in output
    assert "zap" not in output
    assert "Total: 1 tools" in output
    assert "Category: reconnaissance" in output


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_list_tools_filter_installed() -> None:
    """Test 'sniper tools list --installed'."""
    result = runner.invoke(
        app, ["tools", "list", "--installed"]
    )  # Reverted to main app
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert "nmap" in output
    assert "Installed" in output
    assert "zap" not in output
    assert "Not Installed" not in output
    assert "Total: 1 tools" in output


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_list_tools_filter_not_installed() -> None:
    """Test 'sniper tools list --not-installed'."""
    result = runner.invoke(
        app, ["tools", "list", "--not-installed"]
    )  # Reverted to main app
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert "nmap" not in output
    assert "Not Installed" in output
    assert "zap" in output
    assert "Total: 1 tools" in output
    assert "Status: Not Installed" in output


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_show_tool_found() -> None:
    """Test the 'sniper tools show <tool_name>' command for an existing tool."""
    result = runner.invoke(app, ["tools", "show", "nmap"])  # Reverted to main app
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert "=== nmap ===" in output
    assert "Category: reconnaissance" in output
    assert "Description: Network exploration tool and security / port scanner" in output
    assert "Status: Installed" in output  # Adjusted to match actual output format
    assert "Website: https://nmap.org" in output
    assert "Installation Methods:" in output
    assert "- apt: sudo apt install nmap" in output
    assert "Update Methods:" in output
    assert "- apt: sudo apt update && sudo apt install nmap" in output


# @pytest.mark.skip(
#     reason="Skipping due to typer.testing.CliRunner incompatibility with nested apps or fixtures."
# )
def test_show_tool_not_found() -> None:
    """Test the 'sniper tools show <tool_name>' command for a non-existent tool."""
    result = runner.invoke(
        app, ["tools", "show", "nonexistenttool"]
    )  # Reverted to main app
    assert (
        result.exit_code == 1
    )  # Expecting non-zero exit code for tool not found error
    output = strip_ansi(result.stdout)
    # Check the specific error message format from print_error
    assert "✗ Tool 'nonexistenttool' not found" in output


# --- Tests for install_tool ---


def test_install_tool_success(mock_tool_manager: MockToolManager) -> None:
    """Test 'sniper tools install <tool_name>' for a tool not yet installed."""
    tool_to_install = "zap"  # Zap is initially not installed in the mock
    assert not mock_tool_manager._installation_status[tool_to_install]

    result = runner.invoke(app, ["tools", "install", tool_to_install])

    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert f"Installing {tool_to_install}..." in output
    assert f"✓ Successfully installed {tool_to_install}" in output
    assert "Installation Summary:" in output
    assert "Successfully installed: 1" in output
    # assert "Failed to install: 0" in output # This line is only printed if failures > 0

    # Verify mock state
    assert mock_tool_manager.install_attempts == [tool_to_install]
    assert mock_tool_manager._installation_status[tool_to_install] is True


def test_install_tool_already_installed(mock_tool_manager: MockToolManager) -> None:
    """Test 'sniper tools install <tool_name>' for a tool already installed."""
    tool_to_install = "nmap"  # Nmap is initially installed in the mock
    assert mock_tool_manager._installation_status[tool_to_install] is True

    # Reset install attempts before invoking
    mock_tool_manager.install_attempts = []

    result = runner.invoke(app, ["tools", "install", tool_to_install])

    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert f"Installing {tool_to_install}..." in output
    # The ToolManager._install_tool method handles the "already installed" check and logs info
    # The CLI itself doesn't print a specific message for already installed, it relies on the manager log
    # The CLI *does* print the success message because the manager returns True.
    # We could enhance the CLI to print a specific message, but for now test current behaviour.
    assert f"✓ Successfully installed {tool_to_install}" in output
    assert "Installation Summary:" in output
    assert "Successfully installed: 1" in output

    # Verify install_tool was NOT called because manager handles the check internally
    # Update: Actually, the CLI calls install_tool, which then checks availability.
    # So install_attempts should still contain the tool.
    assert mock_tool_manager.install_attempts == [tool_to_install]
    assert (
        mock_tool_manager._installation_status[tool_to_install] is True
    )  # Status remains true


def test_install_tool_failure(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test 'sniper tools install <tool_name>' when installation fails."""
    tool_to_install = "zap"
    assert not mock_tool_manager._installation_status[tool_to_install]

    # Force the mock install_tool method to return False for this test
    monkeypatch.setattr(mock_tool_manager, "install_tool", lambda name: False)
    # Reset attempts
    mock_tool_manager.install_attempts = []

    result = runner.invoke(app, ["tools", "install", tool_to_install])

    assert result.exit_code == 0  # Command should still exit 0, but report failure
    output = strip_ansi(result.stdout)
    assert f"Installing {tool_to_install}..." in output
    assert f"✗ Installation failed for {tool_to_install}" in output
    assert "Installation Summary:" in output
    assert "Successfully installed: 0" in output
    assert "Failed to install: 1" in output

    # Verify mock state (install was attempted, status didn't change)
    # The patched method doesn't append to install_attempts, so we can't check that easily.
    # assert mock_tool_manager.install_attempts == [tool_to_install]
    assert not mock_tool_manager._installation_status[tool_to_install]


# --- Tests for update_tool ---


def test_update_tool_success(mock_tool_manager: MockToolManager) -> None:
    """Test 'sniper tools update <tool_name>' for an installed tool."""
    tool_to_update = "nmap"  # Nmap is installed and has update method in mock
    assert mock_tool_manager._installation_status[tool_to_update] is True

    # Reset update attempts
    mock_tool_manager.update_attempts = []

    result = runner.invoke(app, ["tools", "update", tool_to_update])

    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert f"Updating {tool_to_update}..." in output
    assert f"✓ Successfully updated {tool_to_update}" in output
    assert "Update Summary:" in output
    assert "Successfully updated: 1" in output
    assert "Failed to update: 0" not in output  # Check failure message isn't printed
    assert (
        "Skipped/Not applicable: 0" not in output
    )  # Check skipped message isn't printed

    # Verify mock state
    assert mock_tool_manager.update_attempts == [tool_to_update]


def test_update_tool_not_installed(mock_tool_manager: MockToolManager) -> None:
    """Test 'sniper tools update <tool_name>' for a tool that is not installed."""
    tool_to_update = "zap"  # Zap is not installed
    assert not mock_tool_manager._installation_status[tool_to_update]

    # Reset update attempts
    mock_tool_manager.update_attempts = []

    result = runner.invoke(app, ["tools", "update", tool_to_update])

    assert result.exit_code == 1  # Command fails if specified tool isn't installed
    output = strip_ansi(result.stdout)
    # Check for the specific warning/error messages
    assert (
        f"The following specified tools are not installed and will be skipped: {tool_to_update}"
        in output
    )
    assert "None of the specified tools are installed or valid." in output
    # Verify update_tool was not called on the manager
    assert mock_tool_manager.update_attempts == []


def test_update_tool_skipped(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test 'sniper tools update <tool_name>' when manager returns None (skipped)."""
    tool_to_update = "nmap"
    assert mock_tool_manager._installation_status[tool_to_update] is True

    # Force the mock update_tool method to return None
    monkeypatch.setattr(
        mock_tool_manager, "update_tool", lambda name, method=None: None
    )
    mock_tool_manager.update_attempts = []

    result = runner.invoke(app, ["tools", "update", tool_to_update])

    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert f"Updating {tool_to_update}..." in output
    assert f"ℹ Update skipped for {tool_to_update}" in output
    assert "Update Summary:" in output
    assert "Skipped/Not applicable: 1" in output
    assert "Successfully updated: 0" in output
    assert "Failed to update: 0" not in output


def test_update_tool_failure(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test 'sniper tools update <tool_name>' when update fails."""
    tool_to_update = "nmap"
    assert mock_tool_manager._installation_status[tool_to_update] is True

    # Force the mock update_tool method to return False
    monkeypatch.setattr(
        mock_tool_manager, "update_tool", lambda name, method=None: False
    )
    mock_tool_manager.update_attempts = []

    result = runner.invoke(app, ["tools", "update", tool_to_update])

    assert result.exit_code == 0  # Command should still exit 0
    output = strip_ansi(result.stdout)
    assert f"Updating {tool_to_update}..." in output
    assert f"! Update failed or was not applicable for {tool_to_update}." in output
    assert "Update Summary:" in output
    assert "Failed to update: 1" in output
    assert "Successfully updated: 0" in output
    assert "Skipped/Not applicable: 0" not in output


# TODO: Add tests for install/update with --all and --category flags


def test_add_tool_command(
    mock_tool_manager: MockToolManager, monkeypatch, tmp_path
) -> None:
    """Test the 'sniper tools add' command with a mock YAML file."""
    # Create a temporary YAML file with the correct structure - tools are defined as a dictionary
    tool_yaml = tmp_path / "test-tool.yaml"
    tool_yaml.write_text(
        """
test-tool:
  name: test-tool
  version: 1.0.0
  description: A test tool for unit testing
  category: vulnerability_scanning
  install_command: apt-get install test-tool
  install_method: apt
  binary_name: test-tool
  detection_args: --version
  run_command: test-tool scan {TARGET}
  run_args:
    - --output={OUTPUT}
  output_parser: json
  url: https://example.com/test-tool
  tags:
    - test
    - unit-test
  requirements:
    - python3
"""
    )

    # Mock the add_tool method in ToolManager
    def mock_add_tool(self, name, config, custom=True):
        # Add to our tracking for verification
        self.install_attempts.append(name)
        # Update internal state for future checks
        self._tools_data[name] = config
        return True

    monkeypatch.setattr(MockToolManager, "add_tool", mock_add_tool)

    # Run the command
    result = runner.invoke(app, ["tools", "add", str(tool_yaml)])

    # Verify the result
    assert result.exit_code == 0
    output = strip_ansi(result.stdout)
    assert "Successfully added custom tool: test-tool" in output
    assert "test-tool" in mock_tool_manager.install_attempts


def test_categories_command(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test the 'sniper tools categories' command."""

    # Extend the mock to include get_tool_categories method
    def mock_get_tool_categories():
        return {
            ToolCategory.RECONNAISSANCE.value,
            ToolCategory.VULNERABILITY_SCANNING.value,
            ToolCategory.EXPLOITATION.value,
            ToolCategory.MISCELLANEOUS.value,
        }

    # Patch the get_tool_categories method
    monkeypatch.setattr(
        mock_tool_manager, "get_tool_categories", mock_get_tool_categories
    )

    # Run the command
    result = runner.invoke(app, ["tools", "categories"])

    # Check exit code
    assert result.exit_code == 0

    # Verify all categories are listed in the output
    output = strip_ansi(result.stdout)
    assert "Available Tool Categories:" in output
    assert ToolCategory.RECONNAISSANCE.value in output
    assert ToolCategory.VULNERABILITY_SCANNING.value in output
    assert ToolCategory.EXPLOITATION.value in output
    assert ToolCategory.MISCELLANEOUS.value in output


def test_remove_tool_command(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test the 'sniper tools remove <tool_name>' command."""
    # Mock the remove_tool method
    remove_calls = []

    def mock_remove_tool(name: str) -> bool:
        remove_calls.append(name)
        # Simulate successful removal
        if name in mock_tool_manager._tools_data:
            del mock_tool_manager._tools_data[name]
            if name in mock_tool_manager._installation_status:
                del mock_tool_manager._installation_status[name]
            return True
        return False

    # Patch the remove_tool method
    monkeypatch.setattr(mock_tool_manager, "remove_tool", mock_remove_tool)

    # Add a test tool to remove
    mock_tool_manager._tools_data["test-custom-tool"] = {
        "name": "test-custom-tool",
        "category": "miscellaneous",
        "description": "A test custom tool",
    }
    mock_tool_manager._installation_status["test-custom-tool"] = True

    # Run the command
    result = runner.invoke(app, ["tools", "remove", "test-custom-tool"])

    # Check exit code
    assert result.exit_code == 0

    # Verify the tool was removed
    assert "test-custom-tool" in remove_calls
    assert "test-custom-tool" not in mock_tool_manager._tools_data
    assert "test-custom-tool" not in mock_tool_manager._installation_status

    # Verify output message
    output = strip_ansi(result.stdout)
    assert "Successfully removed custom tool: test-custom-tool" in output

    # Test attempting to remove a non-existent tool
    nonexistent_tool = "nonexistent-tool"
    remove_calls.clear()  # Reset the calls list

    result = runner.invoke(app, ["tools", "remove", nonexistent_tool])
    # Check that the command was run
    assert nonexistent_tool in remove_calls

    # The implementation may just print a warning rather than error
    # So we'll check both possible outputs
    output = strip_ansi(result.stdout)
    # Check for the actual error message shown in the output
    assert "Failed to remove tool: nonexistent-tool" in output
    assert "Tools failed to remove: 1" in output


def test_check_updates_command(mock_tool_manager: MockToolManager, monkeypatch) -> None:
    """Test the 'sniper tools check-updates' command."""
    # Mock the check_for_updates method
    updates_dict = {
        "nmap": True,  # Has updates
        "zap": False,  # No updates
        "massdns": None,  # Error/Not installed
    }

    def mock_check_for_updates(*args, **kwargs):
        # Accept any arguments but return our predefined dict
        return updates_dict

    # Patch the check_for_updates method
    monkeypatch.setattr(mock_tool_manager, "check_for_updates", mock_check_for_updates)

    # Make sure we have the right tools in the manager
    mock_tool_manager._tools_data = {
        "nmap": {
            "name": "nmap",
            "category": "reconnaissance",
            "description": "Network scanner",
        },
        "zap": {
            "name": "zap",
            "category": "vulnerability_scanning",
            "description": "Web application scanner",
        },
        "massdns": {
            "name": "massdns",
            "category": "reconnaissance",
            "description": "High-performance DNS resolver",
        },
    }

    # Set installation status
    mock_tool_manager._installation_status = {
        "nmap": True,
        "zap": True,
        "massdns": False,
    }

    # Run the command
    result = runner.invoke(app, ["tools", "check-updates"])

    # Check exit code
    assert result.exit_code == 0

    # Verify output - might need adjustments based on actual output format
    output = strip_ansi(result.stdout)
    assert "Checking updates" in output
