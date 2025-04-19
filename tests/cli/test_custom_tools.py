import json
import os
import sys  # Import sys
from pathlib import Path  # Import Path
from typing import Optional  # Added Optional
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

# Ensure project root is in path for src/app imports
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Import the main app instance where custom-tools is registered
from src.cli.main import app

# Import the ToolManager and categories for mocking
from src.tools.manager import ToolCategory, ToolManager


@pytest.fixture
def runner():
    """Provides a CliRunner instance."""
    return CliRunner()


# Mock ToolManager data relevant to custom tools list
class MockCustomToolManager:
    def __init__(self):
        self._tools_data = {
            "nmap": {
                "name": "nmap",
                "category": ToolCategory.RECONNAISSANCE.value,
                "description": "Network exploration tool.",
            },
            "mytool": {
                "name": "mytool",
                "category": ToolCategory.MISCELLANEOUS.value,
                "description": "A custom tool added by user.",
            },
        }
        self._installation_status = {
            "nmap": True,
            "mytool": False,
        }
        # Simulate custom tools directory path relative to project root
        # Assuming parent_dir calculation in custom_tools.py works
        project_root = Path(__file__).resolve().parent.parent.parent
        self.custom_tools_dir = project_root / "config" / "custom_tools"

    def get_all_tools(self):
        return self._tools_data

    def get_installation_status(self):
        return self._installation_status

    def get_tool(self, name: str):
        return self._tools_data.get(name)

    def check_tool_availability(self, name: str):
        return self._installation_status.get(name, False)

    def get_tools_by_category(self, category: ToolCategory):
        cat_value = category.value
        return {
            name: data
            for name, data in self._tools_data.items()
            if data.get("category") == cat_value
        }

    def get_available_tools(self, category: Optional[str] = None):
        # Simplified mock for available tools
        available = {
            name: data
            for name, data in self._tools_data.items()
            if self._installation_status.get(name)
        }
        if category:
            try:
                ToolCategory(category)  # Validate
                return {
                    name: data
                    for name, data in available.items()
                    if data.get("category") == category
                }
            except ValueError:
                return {}
        return available

    # Add mock methods for add/remove if testing those commands
    def add_tool(self, name: str, config: dict, custom: bool = True):
        # Mock adding logic (e.g., check if exists, save to mock filesystem)
        return True

    def remove_tool(self, name: str):
        # Mock removing logic
        return True

    def get_tool_categories(self) -> set:
        return {data.get("category", "unknown") for data in self._tools_data.values()}


@pytest.fixture
def mock_custom_tool_manager(monkeypatch):
    """Fixture to replace ToolManager specifically for custom tool tests."""
    mock_manager = MockCustomToolManager()
    # Patch the ToolManager where it's instantiated in src/cli/custom_tools.py
    monkeypatch.setattr("src.cli.custom_tools.ToolManager", lambda: mock_manager)

    # Mock Path.glob in custom_tools.py to simulate finding custom tool files
    # This requires knowing the exact path calculated in the module
    # Assume parent_dir calculation leads to project_root/config/custom_tools
    project_root = Path(__file__).resolve().parent.parent.parent
    expected_glob_path = project_root / "config" / "custom_tools"

    # Accept 'self' as the first argument because glob is an instance method
    def mock_glob(self, pattern):
        # Only return mock files if the path matches where custom_tools looks
        # print(f"Mock glob called with self={self}, pattern={pattern}") # Debug print
        # Use a simple check: if the Path instance being globbed is the expected one
        if self == expected_glob_path and pattern == "*.yaml":
            # Return Path objects with stems matching our mock custom tools
            mock_mytool_path = MagicMock(spec=Path)
            mock_mytool_path.stem = "mytool"
            return [mock_mytool_path]
        else:
            return []  # Return empty list for other paths/patterns

    # Patch Path.glob directly - might affect other tests if not careful
    # A more targeted patch on the specific Path instance used would be better but harder
    monkeypatch.setattr("pathlib.Path.glob", mock_glob)
    # Alternatively patch os.listdir if that was used
    # monkeypatch.setattr("os.listdir", lambda path: ["mytool.yaml"] if "custom_tools" in str(path) else [])

    return mock_manager


# Helper to strip ANSI codes
import re


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


# --- Test Cases ---


def test_list_custom_tools_table(runner, mock_custom_tool_manager):
    """Test the 'custom-tools list' command table output."""
    result = runner.invoke(app, ["custom-tools", "list"])
    output = strip_ansi(result.stdout)

    print(f"\nList Output:\n{result.stdout}")  # Print for debugging
    assert result.exit_code == 0

    # Check headers
    assert "Name" in output
    assert "Category" in output
    assert "Description" in output
    assert "Type" in output
    assert "Status" in output

    # Check nmap (standard tool)
    assert "nmap" in output
    assert "reconnaissance" in output
    # Find the line containing nmap and check it doesn't have the custom marker
    nmap_line = next((line for line in output.splitlines() if "nmap" in line), None)
    assert nmap_line is not None, "Nmap line not found in output"
    assert "✓ Custom" not in nmap_line
    assert "Available" in nmap_line  # Check status on the correct line

    # Check mytool (custom tool)
    assert "mytool" in output
    assert "miscellaneous" in output
    # Find the line containing mytool and check it has the custom marker
    mytool_line = next((line for line in output.splitlines() if "mytool" in line), None)
    assert mytool_line is not None, "Mytool line not found in output"
    assert "✓ Custom" in mytool_line  # Should be marked custom
    assert "Unavailable" in mytool_line  # Check status on the correct line

    assert "Total tools listed: 2" in output
    assert "Custom tools: 1" in output


def test_list_custom_tools_json(runner, mock_custom_tool_manager):
    """Test the 'custom-tools list --json' command."""
    result = runner.invoke(app, ["custom-tools", "list", "--json"])
    assert result.exit_code == 0
    try:
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 2

        nmap_data = next((item for item in data if item["name"] == "nmap"), None)
        assert nmap_data is not None
        assert nmap_data["is_custom"] is False
        assert nmap_data["is_available"] is True

        mytool_data = next((item for item in data if item["name"] == "mytool"), None)
        assert mytool_data is not None
        assert mytool_data["is_custom"] is True
        assert mytool_data["is_available"] is False

    except json.JSONDecodeError:
        pytest.fail(f"Output was not valid JSON: {result.stdout}")


# TODO: Add tests for list filters (--category, --available)
# TODO: Add tests for 'add', 'remove', 'import' commands
