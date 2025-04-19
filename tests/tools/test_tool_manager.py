import os
import shutil
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import yaml

# Add the src directory to the Python path
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from tools.manager import ToolCategory, ToolInstallMethod, ToolManager


class TestToolManager:
    @pytest.fixture
    def temp_tool_dir(self):
        """Create a temporary directory with tool configuration files for testing."""
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        try:
            # Create sample tool files
            tools = {
                "nmap": {
                    "name": "nmap",
                    "description": "Network mapper utility for network discovery and security auditing",
                    "category": "reconnaissance",
                    "installation": {"method": "apt", "package": "nmap"},
                    "command_format": "nmap {options} {target}",
                    "default_options": "-sV -sC -p-",
                },
                "sqlmap": {
                    "name": "sqlmap",
                    "description": "Automatic SQL injection and database takeover tool",
                    "category": "exploitation",
                    "installation": {"method": "apt", "package": "sqlmap"},
                    "command_format": "sqlmap {options} -u {target}",
                    "default_options": "--batch --random-agent",
                },
            }

            # Create individual tool files
            for tool_name, tool_config in tools.items():
                file_path = os.path.join(temp_dir, f"{tool_name}.yaml")
                with open(file_path, "w") as f:
                    yaml.dump({tool_name: tool_config}, f, default_flow_style=False)

            yield temp_dir
        finally:
            # Clean up
            shutil.rmtree(temp_dir)

    @pytest.fixture
    def temp_custom_dir(self):
        """Create a temporary directory for custom tools."""
        temp_dir = tempfile.mkdtemp()
        try:
            yield temp_dir
        finally:
            shutil.rmtree(temp_dir)

    @patch("platform.system")
    @patch("shutil.which")
    def test_tool_manager_initialization(
        self, mock_which, mock_system, temp_tool_dir, temp_custom_dir
    ):
        """Test that the ToolManager initializes correctly and loads tools from individual files."""
        # Mock platform.system to return 'Linux'
        mock_system.return_value = "Linux"

        # Mock shutil.which to indicate apt and pip are available
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/" + cmd if cmd in ["apt", "pip"] else None
        )

        # Initialize the ToolManager with our temporary directories
        manager = ToolManager(tools_dir=temp_tool_dir, custom_tools_dir=temp_custom_dir)

        # Verify that tools were loaded
        assert len(manager.tools) == 2
        assert "nmap" in manager.tools
        assert "sqlmap" in manager.tools

        # Verify tool properties
        nmap = manager.get_tool("nmap")
        assert nmap is not None
        assert nmap["category"] == "reconnaissance"
        assert nmap["installation"]["method"] == "apt"

        sqlmap = manager.get_tool("sqlmap")
        assert sqlmap is not None
        assert sqlmap["category"] == "exploitation"

    @patch("platform.system")
    @patch("shutil.which")
    def test_add_custom_tool(
        self, mock_which, mock_system, temp_tool_dir, temp_custom_dir
    ):
        """Test adding a custom tool and saving it to a file."""
        # Mock platform.system to return 'Linux'
        mock_system.return_value = "Linux"

        # Mock shutil.which to indicate apt and pip are available
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/" + cmd if cmd in ["apt", "pip"] else None
        )

        # Initialize the ToolManager with our temporary directories
        manager = ToolManager(tools_dir=temp_tool_dir, custom_tools_dir=temp_custom_dir)

        # Add a custom tool
        custom_tool = {
            "name": "custom_tool",
            "description": "A custom security tool",
            "category": "vulnerability_scanning",
            "installation": {"method": "pip", "package": "custom-security-tool"},
            "command_format": "custom-tool {options} {target}",
            "default_options": "--scan",
        }

        manager.add_tool("custom_tool", custom_tool)

        # Verify the tool was added to the manager
        assert "custom_tool" in manager.tools

        # Verify the tool was saved to a file in the custom tools directory
        custom_tool_file = os.path.join(temp_custom_dir, "custom_tool.yaml")
        assert os.path.exists(custom_tool_file)

        # Verify the file content
        with open(custom_tool_file, "r") as f:
            saved_tool = yaml.safe_load(f)

        assert "custom_tool" in saved_tool
        assert saved_tool["custom_tool"]["description"] == "A custom security tool"

    @patch("platform.system")
    @patch("shutil.which")
    def test_get_tools_by_category(
        self, mock_which, mock_system, temp_tool_dir, temp_custom_dir
    ):
        """Test getting tools by category."""
        # Mock platform.system to return 'Linux'
        mock_system.return_value = "Linux"

        # Mock shutil.which to indicate apt and pip are available
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/" + cmd if cmd in ["apt", "pip"] else None
        )

        # Initialize the ToolManager with our temporary directories
        manager = ToolManager(tools_dir=temp_tool_dir, custom_tools_dir=temp_custom_dir)

        # Test getting reconnaissance tools
        recon_tools = manager.get_tools_by_category(ToolCategory.RECONNAISSANCE)
        assert len(recon_tools) == 1
        assert "nmap" in recon_tools

        # Test getting exploitation tools
        exploit_tools = manager.get_tools_by_category(ToolCategory.EXPLOITATION)
        assert len(exploit_tools) == 1
        assert "sqlmap" in exploit_tools

        # Test getting vulnerability scanning tools (should be empty)
        vuln_tools = manager.get_tools_by_category(ToolCategory.VULNERABILITY_SCANNING)
        assert len(vuln_tools) == 0

    @patch("platform.system")
    @patch("shutil.which")
    def test_remove_tool(self, mock_which, mock_system, temp_tool_dir, temp_custom_dir):
        """Test removing a tool."""
        # Mock platform.system to return 'Linux'
        mock_system.return_value = "Linux"

        # Mock shutil.which to indicate apt and pip are available
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/" + cmd if cmd in ["apt", "pip"] else None
        )

        # Initialize the ToolManager with our temporary directories
        manager = ToolManager(tools_dir=temp_tool_dir, custom_tools_dir=temp_custom_dir)

        # Add a custom tool
        custom_tool = {
            "name": "custom_tool",
            "description": "A custom security tool",
            "category": "vulnerability_scanning",
            "installation": {"method": "pip", "package": "custom-security-tool"},
            "command_format": "custom-tool {options} {target}",
            "default_options": "--scan",
        }

        manager.add_tool("custom_tool", custom_tool)
        assert "custom_tool" in manager.tools

        # Remove the custom tool
        manager.remove_tool("custom_tool")

        # Verify the tool was removed
        assert "custom_tool" not in manager.tools

        # Verify the file was also removed
        custom_tool_file = os.path.join(temp_custom_dir, "custom_tool.yaml")
        assert not os.path.exists(custom_tool_file)
