import os
import sys
import tempfile
import shutil
import pytest
import yaml
from pathlib import Path

# Ensure src is in path
src_path = Path(__file__).parent.parent.parent / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

@pytest.fixture
def temp_tool_dir():
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
def temp_custom_dir():
    """Create a temporary directory for custom tools."""
    temp_dir = tempfile.mkdtemp()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)

# Add specific fixtures for tools tests here

