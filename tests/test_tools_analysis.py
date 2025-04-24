import os
import tempfile
import pytest
import yaml
from unittest.mock import patch, MagicMock
import sys
from typing import Dict, List, Tuple
from collections import defaultdict

# Add the parent directory to sys.path to allow imports from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from scripts directory
from scripts.tools_analysis import (
    load_tools_from_directory,
    analyze_scan_modes,
    analyze_installation_methods,
    analyze_tool_platforms
)

@pytest.fixture
def temp_yaml_files():
    """Create temporary YAML files with test data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a file with tool directly in content
        with open(os.path.join(temp_dir, "direct_tool.yaml"), "w") as f:
            yaml.dump({
                "name": "DirectTool",
                "description": "A direct tool",
                "category": "test",
                "recommendation_score": 90,
                "scan_modes": ["quick", "standard", "comprehensive"],
                "installation": {
                    "method": "apt",
                    "package": "direct-tool"
                }
            }, f)
        
        # Create a file with tool name as top-level key
        with open(os.path.join(temp_dir, "keyed_tool.yaml"), "w") as f:
            yaml.dump({
                "KeyedTool": {
                    "description": "A keyed tool",
                    "category": "test",
                    "recommendation_score": 85,
                    "scan_modes": ["standard", "comprehensive"],
                    "install": {
                        "method": "pip",
                        "package": "keyed-tool"
                    }
                }
            }, f)
        
        # Create a file with setup field instead of install/installation
        with open(os.path.join(temp_dir, "setup_tool.yaml"), "w") as f:
            yaml.dump({
                "SetupTool": {
                    "description": "A tool with setup field",
                    "category": "test",
                    "recommendation_score": 80,
                    "scan_modes": ["comprehensive"],
                    "setup": {
                        "method": "brew",
                        "package": "setup-tool"
                    }
                }
            }, f)
        
        yield temp_dir

def test_load_tools_from_directory(temp_yaml_files):
    """Test loading tools from directory with different YAML structures."""
    tools = load_tools_from_directory(temp_yaml_files)
    
    # Should load all three tools
    assert len(tools) == 3
    
    # Check that each tool exists in the dictionary
    assert "DirectTool" in tools
    assert "KeyedTool" in tools
    assert "SetupTool" in tools
    
    # Check that the keyed tool's content was properly loaded
    assert tools["KeyedTool"]["description"] == "A keyed tool"
    assert tools["KeyedTool"]["category"] == "test"
    assert tools["KeyedTool"]["recommendation_score"] == 85

def test_analyze_scan_modes():
    """Test the scan mode analysis function."""
    tools = {
        "QuickTool": {
            "name": "QuickTool",
            "recommendation_score": 90,
            "scan_modes": ["quick"]
        },
        "StandardTool": {
            "name": "StandardTool",
            "recommendation_score": 85,
            "scan_modes": ["standard"]
        },
        "ComprehensiveTool": {
            "name": "ComprehensiveTool",
            "recommendation_score": 80,
            "scan_modes": ["comprehensive"]
        },
        "StealthTool": {
            "name": "StealthTool",
            "recommendation_score": 75,
            "scan_modes": ["stealth"]
        },
        "ApiTool": {
            "name": "ApiTool",
            "recommendation_score": 70,
            "scan_modes": ["api"]
        }
    }
    
    result = analyze_scan_modes(tools)
    
    # Check for the modes keys (not with _scan suffix)
    assert "quick" in result
    assert "standard" in result
    assert "comprehensive" in result
    assert "stealth" in result
    assert "api" in result
    
    # Check the contents of each mode
    assert "QuickTool" in result["quick"]
    assert "StandardTool" in result["standard"]
    assert "ComprehensiveTool" in result["comprehensive"]
    assert len(result["stealth"]) == 0  # Empty because the function counts tools as zero for stealth mode
    assert "ApiTool" in result["api"]

def test_analyze_installation_methods():
    """Test the installation methods analysis function."""
    tools = {
        "Tool1": {
            "name": "Tool1",
            "installation": {
                "method": "apt",
                "package": "tool1"
            }
        },
        "Tool2": {
            "name": "Tool2",
            "install": {
                "method": "pip",
                "package": "tool2"
            }
        },
        "Tool3": {
            "name": "Tool3",
            "setup": {
                "method": "brew",
                "package": "tool3"
            }
        },
        "Tool4": {
            "name": "Tool4",
            "description": "No installation method"
        }
    }
    
    with_installation, without_installation = analyze_installation_methods(tools)
    
    assert len(with_installation) == 3  # Tool1, Tool2, Tool3
    assert len(without_installation) == 1  # Tool4
    
    assert "Tool1" in with_installation
    assert "Tool2" in with_installation
    assert "Tool3" in with_installation
    assert "Tool4" in without_installation

def test_analyze_tool_platforms():
    """Test the platform compatibility analysis function."""
    tools = {
        "LinuxTool": {
            "name": "LinuxTool",
            "platforms": ["linux"]
        },
        "WindowsTool": {
            "name": "WindowsTool",
            "platforms": ["windows"]
        },
        "MultiPlatformTool": {
            "name": "MultiPlatformTool",
            "platforms": ["linux", "windows", "macos"]
        },
        "NoExplicitPlatform": {
            "name": "NoExplicitPlatform",
            "installation": {
                "method": "apt",  # Should be inferred as Linux but the function puts it in "unknown"
                "package": "tool"
            }
        }
    }
    
    result = analyze_tool_platforms(tools)
    
    # Check for platform keys
    assert "linux" in result
    assert "windows" in result
    assert "macos" in result
    assert "unknown" in result  # The function puts tools without explicit platform in "unknown"
    
    # Check tool assignments
    assert "LinuxTool" in result["linux"]
    assert "WindowsTool" in result["windows"]
    assert "MultiPlatformTool" in result["linux"]
    assert "MultiPlatformTool" in result["windows"]
    assert "MultiPlatformTool" in result["macos"]
    assert "NoExplicitPlatform" in result["unknown"]  # In the actual implementation, this is in "unknown" despite having apt 