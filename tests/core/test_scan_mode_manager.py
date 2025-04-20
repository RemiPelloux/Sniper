"""
Unit tests for the Scan Mode Manager class.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

import yaml

from src.core.scan_mode_manager import ScanModeManager


class TestScanModeManager(unittest.TestCase):
    """Test case for the ScanModeManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary test file with sample scan modes
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.temp_dir.name, "test_scan_modes.yaml")
        
        # Sample scan modes for testing
        self.test_scan_modes = {
            "test_quick": {
                "name": "test_quick",
                "description": "Test quick scan mode",
                "target_types": ["domain", "url"],
                "modules": ["technologies", "ports"],
                "settings": {
                    "max_threads": 5,
                    "timeout": 600,
                    "scan_depth": "quick"
                },
                "tools": {
                    "nmap": {
                        "enabled": True,
                        "options": {"ports": "80,443"}
                    }
                }
            },
            "test_comprehensive": {
                "name": "test_comprehensive",
                "description": "Test comprehensive scan mode",
                "target_types": ["domain", "url", "ip"],
                "modules": ["technologies", "subdomains", "ports", "web", "directories"],
                "settings": {
                    "max_threads": 15,
                    "timeout": 7200,
                    "scan_depth": "comprehensive"
                },
                "tools": {
                    "nmap": {
                        "enabled": True,
                        "options": {"ports": "1-65535"}
                    },
                    "zap": {
                        "enabled": True,
                        "options": {"active_scan": True}
                    }
                }
            }
        }
        
        # Write the test data to the temporary file
        with open(self.test_file_path, "w") as file:
            yaml.dump(self.test_scan_modes, file)
    
    def tearDown(self):
        """Tear down test fixtures."""
        self.temp_dir.cleanup()
    
    def test_load_scan_modes(self):
        """Test loading scan modes from a YAML file."""
        manager = ScanModeManager(self.test_file_path)
        
        # Verify scan modes were loaded
        self.assertEqual(len(manager.scan_modes), 2)
        self.assertIn("test_quick", manager.scan_modes)
        self.assertIn("test_comprehensive", manager.scan_modes)
        
        # Verify contents of loaded scan modes
        quick_mode = manager.scan_modes["test_quick"]
        self.assertEqual(quick_mode["description"], "Test quick scan mode")
        self.assertEqual(quick_mode["settings"]["max_threads"], 5)
        
        comprehensive_mode = manager.scan_modes["test_comprehensive"]
        self.assertEqual(comprehensive_mode["settings"]["scan_depth"], "comprehensive")
        self.assertTrue(comprehensive_mode["tools"]["zap"]["enabled"])
    
    def test_get_scan_mode(self):
        """Test retrieving a specific scan mode by name."""
        manager = ScanModeManager(self.test_file_path)
        
        # Verify retrieving an existing mode
        quick_mode = manager.get_scan_mode("test_quick")
        self.assertIsNotNone(quick_mode)
        self.assertEqual(quick_mode["description"], "Test quick scan mode")
        
        # Verify retrieving a non-existent mode
        nonexistent_mode = manager.get_scan_mode("nonexistent")
        self.assertIsNone(nonexistent_mode)
    
    def test_get_scan_mode_names(self):
        """Test retrieving list of scan mode names."""
        manager = ScanModeManager(self.test_file_path)
        
        mode_names = manager.get_scan_mode_names()
        self.assertEqual(len(mode_names), 2)
        self.assertIn("test_quick", mode_names)
        self.assertIn("test_comprehensive", mode_names)
    
    def test_get_scan_mode_by_target_type(self):
        """Test filtering scan modes by target type."""
        manager = ScanModeManager(self.test_file_path)
        
        # Both modes support URL target type
        url_modes = manager.get_scan_mode_by_target_type("url")
        self.assertEqual(len(url_modes), 2)
        
        # Only comprehensive mode supports IP target type
        ip_modes = manager.get_scan_mode_by_target_type("ip")
        self.assertEqual(len(ip_modes), 1)
        self.assertIn("test_comprehensive", ip_modes)
        
        # No modes support network target type
        network_modes = manager.get_scan_mode_by_target_type("network")
        self.assertEqual(len(network_modes), 0)
    
    def test_get_modules_for_scan_mode(self):
        """Test retrieving modules for a specific scan mode."""
        manager = ScanModeManager(self.test_file_path)
        
        # Verify modules for quick mode
        quick_modules = manager.get_modules_for_scan_mode("test_quick")
        self.assertEqual(len(quick_modules), 2)
        self.assertIn("technologies", quick_modules)
        self.assertIn("ports", quick_modules)
        
        # Verify modules for comprehensive mode
        comprehensive_modules = manager.get_modules_for_scan_mode("test_comprehensive")
        self.assertEqual(len(comprehensive_modules), 5)
        
        # Verify modules for non-existent mode
        nonexistent_modules = manager.get_modules_for_scan_mode("nonexistent")
        self.assertEqual(len(nonexistent_modules), 0)
    
    def test_get_tools_for_scan_mode(self):
        """Test retrieving tools configuration for a specific scan mode."""
        manager = ScanModeManager(self.test_file_path)
        
        # Verify tools for quick mode
        quick_tools = manager.get_tools_for_scan_mode("test_quick")
        self.assertEqual(len(quick_tools), 1)
        self.assertIn("nmap", quick_tools)
        self.assertEqual(quick_tools["nmap"]["options"]["ports"], "80,443")
        
        # Verify tools for comprehensive mode
        comprehensive_tools = manager.get_tools_for_scan_mode("test_comprehensive")
        self.assertEqual(len(comprehensive_tools), 2)
        self.assertIn("nmap", comprehensive_tools)
        self.assertIn("zap", comprehensive_tools)
        
        # Verify tools for non-existent mode
        nonexistent_tools = manager.get_tools_for_scan_mode("nonexistent")
        self.assertEqual(len(nonexistent_tools), 0)
    
    def test_get_settings_for_scan_mode(self):
        """Test retrieving settings for a specific scan mode."""
        manager = ScanModeManager(self.test_file_path)
        
        # Verify settings for quick mode
        quick_settings = manager.get_settings_for_scan_mode("test_quick")
        self.assertEqual(quick_settings["max_threads"], 5)
        self.assertEqual(quick_settings["timeout"], 600)
        self.assertEqual(quick_settings["scan_depth"], "quick")
        
        # Verify settings for comprehensive mode
        comprehensive_settings = manager.get_settings_for_scan_mode("test_comprehensive")
        self.assertEqual(comprehensive_settings["max_threads"], 15)
        self.assertEqual(comprehensive_settings["timeout"], 7200)
        
        # Verify settings for non-existent mode
        nonexistent_settings = manager.get_settings_for_scan_mode("nonexistent")
        self.assertEqual(len(nonexistent_settings), 0)
    
    def test_nonexistent_file(self):
        """Test graceful handling of non-existent config file."""
        with patch("logging.Logger.warning") as mock_warning:
            manager = ScanModeManager("/nonexistent/path/to/config.yaml")
            # Verify logger was called with a warning
            mock_warning.assert_called_once()
            # Verify scan_modes is empty
            self.assertEqual(len(manager.scan_modes), 0)
    
    def test_empty_file(self):
        """Test graceful handling of empty config file."""
        # Create empty file
        empty_file_path = os.path.join(self.temp_dir.name, "empty.yaml")
        with open(empty_file_path, "w") as file:
            file.write("")
        
        with patch("logging.Logger.warning") as mock_warning:
            manager = ScanModeManager(empty_file_path)
            # Verify logger was called with a warning
            mock_warning.assert_called_once()
            # Verify scan_modes is empty
            self.assertEqual(len(manager.scan_modes), 0) 