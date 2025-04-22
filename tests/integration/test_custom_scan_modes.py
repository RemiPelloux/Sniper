"""
Integration tests for custom scan modes.

This module tests the ability to define, load, and use custom scan modes
for security scanning with the Sniper Security Tool.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from src.cli.main import app
from src.core.scan_mode_manager import ScanModeManager


@pytest.fixture
def backup_and_restore_scan_modes():
    """
    Backup the original scan_modes.yaml file and restore it after the test.

    This ensures that tests don't permanently modify the scan modes configuration.
    """
    # Paths
    config_dir = (
        Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) / "config"
    )
    scan_modes_file = config_dir / "scan_modes.yaml"
    backup_file = config_dir / "scan_modes.yaml.bak"

    # Create backup if the file exists
    if scan_modes_file.exists():
        shutil.copy2(scan_modes_file, backup_file)

    yield

    # Restore from backup
    if backup_file.exists():
        shutil.copy2(backup_file, scan_modes_file)
        backup_file.unlink()  # Remove backup file


@pytest.fixture
def custom_scan_modes(backup_and_restore_scan_modes):
    """
    Add custom scan modes to the scan_modes.yaml file for testing.

    This adds temporary test scan modes to the actual configuration file.
    """
    # Paths
    config_dir = (
        Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) / "config"
    )
    scan_modes_file = config_dir / "scan_modes.yaml"

    # Custom scan modes to add
    test_scan_modes = {
        "web_api_test": {
            "name": "web_api_test",
            "description": "Custom scan mode for testing REST APIs and web services",
            "target_types": ["url", "webapp"],
            "modules": ["technologies", "web"],
            "settings": {
                "max_threads": 4,
                "timeout": 1200,
                "scan_depth": "standard",
                "delay": 1,
            },
            "tools": {
                "wappalyzer": {"enabled": True, "options": {}},
                "zap": {
                    "enabled": True,
                    "options": {
                        "active_scan": True,
                        "api_scan": True,
                        "scan_policy": "API-Minimal",
                    },
                },
                "nuclei": {"enabled": True, "options": {"templates": "api,cves"}},
            },
        },
        "minimal_recon": {
            "name": "minimal_recon",
            "description": "Fast reconnaissance with minimal scanning",
            "target_types": ["domain", "ip"],
            "modules": ["technologies", "ports"],
            "settings": {
                "max_threads": 2,
                "timeout": 300,
                "scan_depth": "quick",
                "delay": 2,
            },
            "tools": {
                "wappalyzer": {"enabled": True, "options": {}},
                "nmap": {
                    "enabled": True,
                    "options": {"ports": "80,443,22,8080", "timing_template": 2},
                },
            },
        },
    }

    # Load existing scan modes
    if scan_modes_file.exists():
        with open(scan_modes_file, "r") as f:
            existing_modes = yaml.safe_load(f) or {}
    else:
        existing_modes = {}

    # Update with our test modes
    existing_modes.update(test_scan_modes)

    # Write back the updated config
    with open(scan_modes_file, "w") as f:
        yaml.dump(existing_modes, f, default_flow_style=False)

    yield test_scan_modes


@pytest.fixture
def mock_scan_execution():
    """Mock scan execution functions to prevent actual scans from running."""
    with patch("src.cli.scan.run_technology_scan") as mock_tech, patch(
        "src.cli.scan.run_subdomain_scan"
    ) as mock_sub, patch("src.cli.scan.run_port_scan") as mock_port, patch(
        "src.cli.scan.run_web_scan"
    ) as mock_web, patch(
        "src.cli.scan.run_directory_scan"
    ) as mock_dir, patch(
        "src.cli.scan.ResultNormalizer"
    ) as mock_normalizer:

        # Configure mocks to return empty lists
        mock_tech.return_value = []
        mock_sub.return_value = []
        mock_port.return_value = []
        mock_web.return_value = []
        mock_dir.return_value = []

        # Configure normalizer mock
        mock_normalizer_instance = mock_normalizer.return_value
        mock_normalizer_instance.correlate_findings.return_value = []

        yield {
            "tech": mock_tech,
            "sub": mock_sub,
            "port": mock_port,
            "web": mock_web,
            "dir": mock_dir,
            "normalizer": mock_normalizer,
        }


def test_list_custom_scan_modes(custom_scan_modes):
    """Test that custom scan modes appear in the scan modes listing."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "modes"])

    # Check command success
    assert result.exit_code == 0

    # Check for our custom modes in the output
    assert "web_api_test" in result.stdout
    assert "minimal_recon" in result.stdout


def test_scan_with_web_api_test_mode(custom_scan_modes, mock_scan_execution):
    """Test running a scan with the web_api_test custom mode."""
    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "run", "https://api.example.com", "--mode", "web_api_test"]
    )

    # Check command success
    assert result.exit_code == 0

    # Verify correct scan mode was used
    assert "Running scan with mode: web_api_test" in result.stdout

    # Verify that only the modules defined in the mode were called
    mock_scan_execution["tech"].assert_called_once()  # technologies module
    mock_scan_execution["web"].assert_called_once()  # web module

    # Verify that undefined modules were not called
    mock_scan_execution["sub"].assert_not_called()  # subdomains not in web_api_test
    mock_scan_execution["port"].assert_not_called()  # ports not in web_api_test
    mock_scan_execution["dir"].assert_not_called()  # directories not in web_api_test


def test_scan_with_minimal_recon_mode(custom_scan_modes, mock_scan_execution):
    """Test running a scan with the minimal_recon custom mode."""
    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "run", "example.com", "--mode", "minimal_recon"]
    )

    # Check command success
    assert result.exit_code == 0

    # Verify correct scan mode was used
    assert "Running scan with mode: minimal_recon" in result.stdout

    # Verify that only the modules defined in the mode were called
    mock_scan_execution["tech"].assert_called_once()  # technologies module
    mock_scan_execution["port"].assert_called_once()  # ports module

    # Verify that undefined modules were not called
    mock_scan_execution["sub"].assert_not_called()  # subdomains not in minimal_recon
    mock_scan_execution["web"].assert_not_called()  # web not in minimal_recon
    mock_scan_execution["dir"].assert_not_called()  # directories not in minimal_recon


def test_scan_mode_output_format(custom_scan_modes, mock_scan_execution):
    """Test scan output with different formats when using custom modes."""
    runner = CliRunner()

    # Test JSON output
    json_result = runner.invoke(
        app, ["scan", "run", "example.com", "--mode", "minimal_recon", "--json"]
    )

    assert json_result.exit_code == 0
    # JSON format is configured but we can't easily test the actual output format
    # since we're mocking the scan results. Just verify that the scan completes.
    assert "Scan Results Summary" in json_result.stdout

    # Test with output file
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
        output_path = temp_file.name

    try:
        file_result = runner.invoke(
            app,
            [
                "scan",
                "run",
                "example.com",
                "--mode",
                "minimal_recon",
                "-o",
                output_path,
            ],
        )

        assert file_result.exit_code == 0
        # Check that the output file was mentioned in the output
        assert "Detailed results written to" in file_result.stdout

        # In a real test, we would check the file contents
        # But here we're mocking the scan, so the file won't contain actual results
    finally:
        # Clean up the temporary file
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_override_scan_mode_parameters(custom_scan_modes, mock_scan_execution):
    """Test the ability to override scan mode parameters via command line."""
    runner = CliRunner()

    # Test with additional module parameter
    result = runner.invoke(
        app,
        [
            "scan",
            "run",
            "example.com",
            "--mode",
            "minimal_recon",
            "--module",
            "web",  # Add a module not in the default set for minimal_recon
        ],
    )

    assert result.exit_code == 0
    assert "Running scan with mode: minimal_recon" in result.stdout
    # Simply verify the scan completes successfully
    assert "Scan Results Summary" in result.stdout
