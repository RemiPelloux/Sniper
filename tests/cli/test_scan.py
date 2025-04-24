"""Unit tests for the scan command."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from src.cli.main import app
from src.core.exceptions import ScanConfigError, ScanExecutionError
from src.core.findings import Finding, Severity


@pytest.fixture
def runner():
    """CLI runner for testing commands."""
    return CliRunner()


@pytest.fixture
def mock_scan_mode_manager():
    """Mock ScanModeManager with test configuration."""
    manager_mock = MagicMock()

    # Define test mode config
    test_config = {
        "name": "test_mode",
        "description": "Test scan mode",
        "target_types": ["url", "webapp"],
        "modules": ["technologies", "web", "directories"],
        "depth": "standard",
        "settings": {"max_threads": 8, "timeout": 3600, "retries": 2},
        "tools": {
            "wappalyzer": {"enabled": True, "options": {}},
            "zap": {
                "enabled": True,
                "options": {"active_scan": True, "ajax_spider": True},
            },
            "dirsearch": {"enabled": True, "options": {}},
        },
    }

    manager_mock.get_scan_mode.return_value = test_config
    manager_mock.get_tools_for_scan_mode.return_value = test_config["tools"]

    return manager_mock


@pytest.fixture
def mock_normalizer():
    """Mock ResultNormalizer."""
    normalizer = MagicMock()
    normalizer.correlate_findings.return_value = [
        Finding(
            title="Test Finding",
            description="Test Description",
            severity=Severity.MEDIUM,
            confidence=90,
            target="http://test.com",
            tool="test_tool",
        )
    ]
    return normalizer


@patch("src.cli.scan.validate_target_url", return_value="http://test.com")
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_basic(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class,
    mock_validate_target,
    mock_scan_mode_manager,
    mock_normalizer,
    runner,
):
    """Test basic scan command execution."""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    mock_normalizer_class.return_value = mock_normalizer

    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available"),
    }

    # Run command
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, patch(
        "src.cli.scan.run_web_scan"
    ) as mock_web_scan, patch(
        "src.cli.scan.run_directory_scan"
    ) as mock_dir_scan, patch(
        "src.cli.scan.asyncio.run"
    ) as mock_asyncio_run:

        # Mock scan functions
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.return_value = {"http://test.com": []}

        result = runner.invoke(
            app, ["scan", "run", "http://test.com", "--depth", "standard"]
        )

    # Assertions
    assert result.exit_code == 0
    assert "Scan Results Summary" in result.output


@patch("src.cli.scan.validate_target_url", return_value="http://test.com")
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_with_output(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class,
    mock_validate_target,
    mock_scan_mode_manager,
    mock_normalizer,
    runner,
    tmp_path,
):
    """Test scan command with output file."""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    mock_normalizer_class.return_value = mock_normalizer

    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available"),
    }

    # Create temporary output file
    output_file = tmp_path / "test_results.json"

    # Run command
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, patch(
        "src.cli.scan.run_web_scan"
    ) as mock_web_scan, patch(
        "src.cli.scan.run_directory_scan"
    ) as mock_dir_scan, patch(
        "src.cli.scan.asyncio.run"
    ) as mock_asyncio_run:

        # Mock scan functions
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.return_value = {"http://test.com": []}

        result = runner.invoke(
            app,
            ["scan", "run", "http://test.com", "--output", str(output_file), "--json"],
        )

    # Assertions
    assert result.exit_code == 0
    assert output_file.exists()
    assert "Detailed results written to" in result.output


@patch("src.cli.scan.validate_target_url", return_value="http://test.com")
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_with_unavailable_tools(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class,
    mock_validate_target,
    mock_scan_mode_manager,
    mock_normalizer,
    runner,
):
    """Test scan command when some tools are unavailable."""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    mock_normalizer_class.return_value = mock_normalizer

    # Mock tool availability - some tools missing
    mock_check_tools.return_value = {
        "wappalyzer": (False, "Wappalyzer not found"),
        "zap": (False, "ZAP not found"),
        "dirsearch": (True, "Dirsearch is available"),
    }

    # Run command
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, patch(
        "src.cli.scan.run_web_scan"
    ) as mock_web_scan, patch(
        "src.cli.scan.run_directory_scan"
    ) as mock_dir_scan, patch(
        "src.cli.scan.asyncio.run"
    ) as mock_asyncio_run:

        # Mock scan functions
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.return_value = {"http://test.com": []}

        result = runner.invoke(app, ["scan", "run", "http://test.com"])

    # Assertions
    assert result.exit_code == 0
    assert "some tools are not available" in result.output.lower()
    assert "wappalyzer" in result.output.lower()
    assert "zap" in result.output.lower()
