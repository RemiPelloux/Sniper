"""Tests for the scan orchestration CLI module."""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from src.cli.scan import app, ScanDepth, ScanModule


runner = CliRunner()


def test_scan_help():
    """Test the help output for the scan command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "help" in result.stdout


def test_run_scan_missing_target():
    """Test that run-scan requires a target argument."""
    result = runner.invoke(app, ["run"])
    assert result.exit_code != 0
    assert result.exit_code == 2


def test_scan_depth_enum():
    """Test that ScanDepth enum has the expected values."""
    assert ScanDepth.QUICK.value == "quick"
    assert ScanDepth.STANDARD.value == "standard"
    assert ScanDepth.COMPREHENSIVE.value == "comprehensive"


def test_scan_module_enum():
    """Test that ScanModule enum has the expected values."""
    assert ScanModule.PORTS.value == "ports"
    assert ScanModule.WEB.value == "web"
    assert ScanModule.SUBDOMAINS.value == "subdomains"
    assert ScanModule.TECHNOLOGIES.value == "technologies"
    assert ScanModule.DIRECTORIES.value == "directories"
    assert ScanModule.ALL.value == "all"


@patch("src.cli.scan.ResultNormalizer")
@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.run_technology_scan")
@patch("src.cli.scan.run_subdomain_scan")
@patch("src.cli.scan.run_port_scan")
@patch("src.cli.scan.run_web_scan")
@patch("src.cli.scan.run_directory_scan")
@patch("src.cli.scan.ResultNormalizer")
def test_run_scan_all_modules(
    mock_normalizer, 
    mock_dir_scan, 
    mock_web_scan, 
    mock_port_scan, 
    mock_subdomain_scan, 
    mock_tech_scan,
    mock_validate
):
    """Test that run-scan with default modules calls all scan functions."""
    # Skip actual runner invoke and directly call the function
    from src.cli.scan import run_scan, ScanModule
    
    # Configure mocks
    normalizer_instance = MagicMock()
    mock_normalizer.return_value = normalizer_instance
    normalizer_instance.normalize_findings.return_value = []
    normalizer_instance.deduplicate_findings.return_value = []
    normalizer_instance.correlate_findings.return_value = {}
    
    mock_tech_scan.return_value = []
    mock_subdomain_scan.return_value = []
    mock_port_scan.return_value = []
    mock_web_scan.return_value = []
    mock_dir_scan.return_value = []
    
    # Call the function directly
    run_scan(
        target="https://example.com",
        modules=[ScanModule.ALL],
    )
    
    # Verify all scan functions were called
    mock_tech_scan.assert_called_once()
    mock_subdomain_scan.assert_called_once()
    mock_port_scan.assert_called_once()
    mock_web_scan.assert_called_once()
    mock_dir_scan.assert_called_once()
    
    # Verify normalizer was used
    normalizer_instance.normalize_findings.assert_called_once()
    normalizer_instance.deduplicate_findings.assert_called_once()
    normalizer_instance.correlate_findings.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.run_port_scan")
@patch("src.cli.scan.ResultNormalizer")
def test_run_scan_specific_module(mock_normalizer, mock_port_scan, mock_validate):
    """Test that run-scan with specific module only calls that function."""
    # Skip actual runner invoke and directly call the function
    from src.cli.scan import run_scan, ScanModule
    
    # Configure mocks
    normalizer_instance = MagicMock()
    mock_normalizer.return_value = normalizer_instance
    normalizer_instance.normalize_findings.return_value = []
    normalizer_instance.deduplicate_findings.return_value = []
    normalizer_instance.correlate_findings.return_value = {}
    
    mock_port_scan.return_value = []
    
    # Call the function directly with only ports module
    run_scan(
        target="https://example.com",
        modules=[ScanModule.PORTS],
    )
    
    # Verify only port scan was called
    mock_port_scan.assert_called_once()
    
    # Verify normalizer was used
    normalizer_instance.normalize_findings.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.run_port_scan")
def test_run_scan_with_depth(mock_port_scan, mock_validate):
    """Test that run-scan passes depth parameter to scan functions."""
    # Skip actual runner invoke and directly call the function
    from src.cli.scan import run_scan, ScanModule, ScanDepth
    
    mock_port_scan.return_value = []
    
    # Call the function directly with comprehensive depth
    run_scan(
        target="https://example.com",
        modules=[ScanModule.PORTS],
        depth=ScanDepth.COMPREHENSIVE,
    )
    
    # Verify port scan was called with the depth parameter
    mock_port_scan.assert_called_once()
    args, kwargs = mock_port_scan.call_args
    assert args[0] == "https://example.com"
    assert args[1] == ScanDepth.COMPREHENSIVE 