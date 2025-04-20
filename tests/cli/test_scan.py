"""Tests for the scan orchestration CLI module."""

import asyncio
import os
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from src.cli.scan import (
    ScanDepth,
    ScanModule,
    app,
    configure_scan_parameters,
    resolve_scan_modules,
)
from src.integrations.wappalyzer import WappalyzerIntegration
from src.results.normalizer import ResultNormalizer

runner = CliRunner()


def test_scan_help():
    """Test the help output for the scan command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "help" in result.stdout


def test_run_scan_missing_target():
    """Test that run-scan requires a target argument."""
    result = runner.invoke(app)
    assert result.exit_code != 0
    assert result.exit_code == 2  # For Typer CLI, it's exit code 2 for parameter issues


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


def test_configure_scan_parameters():
    """Test that configure_scan_parameters sets the correct values."""
    # This is mostly for coverage as the function currently just logs
    configure_scan_parameters(ScanDepth.COMPREHENSIVE, 10, 7200)
    # No assertions since the function just logs currently


def test_resolve_scan_modules_all():
    """Test that resolve_scan_modules works with the ALL module."""
    modules = resolve_scan_modules([ScanModule.ALL])
    # Should include all modules except ALL
    assert ScanModule.PORTS.value in modules
    assert ScanModule.WEB.value in modules
    assert ScanModule.SUBDOMAINS.value in modules
    assert ScanModule.TECHNOLOGIES.value in modules
    assert ScanModule.DIRECTORIES.value in modules
    assert ScanModule.ALL.value not in modules
    assert len(modules) == 5  # There should be 5 modules


def test_resolve_scan_modules_specific():
    """Test that resolve_scan_modules works with specific modules."""
    modules = resolve_scan_modules([ScanModule.PORTS, ScanModule.WEB])
    assert len(modules) == 2
    assert ScanModule.PORTS.value in modules
    assert ScanModule.WEB.value in modules
    assert ScanModule.ALL.value not in modules


@patch("src.cli.scan.WappalyzerIntegration")
def test_technology_scan_function(mock_wappalyzer_class):
    """Test the technology scan function wrapper."""
    target = "https://example.com"
    ignore_ssl = False

    # Create a properly mocked integration object
    mock_instance = MagicMock()
    # The run method needs to be an AsyncMock to be awaitable
    mock_instance.run = AsyncMock()
    mock_instance.run.return_value = MagicMock()
    mock_instance.parse_output.return_value = []

    # Make the constructor return our mocked instance
    mock_wappalyzer_class.return_value = mock_instance

    # Call the function (wrap in asyncio.run since it's async)
    from src.cli.scan import run_technology_scan

    result = asyncio.run(run_technology_scan(target, ignore_ssl))

    # Verify the instance was created and methods called with right args
    mock_wappalyzer_class.assert_called_once()
    mock_instance.run.assert_called_once_with(
        target, options={"verify_ssl": not ignore_ssl}
    )
    mock_instance.parse_output.assert_called_once()
    assert result == []


@patch("src.cli.scan.Sublist3rIntegration")
def test_subdomain_scan_function(mock_sublist3r_class):
    """Test the subdomain scan function wrapper."""
    target = "https://example.com"

    # Create a properly mocked integration object
    mock_instance = MagicMock()
    # The run method needs to be an AsyncMock to be awaitable
    mock_instance.run = AsyncMock()
    mock_instance.run.return_value = MagicMock()
    mock_instance.parse_output.return_value = []

    # Make the constructor return our mocked instance
    mock_sublist3r_class.return_value = mock_instance

    # Call the function (wrap in asyncio.run since it's async)
    from src.cli.scan import run_subdomain_scan

    result = asyncio.run(run_subdomain_scan(target))

    # Verify the instance was created and methods called with right args
    mock_sublist3r_class.assert_called_once()
    mock_instance.run.assert_called_once_with(target, options={})
    mock_instance.parse_output.assert_called_once()
    assert result == []


@patch("src.cli.scan.NmapIntegration")
def test_port_scan_function(mock_nmap_class):
    """Test the port scan function wrapper."""
    target = "https://example.com"
    depth = ScanDepth.STANDARD

    # Create a properly mocked integration object
    mock_instance = MagicMock()
    # The run method needs to be an AsyncMock to be awaitable
    mock_instance.run = AsyncMock()
    mock_instance.run.return_value = MagicMock()
    mock_instance.parse_output.return_value = []

    # Make the constructor return our mocked instance
    mock_nmap_class.return_value = mock_instance

    # Call the function (wrap in asyncio.run since it's async)
    from src.cli.scan import run_port_scan

    result = asyncio.run(run_port_scan(target, depth))

    # Verify the instance was created and methods called with right args
    mock_nmap_class.assert_called_once()
    mock_instance.run.assert_called_once_with(target, options={"ports": "top1000"})
    mock_instance.parse_output.assert_called_once()
    assert result == []


@patch("src.cli.scan.ZapIntegration")
def test_web_scan_function(mock_zap_class):
    """Test the web scan function wrapper."""
    target = "https://example.com"
    depth = ScanDepth.STANDARD
    ignore_ssl = False

    # Create a properly mocked integration object
    mock_instance = MagicMock()
    # The run method needs to be an AsyncMock to be awaitable
    mock_instance.run = AsyncMock()
    mock_instance.run.return_value = MagicMock()
    mock_instance.parse_output.return_value = []

    # Make the constructor return our mocked instance
    mock_zap_class.return_value = mock_instance

    # Call the function (wrap in asyncio.run since it's async)
    from src.cli.scan import run_web_scan

    result = asyncio.run(run_web_scan(target, depth, ignore_ssl))

    # Verify the instance was created and methods called with right args
    mock_zap_class.assert_called_once()
    mock_instance.run.assert_called_once_with(
        target, options={"active_scan": True, "ajax_spider": False, "verify_ssl": True}
    )
    mock_instance.parse_output.assert_called_once()
    assert result == []


@patch("src.cli.scan.DirsearchIntegration")
def test_directory_scan_function(mock_dirsearch_class):
    """Test the directory scan function wrapper."""
    target = "https://example.com"
    depth = ScanDepth.STANDARD
    ignore_ssl = False

    # Create a properly mocked integration object
    mock_instance = MagicMock()
    # The run method needs to be an AsyncMock to be awaitable
    mock_instance.run = AsyncMock()
    mock_instance.run.return_value = MagicMock()
    mock_instance.parse_output.return_value = []

    # Make the constructor return our mocked instance
    mock_dirsearch_class.return_value = mock_instance

    # Call the function (wrap in asyncio.run since it's async)
    from src.cli.scan import run_directory_scan

    result = asyncio.run(run_directory_scan(target, depth, ignore_ssl))

    # Verify the instance was created and methods called with right args
    mock_dirsearch_class.assert_called_once()
    mock_instance.run.assert_called_once_with(
        target,
        options={
            "wordlist": "medium.txt",
            "extensions": "php,html,js,txt",
            "verify_ssl": True,
        },
    )
    mock_instance.parse_output.assert_called_once()
    assert result == []


# Test the full CLI functionality with proper mocking
@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.ResultNormalizer")
@patch("src.cli.scan.run_directory_scan", return_value=[])
@patch("src.cli.scan.run_web_scan", return_value=[])
@patch("src.cli.scan.run_port_scan", return_value=[])
@patch("src.cli.scan.run_subdomain_scan", return_value=[])
@patch("src.cli.scan.run_technology_scan", return_value=[])
def test_scan_command_integration(
    mock_tech_scan,
    mock_subdomain_scan,
    mock_port_scan,
    mock_web_scan,
    mock_dir_scan,
    mock_normalizer_class,
    mock_validate,
):
    """Test that the scan command integrates all components correctly."""
    # Set up the normalizer mock
    normalizer_instance = MagicMock()
    mock_normalizer_class.return_value = normalizer_instance

    # Create a valid return structure (list of findings dictionaries)
    normalizer_instance.correlate_findings.return_value = [
        {
            "title": "Test Finding",
            "severity": "medium",
            "description": "A test finding for the scan test",
            "location": "https://example.com/test",
        }
    ]

    # Test with invoke
    result = runner.invoke(app, ["run", "https://example.com"])
    print(f"Exit code: {result.exit_code}")
    print(f"Output: {result.stdout}")
    if result.exception:
        print(f"Exception: {result.exception}")
    assert result.exit_code == 0

    # Verify all scan functions were called
    mock_tech_scan.assert_called_once()
    mock_subdomain_scan.assert_called_once()
    mock_port_scan.assert_called_once()
    mock_web_scan.assert_called_once()
    mock_dir_scan.assert_called_once()

    # Verify normalizer was used
    normalizer_instance.correlate_findings.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.ResultNormalizer")
@patch("src.cli.scan.run_web_scan", return_value=[])
@patch("src.cli.scan.run_port_scan", return_value=[])
def test_scan_command_specific_module(
    mock_port_scan,
    mock_web_scan,
    mock_normalizer_class,
    mock_validate,
):
    """Test that scan command works with specific modules."""
    # Set up the normalizer mock
    normalizer_instance = MagicMock()
    mock_normalizer_class.return_value = normalizer_instance

    # Create a valid return structure (list of findings dictionaries)
    normalizer_instance.correlate_findings.return_value = [
        {
            "title": "Test Finding",
            "severity": "medium",
            "description": "A test finding for the scan test",
            "location": "https://example.com/test",
        }
    ]

    # Test with invoke - specify only PORT and WEB modules
    result = runner.invoke(
        app, ["run", "https://example.com", "-m", "ports", "-m", "web"]
    )
    assert result.exit_code == 0

    # Verify only specified scan functions were called
    mock_port_scan.assert_called_once()
    mock_web_scan.assert_called_once()

    # Verify normalizer was used
    normalizer_instance.correlate_findings.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="https://example.com")
@patch("src.cli.scan.ResultNormalizer")
@patch("src.cli.scan.run_directory_scan", return_value=[])
@patch("src.cli.scan.run_web_scan", return_value=[])
@patch("src.cli.scan.run_port_scan", return_value=[])
@patch("src.cli.scan.run_subdomain_scan", return_value=[])
@patch("src.cli.scan.run_technology_scan", return_value=[])
def test_scan_command_with_ignore_ssl(
    mock_tech_scan,
    mock_subdomain_scan,
    mock_port_scan,
    mock_web_scan,
    mock_dir_scan,
    mock_normalizer_class,
    mock_validate,
):
    """Test that scan command properly passes ignore_ssl option."""
    # Set up the normalizer mock
    normalizer_instance = MagicMock()
    mock_normalizer_class.return_value = normalizer_instance

    # Create a valid return structure (list of findings dictionaries)
    normalizer_instance.correlate_findings.return_value = [
        {
            "title": "Test Finding",
            "severity": "medium",
            "description": "A test finding for the scan test",
            "location": "https://example.com/test",
        }
    ]

    # Test with invoke - with ignore-ssl flag
    result = runner.invoke(app, ["run", "https://example.com", "--ignore-ssl"])
    assert result.exit_code == 0

    # Verify scan functions that should handle SSL verification were called with ignore_ssl=True
    mock_tech_scan.assert_called_once_with("https://example.com", True, {})
    mock_web_scan.assert_called_once_with(
        "https://example.com", ScanDepth.STANDARD, True, {}
    )
    mock_dir_scan.assert_called_once_with(
        "https://example.com", ScanDepth.STANDARD, True, {}
    )


def test_scan_command_with_exception():
    """Test that scan command handles missing target parameter."""
    # Invoke command without a required target parameter
    result = runner.invoke(app)

    # Expect non-zero exit code due to the missing param
    assert result.exit_code != 0
    assert "Error" in result.stdout or "Error" in result.stderr
