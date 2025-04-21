"""
Unit tests for the generic scan command using juiceshop mode.
"""

import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from src.cli.main import app
from src.integrations.vulnerability_scanner import VulnerabilityFinding
from src.results.types import BaseFinding, FindingSeverity


@pytest.fixture
def mock_vulnerability_scanner():
    """Mock the VulnerabilityScanner for testing"""
    scanner_mock = MagicMock()
    scanner_mock.check_prerequisites.return_value = True
    scanner_mock.run.return_value = {
        "target": "http://localhost:3000",
        "scan_time": "2023-01-01 00:00:00",
        "scan_types": ["xss", "sqli", "open_redirect", "path_traversal"],
        "scan_depth": "comprehensive",
        "urls_crawled": 20,
        "findings": [
            {
                "title": "SQL Injection in id",
                "description": "SQL Injection vulnerability that allows attackers to manipulate database queries in parameter 'id'",
                "severity": "HIGH",
                "url": "http://localhost:3000/rest/products/search",
                "vulnerability_type": "sqli",
                "payload": "1' OR '1'='1",
                "evidence": "You have an error in your SQL syntax",
                "request_method": "GET"
            },
            {
                "title": "XSS in name",
                "description": "Cross-Site Scripting (XSS) vulnerability that allows attackers to inject client-side scripts in parameter 'q'",
                "severity": "MEDIUM",
                "url": "http://localhost:3000/search",
                "vulnerability_type": "xss",
                "payload": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script>",
                "request_method": "GET"
            }
        ]
    }
    
    # Mock parse_output to return BaseFinding objects
    def mock_parse_output(raw_output):
        findings = []
        for finding_dict in raw_output.get("findings", []):
            vuln_finding = VulnerabilityFinding(**finding_dict)
            web_finding = vuln_finding.to_web_finding()
            findings.append(web_finding)
        return findings
    
    scanner_mock.parse_output.side_effect = mock_parse_output
    
    return scanner_mock


@pytest.fixture
def runner():
    """CLI runner for testing commands"""
    return CliRunner()


@pytest.fixture
def mock_scan_mode_manager():
    """Mock ScanModeManager with juiceshop mode configuration"""
    manager_mock = MagicMock()
    
    # Define juiceshop mode config
    juiceshop_config = {
        "name": "juiceshop",
        "description": "Scan mode optimized for testing OWASP Juice Shop vulnerabilities",
        "target_types": ["url", "webapp"],
        "modules": ["technologies", "web", "directories"],
        "settings": {
            "max_threads": 5,
            "timeout": 1800,
            "retries": 2,
            "scan_depth": "standard"
        },
        "tools": {
            "wappalyzer": {
                "enabled": True,
                "options": {}
            },
            "nmap": {
                "enabled": True,
                "options": {
                    "ports": "3000",
                    "timing_template": 3,
                    "scripts": "http-enum,http-headers"
                }
            },
            "zap": {
                "enabled": True,
                "options": {
                    "active_scan": True,
                    "ajax_spider": True,
                    "scan_policy": "Default Policy",
                    "context_name": "JuiceShop"
                }
            },
            "dirsearch": {
                "enabled": True,
                "options": {
                    "wordlist": "common.txt",
                    "extensions": "js,json,html"
                }
            },
            "vulnerability_scanner": {
                "enabled": True,
                "options": {
                    "scan_types": ["xss", "sqli", "open_redirect", "path_traversal"],
                    "scan_depth": "comprehensive",
                    "verify_ssl": False
                }
            }
        }
    }
    
    manager_mock.get_scan_mode.return_value = juiceshop_config
    manager_mock.get_tools_for_scan_mode.return_value = juiceshop_config["tools"]
    
    return manager_mock


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:3000")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_juiceshop_using_mode(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test running generic scan command with juiceshop mode"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://localhost:3000": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "nmap": (True, "Nmap is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Run command with juiceshop mode
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, \
         patch("src.cli.scan.run_web_scan") as mock_web_scan, \
         patch("src.cli.scan.run_directory_scan") as mock_dir_scan, \
         patch("src.cli.scan.asyncio.run") as mock_asyncio_run, \
         patch("src.cli.scan.output_scan_results") as mock_output_results:
        
        # Mock the scan functions to return empty results
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.side_effect = lambda coroutine: coroutine
        
        # Run the command
        result = runner.invoke(app, ["scan", "run", "http://localhost:3000", "--mode", "juiceshop"], catch_exceptions=True)
    
    # Assertions
    assert "juiceshop" in str(result.output).lower()
    
    # Verify scan mode manager was called to get juiceshop mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("juiceshop")
    
    # Verify correct tools were checked
    mock_check_tools.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:3000")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_juiceshop_using_mode_with_output(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner,
    tmp_path
):
    """Test running generic scan command with juiceshop mode and output file"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://localhost:3000": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "nmap": (True, "Nmap is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Create temporary output file
    output_file = tmp_path / "juiceshop_scan_results.json"
    
    # Run command with juiceshop mode and output file
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, \
         patch("src.cli.scan.run_web_scan") as mock_web_scan, \
         patch("src.cli.scan.run_directory_scan") as mock_dir_scan, \
         patch("src.cli.scan.asyncio.run") as mock_asyncio_run, \
         patch("src.cli.scan.output_scan_results") as mock_output_results:
        
        # Mock the scan functions to return empty results
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.side_effect = lambda coroutine: coroutine
        
        # Run the command
        result = runner.invoke(app, [
            "scan", "run", "http://localhost:3000", 
            "--mode", "juiceshop", 
            "--output", str(output_file),
            "--json"
        ], catch_exceptions=True)
    
    # Assertions
    assert "juiceshop" in str(result.output).lower()
    
    # Verify scan mode manager was called to get juiceshop mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("juiceshop")
    
    # Verify correct tools were checked
    mock_check_tools.assert_called_once()


@patch("src.cli.scan.ScanModeManager")
def test_scan_with_invalid_juiceshop_mode(mock_scan_mode_manager_class, runner):
    """Test scan command with mode that doesn't exist"""
    # Setup mock to return None for non-existent mode
    manager_mock = MagicMock()
    manager_mock.get_scan_mode.side_effect = ValueError("Unknown scan mode: invalid_mode")
    mock_scan_mode_manager_class.return_value = manager_mock
    
    # Run command with invalid mode
    result = runner.invoke(app, ["scan", "run", "http://localhost:3000", "--mode", "invalid_mode"], catch_exceptions=True)
    
    # Assertions
    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)
    assert "Unknown scan mode: invalid_mode" in str(result.exception)


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:3000")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_juiceshop_mode_with_unavailable_tools(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test scan with juiceshop mode when some tools are unavailable"""
    # Setup mock for scan mode manager
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://localhost:3000": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability - some tools missing
    mock_check_tools.return_value = {
        "wappalyzer": (False, "Wappalyzer not found"),
        "nmap": (True, "Nmap is available"),
        "zap": (False, "ZAP not found"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Run command with juiceshop mode
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, \
         patch("src.cli.scan.run_web_scan") as mock_web_scan, \
         patch("src.cli.scan.run_directory_scan") as mock_dir_scan, \
         patch("src.cli.scan.asyncio.run") as mock_asyncio_run, \
         patch("src.cli.scan.output_scan_results") as mock_output_results:
        
        # Mock the scan functions to return empty results
        mock_tech_scan.return_value = []
        mock_web_scan.return_value = []
        mock_dir_scan.return_value = []
        mock_asyncio_run.side_effect = lambda coroutine: coroutine
        
        # Run the command
        result = runner.invoke(app, ["scan", "run", "http://localhost:3000", "--mode", "juiceshop"], catch_exceptions=True)
    
    # Assertions
    # Verify warning about unavailable tools
    assert "some tools are not available" in str(result.output).lower()
    assert "wappalyzer" in str(result.output).lower()
    assert "zap" in str(result.output).lower()
    assert "continuing with available tools" in str(result.output).lower()
    
    # Verify scan mode manager was called to get juiceshop mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("juiceshop") 