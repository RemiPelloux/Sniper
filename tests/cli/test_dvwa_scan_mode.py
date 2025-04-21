"""
Unit tests for the generic scan command using DVWA mode.
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
        "target": "http://localhost:80",
        "scan_time": "2023-01-01 00:00:00",
        "scan_types": ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"],
        "scan_depth": "comprehensive",
        "urls_crawled": 15,
        "findings": [
            {
                "title": "SQL Injection in id",
                "description": "SQL Injection vulnerability that allows attackers to manipulate database queries in parameter 'id'",
                "severity": "HIGH",
                "url": "http://localhost:80/vulnerabilities/sqli/",
                "vulnerability_type": "sqli",
                "payload": "1' OR '1'='1",
                "evidence": "You have an error in your SQL syntax",
                "request_method": "GET"
            },
            {
                "title": "XSS in username",
                "description": "Cross-Site Scripting (XSS) vulnerability that allows attackers to inject client-side scripts in parameter 'username'",
                "severity": "MEDIUM",
                "url": "http://localhost:80/vulnerabilities/xss_r/",
                "vulnerability_type": "xss",
                "payload": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script>",
                "request_method": "GET"
            },
            {
                "title": "Command Injection in ip",
                "description": "Command Injection vulnerability that allows attackers to execute arbitrary commands in parameter 'ip'",
                "severity": "CRITICAL",
                "url": "http://localhost:80/vulnerabilities/exec/",
                "vulnerability_type": "command_injection",
                "payload": "127.0.0.1; cat /etc/passwd",
                "evidence": "root:x:0:0",
                "request_method": "POST"
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
    """Mock ScanModeManager with DVWA mode configuration"""
    manager_mock = MagicMock()
    
    # Define DVWA mode config
    dvwa_config = {
        "name": "dvwa",
        "description": "Scan mode optimized for testing Damn Vulnerable Web Application (DVWA)",
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
                    "ports": "80,443",
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
                    "context_name": "DVWA"
                }
            },
            "dirsearch": {
                "enabled": True,
                "options": {
                    "wordlist": "common.txt",
                    "extensions": "php,html,js"
                }
            },
            "vulnerability_scanner": {
                "enabled": True,
                "options": {
                    "scan_types": ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"],
                    "scan_depth": "comprehensive",
                    "verify_ssl": False
                }
            }
        }
    }
    
    manager_mock.get_scan_mode.return_value = dvwa_config
    manager_mock.get_tools_for_scan_mode.return_value = dvwa_config["tools"]
    
    return manager_mock


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:80")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_dvwa_using_mode(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test running generic scan command with DVWA mode"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://localhost:80": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "nmap": (True, "Nmap is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Run command with DVWA mode
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
        result = runner.invoke(app, ["scan", "run", "http://localhost:80", "--mode", "dvwa"], catch_exceptions=True)
    
    # Assertions
    assert "dvwa" in str(result.output).lower()
    
    # Verify scan mode manager was called to get DVWA mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("dvwa")
    
    # Verify correct tools were checked
    mock_check_tools.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:80")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
@patch("src.cli.scan.os.makedirs")
def test_scan_dvwa_using_mode_with_output(
    mock_makedirs,
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner,
    tmp_path
):
    """Test running generic scan command with DVWA mode and output file"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://localhost:80": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "nmap": (True, "Nmap is available"),
        "zap": (True, "ZAP is available"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Create temporary output file path and ensure the directory exists
    output_file = tmp_path / "dvwa_scan_results.json"
    output_dir = tmp_path
    output_dir.mkdir(exist_ok=True)
    
    # Define async function return values
    async def mock_tech_scan_coro(*args, **kwargs):
        return []
    
    async def mock_web_scan_coro(*args, **kwargs):
        return []
    
    async def mock_dir_scan_coro(*args, **kwargs):
        return []
    
    # Run command with DVWA mode and output file
    with patch("src.cli.scan.run_technology_scan", return_value=mock_tech_scan_coro()), \
         patch("src.cli.scan.run_web_scan", return_value=mock_web_scan_coro()), \
         patch("src.cli.scan.run_directory_scan", return_value=mock_dir_scan_coro()), \
         patch("src.cli.scan.asyncio.run") as mock_asyncio_run, \
         patch("src.cli.scan.output_scan_results") as mock_output_results:
        
        # Make asyncio.run return empty lists
        mock_asyncio_run.return_value = []
        
        # Run the command
        result = runner.invoke(app, [
            "scan", "run", "http://localhost:80", 
            "--mode", "dvwa", 
            "--output", str(output_file),
            "--json"
        ], catch_exceptions=True)
    
    # Print result for debugging if it fails
    if result.exit_code != 0:
        print(f"Command failed with exit code: {result.exit_code}")
        if hasattr(result, 'exception'):
            print(f"Exception: {result.exception}")
        print(f"Output: {result.output}")
    
    # Assertions
    assert result.exit_code == 0, f"Command failed with: {result.exception if hasattr(result, 'exception') else 'unknown error'}"
    mock_output_results.assert_called_once()
    assert "scan mode: dvwa" in str(result.output).lower()


@patch("src.cli.scan.ScanModeManager")
def test_scan_with_invalid_dvwa_mode(mock_scan_mode_manager_class, runner):
    """Test handling when DVWA mode is not found"""
    # Setup mocks
    mock_manager = MagicMock()
    mock_manager.get_scan_mode.return_value = None  # Simulate mode not found
    mock_scan_mode_manager_class.return_value = mock_manager
    
    # Run command with invalid mode
    result = runner.invoke(app, ["scan", "run", "http://localhost:80", "--mode", "dvwa"], catch_exceptions=True)
    
    # Assertions
    assert result.exit_code != 0
    assert "invalid" in str(result.output).lower() or "not found" in str(result.output).lower()


@patch("src.cli.scan.validate_target_url", return_value="http://localhost:80")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_dvwa_mode_with_unavailable_tools(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test handling of unavailable tools when using DVWA mode"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability - ZAP is missing
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "nmap": (True, "Nmap is available"),
        "zap": (False, "ZAP is not available"),
        "dirsearch": (True, "Dirsearch is available")
    }
    
    # Run command with DVWA mode
    with patch("src.cli.scan.run_technology_scan") as mock_tech_scan, \
         patch("src.cli.scan.run_web_scan") as mock_web_scan, \
         patch("src.cli.scan.run_directory_scan") as mock_dir_scan, \
         patch("src.cli.scan.asyncio.run") as mock_asyncio_run, \
         patch("src.cli.scan.output_scan_results") as mock_output_results:
        
        # Run the command
        result = runner.invoke(app, ["scan", "run", "http://localhost:80", "--mode", "dvwa"], catch_exceptions=True)
    
    # Assertions
    assert "not available" in str(result.output).lower() or "missing" in str(result.output).lower()
    # Command should still run with warnings
    assert result.exit_code == 0 