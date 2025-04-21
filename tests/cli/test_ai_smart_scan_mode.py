"""
Unit tests for the AI smart scan mode.
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
        "target": "http://example.com",
        "scan_time": "2023-01-01 00:00:00",
        "scan_types": ["xss", "sqli", "open_redirect", "path_traversal", "command_injection", "ssrf", "xxe"],
        "scan_depth": "comprehensive",
        "urls_crawled": 35,
        "ai_prioritized": True,
        "findings": [
            {
                "title": "SQL Injection in search parameter",
                "description": "SQL Injection vulnerability that allows attackers to manipulate database queries in parameter 'q'",
                "severity": "HIGH",
                "url": "http://example.com/search",
                "vulnerability_type": "sqli",
                "payload": "1' OR '1'='1",
                "evidence": "You have an error in your SQL syntax",
                "request_method": "GET"
            },
            {
                "title": "XSS in comment field",
                "description": "Cross-Site Scripting (XSS) vulnerability that allows attackers to inject client-side scripts in parameter 'comment'",
                "severity": "MEDIUM",
                "url": "http://example.com/post/123",
                "vulnerability_type": "xss",
                "payload": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script>",
                "request_method": "POST"
            },
            {
                "title": "Command Injection in ping tool",
                "description": "Command Injection vulnerability that allows attackers to execute system commands",
                "severity": "CRITICAL",
                "url": "http://example.com/admin/tools/ping",
                "vulnerability_type": "command_injection",
                "payload": "127.0.0.1; cat /etc/passwd",
                "evidence": "root:x:0:0:",
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
def mock_smart_recon():
    """Mock the SmartRecon module for testing"""
    recon_mock = MagicMock()
    recon_mock.check_prerequisites.return_value = True
    recon_mock.run.return_value = {
        "target": "http://example.com",
        "scan_time": "2023-01-01 00:00:00",
        "urls_analyzed": 50,
        "urls_prioritized": 25,
        "findings": [
            {
                "title": "High-risk endpoint detected",
                "description": "The endpoint appears to handle user input in an unsafe manner",
                "severity": "MEDIUM",
                "url": "http://example.com/user/profile",
                "risk_score": 0.85,
                "endpoints": [
                    {"url": "http://example.com/user/profile", "risk_score": 0.85, "patterns": ["userId", "edit"]}
                ]
            }
        ]
    }
    
    # Mock parse_output for smart recon
    def mock_parse_output(raw_output):
        findings = []
        # Convert to appropriate finding objects
        return findings
    
    recon_mock.parse_output.side_effect = mock_parse_output
    
    return recon_mock


@pytest.fixture
def runner():
    """CLI runner for testing commands"""
    return CliRunner()


@pytest.fixture
def mock_scan_mode_manager():
    """Mock ScanModeManager with ai_smart mode configuration"""
    manager_mock = MagicMock()
    
    # Define ai_smart mode config
    ai_smart_config = {
        "name": "ai_smart",
        "description": "Advanced AI-driven scan that prioritizes pages by vulnerability likelihood",
        "target_types": ["url", "webapp"],
        "modules": ["technologies", "web", "directories", "vulns"],
        "settings": {
            "max_threads": 8,
            "timeout": 3600,
            "retries": 2,
            "scan_depth": "comprehensive"
        },
        "tools": {
            "wappalyzer": {
                "enabled": True,
                "options": {}
            },
            "zap": {
                "enabled": True,
                "options": {
                    "active_scan": True,
                    "ajax_spider": True,
                    "scan_policy": "Default Policy"
                }
            },
            "vulnerability_scanner": {
                "enabled": True,
                "options": {
                    "scan_types": ["xss", "sqli", "open_redirect", "path_traversal", "command_injection", "ssrf", "xxe"],
                    "scan_depth": "comprehensive",
                    "verify_ssl": False,
                    "smart_crawling": True,
                    "ai_prioritization": True
                }
            },
            "smart_recon": {
                "enabled": True,
                "options": {
                    "max_urls": 100,
                    "similarity_threshold": 0.7,
                    "learn_from_findings": True,
                    "adaptive_payload_selection": True
                }
            }
        }
    }
    
    manager_mock.get_scan_mode.return_value = ai_smart_config
    manager_mock.get_tools_for_scan_mode.return_value = ai_smart_config["tools"]
    
    return manager_mock


@patch("src.cli.scan.validate_target_url", return_value="http://example.com")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_ai_smart_using_mode(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test running scan with AI smart mode"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://example.com": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "zap": (True, "ZAP is available"),
        "vulnerability_scanner": (True, "Vulnerability Scanner is available"),
        "smart_recon": (True, "Smart Recon is available")
    }
    
    # Run command with ai_smart mode
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
        result = runner.invoke(app, ["scan", "run", "http://example.com", "--mode", "ai_smart"], catch_exceptions=False)
    
    # Assertions
    assert "ai_smart" in result.stdout
    
    # Verify scan mode manager was called to get ai_smart mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("ai_smart")
    
    # Verify correct tools were checked
    mock_check_tools.assert_called_once()


@patch("src.cli.scan.validate_target_url", return_value="http://example.com")
@patch("src.cli.scan.resolve_scan_modules", return_value=["technologies", "web", "directories"])
@patch("src.cli.scan.ScanModeManager")
@patch("src.cli.scan.check_and_ensure_tools")
@patch("src.cli.scan.ResultNormalizer")
def test_scan_ai_smart_mode_with_unavailable_tools(
    mock_normalizer_class,
    mock_check_tools,
    mock_scan_mode_manager_class, 
    mock_resolve_modules,
    mock_validate_target,
    mock_scan_mode_manager, 
    runner
):
    """Test running scan with AI smart mode when some tools are unavailable"""
    # Setup mocks
    mock_scan_mode_manager_class.return_value = mock_scan_mode_manager
    
    # Mock normalizer
    mock_normalizer = MagicMock()
    mock_normalizer.correlate_findings.return_value = {"http://example.com": []}
    mock_normalizer_class.return_value = mock_normalizer
    
    # Mock tool availability - smart_recon is not available
    mock_check_tools.return_value = {
        "wappalyzer": (True, "Wappalyzer is available"),
        "zap": (True, "ZAP is available"),
        "vulnerability_scanner": (True, "Vulnerability Scanner is available"),
        "smart_recon": (False, "Smart Recon is not available - AI prioritization will be limited")
    }
    
    # Run command with ai_smart mode
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
        result = runner.invoke(app, ["scan", "run", "http://example.com", "--mode", "ai_smart"], catch_exceptions=False)
    
    # Assertions
    assert "some tools are not available" in result.stdout.lower()
    assert "smart_recon" in result.stdout.lower()
    
    # Verify scan mode manager was called to get ai_smart mode
    mock_scan_mode_manager.get_scan_mode.assert_called_once_with("ai_smart")
    
    # Verify correct tools were checked
    mock_check_tools.assert_called_once()


@patch("src.cli.scan.ScanModeManager")
def test_scan_with_invalid_ai_smart_mode(mock_scan_mode_manager_class, runner):
    """Test running scan with incorrect AI smart mode name"""
    # Mock an error when getting the scan mode
    manager_mock = MagicMock()
    manager_mock.get_scan_mode.side_effect = ValueError("Unknown scan mode: ai-smart")
    mock_scan_mode_manager_class.return_value = manager_mock
    
    # Run the command with an incorrect mode name
    result = runner.invoke(app, ["scan", "run", "http://example.com", "--mode", "ai-smart"], catch_exceptions=True)
    
    # Assertions
    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)
    assert "Unknown scan mode: ai-smart" in str(result.exception) 