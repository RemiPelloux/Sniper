"""
Unit tests for the DVWA scan command.
"""

import json
import re
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
        "target": "http://localhost",
        "scan_time": "2023-01-01 00:00:00",
        "scan_types": ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"],
        "scan_depth": "comprehensive",
        "urls_crawled": 10,
        "findings": [
            {
                "title": "SQL Injection in id",
                "description": "SQL Injection vulnerability that allows attackers to manipulate database queries in parameter 'id'",
                "severity": "HIGH",
                "url": "http://localhost/vulnerabilities/sqli/",
                "vulnerability_type": "sqli",
                "payload": "1' OR '1'='1",
                "evidence": "You have an error in your SQL syntax",
                "request_method": "GET"
            },
            {
                "title": "XSS in name",
                "description": "Cross-Site Scripting (XSS) vulnerability that allows attackers to inject client-side scripts in parameter 'name'",
                "severity": "MEDIUM",
                "url": "http://localhost/vulnerabilities/xss_r/",
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


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_basic(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test basic DVWA scan command execution"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Mock asyncio.run to return scanner run result directly
    mock_asyncio_run.side_effect = lambda coroutine: mock_scanner_instance.run.return_value
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify scanner was called correctly
    mock_scanner_class.assert_called_once()
    mock_scanner_instance.check_prerequisites.assert_called_once()
    mock_scanner_instance.run.assert_called_once()
    run_args, run_kwargs = mock_scanner_instance.run.call_args
    assert run_args[0] == "http://localhost"
    assert run_kwargs["options"]["scan_types"] == ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"]
    assert run_kwargs["options"]["scan_depth"] == "comprehensive"
    assert run_kwargs["options"]["max_urls"] == 100
    
    # Verify login was attempted
    mock_login.assert_called_once_with(mock_scanner_instance, "http://localhost", "low")


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_with_security_level(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan with custom security level"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Mock asyncio.run to return scanner run result directly
    mock_asyncio_run.side_effect = lambda coroutine: mock_scanner_instance.run.return_value
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--security-level", "medium"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify login was attempted with correct security level
    mock_login.assert_called_once_with(mock_scanner_instance, "http://localhost", "medium")


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_no_login(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan without login"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    
    # Mock asyncio.run to return scanner run result directly
    mock_asyncio_run.side_effect = lambda coroutine: mock_scanner_instance.run.return_value
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--no-login"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify login was not attempted
    mock_login.assert_not_called()


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_with_json_output(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner, tmp_path):
    """Test DVWA scan with JSON output"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Mock asyncio.run to return scanner run result directly
    mock_asyncio_run.side_effect = lambda coroutine: mock_scanner_instance.run.return_value
    
    # Create temporary output file
    output_file = tmp_path / "output.json"
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--output", str(output_file), "--json"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify that the file exists
    assert output_file.exists()


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_login_failed(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan when login fails"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = False
    
    # Mock asyncio.run to return scanner run result directly
    mock_asyncio_run.side_effect = lambda coroutine: mock_scanner_instance.run.return_value
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify scanning continues despite login failure
    mock_scanner_instance.run.assert_called_once()


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_prerequisites_not_met(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan when prerequisites are not met"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_scanner_instance.check_prerequisites.return_value = False
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 1
    
    # Verify scanner was checked but not run
    mock_scanner_class.assert_called_once()
    mock_scanner_instance.check_prerequisites.assert_called_once()
    mock_scanner_instance.run.assert_not_called()
    mock_login.assert_not_called()


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_no_vulnerabilities(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan with no vulnerabilities found"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Modify scanner to return no findings
    modified_result = mock_scanner_instance.run.return_value.copy()
    modified_result["findings"] = []
    
    # Mock asyncio.run to return modified scanner result
    mock_asyncio_run.side_effect = lambda coroutine: modified_result
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    
    # Verify scanner was called
    mock_scanner_class.assert_called_once()
    mock_scanner_instance.check_prerequisites.assert_called_once()
    mock_scanner_instance.run.assert_called_once()


@patch("src.cli.scan.asyncio.run")
@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_error_handling(mock_scanner_class, mock_login, mock_asyncio_run, mock_vulnerability_scanner, runner):
    """Test DVWA scan error handling"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Make asyncio.run raise an exception
    mock_asyncio_run.side_effect = Exception("Test scan error")
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 1
    
    # Verify scanner was initialized but the error was caught
    mock_scanner_class.assert_called_once()
    mock_scanner_instance.check_prerequisites.assert_called_once()


def test_try_dvwa_login():
    """Test the DVWA login helper function"""
    from src.cli.scan import try_dvwa_login
    
    # Mock scanner and responses
    scanner = MagicMock()
    # Add CSRF token to the login response
    login_response = MagicMock()
    login_response.text = '<input type="hidden" name="user_token" value="abcdef123456"> Welcome to Damn Vulnerable Web Application'
    login_response.status_code = 200
    
    security_response = MagicMock()
    security_response.text = '<input type="hidden" name="user_token" value="abcdef123456">'
    security_response.status_code = 200
    
    security_set_response = MagicMock()
    security_set_response.text = "security level set to low"
    security_set_response.status_code = 200
    
    # Configure session mock responses
    scanner.session.get.side_effect = [login_response, security_response]
    scanner.session.post.side_effect = [login_response, security_set_response]
    
    # Call function
    result = try_dvwa_login(scanner, "http://localhost", "low")
    
    # Assertions
    assert result is True
    assert scanner.session.get.call_count == 2
    assert scanner.session.post.call_count == 2
    
    # Get the actual post call arguments
    post_calls = scanner.session.post.call_args_list
    
    # First post call should be the login request
    login_call = post_calls[0]
    login_url = login_call[0][0]
    login_kwargs = login_call[1]
    assert "login.php" in login_url
    assert login_kwargs['data']["username"] == "admin"
    assert login_kwargs['data']["password"] == "password"
    assert login_kwargs['data']["user_token"] == "abcdef123456"
    
    # Second post call should be the security level change
    security_call = post_calls[1]
    security_url = security_call[0][0]
    security_kwargs = security_call[1]
    assert "security.php" in security_url
    assert security_kwargs['data']["security"] == "low"
    assert security_kwargs['data']["user_token"] == "abcdef123456" 