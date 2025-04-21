"""
Unit tests for the DVWA scan command.
"""

import json
import re
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


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_basic(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test basic DVWA scan command execution"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Starting specialized DVWA scan against: http://localhost" in result.stdout
    assert "This scan will test for: XSS, SQLi, Command Injection, Path Traversal, File Inclusion" in result.stdout
    assert "Found 2 potential vulnerabilities" in result.stdout
    assert "SQL Injection in id" in result.stdout
    assert "XSS in name" in result.stdout
    
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


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_with_security_level(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan with custom security level"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--security-level", "medium"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Security Level: Will set to medium" in result.stdout
    
    # Verify login was attempted with correct security level
    mock_login.assert_called_once_with(mock_scanner_instance, "http://localhost", "medium")


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_no_login(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan without login"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--no-login"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Login: Will attempt to login with default credentials" not in result.stdout
    
    # Verify login was not attempted
    mock_login.assert_not_called()


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_with_json_output(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner, tmp_path):
    """Test DVWA scan with JSON output"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Create temporary output file
    output_file = tmp_path / "output.json"
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost", "--output", str(output_file), "--json"])
    
    # Assertions
    assert result.exit_code == 0
    assert f"Detailed findings saved to: {output_file}" in result.stdout
    
    # Verify that the file exists and contains valid JSON
    assert output_file.exists()
    
    # Since the file isn't actually written in the mock, we can't verify its contents
    # In a real test with integration, we would verify the content of the file


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_login_failed(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan when login fails"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = False
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Failed to login to DVWA" in result.stdout
    
    # Verify scanning continues despite login failure
    mock_scanner_instance.run.assert_called_once()


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_prerequisites_not_met(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan when prerequisites are not met"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_scanner_instance.check_prerequisites.return_value = False
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 1
    assert "Error: Vulnerability scanner prerequisites not met" in result.stdout
    
    # Verify scan was not run
    mock_scanner_instance.run.assert_not_called()


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_no_vulnerabilities(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan when no vulnerabilities are found"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Modify the mock to return no findings
    mock_scanner_instance.run.return_value = {
        "target": "http://localhost",
        "scan_time": "2023-01-01 00:00:00",
        "scan_types": ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"],
        "scan_depth": "comprehensive",
        "urls_crawled": 10,
        "findings": []
    }
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 0
    assert "No vulnerabilities found" in result.stdout
    assert "Suggestions for manual testing" in result.stdout


@patch("src.cli.scan.try_dvwa_login")
@patch("src.cli.scan.VulnerabilityScanner")
def test_dvwa_scan_error_handling(mock_scanner_class, mock_login, mock_vulnerability_scanner, runner):
    """Test DVWA scan error handling"""
    # Setup mocks
    mock_scanner_instance = mock_vulnerability_scanner
    mock_scanner_class.return_value = mock_scanner_instance
    mock_login.return_value = True
    
    # Make the scanner raise an exception
    mock_scanner_instance.run.side_effect = Exception("Test error")
    
    # Run command
    result = runner.invoke(app, ["scan", "dvwa", "http://localhost"])
    
    # Assertions
    assert result.exit_code == 1
    assert "Error during scan: Test error" in result.stdout


def test_try_dvwa_login():
    """Test the DVWA login helper function"""
    from src.cli.scan import try_dvwa_login
    
    # Mock scanner and responses
    scanner = MagicMock()
    login_response = MagicMock()
    login_response.text = "Welcome to Damn Vulnerable Web Application"
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
    
    # Verify CSRF token was extracted
    post_calls = scanner.session.post.call_args_list
    assert post_calls[0][1]["data"]["user_token"] == "abcdef123456"
    assert post_calls[1][1]["data"]["user_token"] == "abcdef123456"
    assert post_calls[1][1]["data"]["security"] == "low" 