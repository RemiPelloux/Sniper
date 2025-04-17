"""Tests for the HTML report generator."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.reporting.html_generator import HTMLReportGenerator


@pytest.fixture
def sample_scan_data():
    """Return sample scan data for testing."""
    return {
        "scan_metadata": {
            "target": "https://test-target.com",
            "timestamp": "2023-06-15T10:30:00Z",
            "scan_duration": "00:15:30",
            "tools_used": ["nmap", "zap", "wappalyzer"],
            "scan_options": {
                "depth": "full",
                "ports": "1-1000",
                "threads": 10
            }
        },
        "findings": [
            {
                "title": "SQL Injection Vulnerability",
                "severity": "critical",
                "type": "vulnerability",
                "description": "SQL injection vulnerability found in login form",
                "location": "/login.php",
                "confidence": "high",
                "evidence": "POST parameter 'username' is vulnerable to SQL injection",
                "remediation": "Use prepared statements and parameterized queries",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection"
                ]
            },
            {
                "title": "Cross-Site Scripting (XSS)",
                "severity": "high",
                "type": "vulnerability",
                "description": "Reflected XSS vulnerability in search function",
                "location": "/search.php",
                "confidence": "medium",
                "evidence": "Parameter 'q' is reflected without proper encoding",
                "remediation": "Implement proper output encoding",
                "references": [
                    "https://owasp.org/www-community/attacks/xss/"
                ]
            },
            {
                "title": "Missing HTTP Security Headers",
                "severity": "medium",
                "type": "misconfiguration",
                "description": "Several security headers are missing",
                "location": "All pages",
                "confidence": "high",
                "evidence": "Content-Security-Policy, X-XSS-Protection headers not present",
                "remediation": "Implement security headers in web server configuration",
                "references": [
                    "https://owasp.org/www-project-secure-headers/"
                ]
            }
        ]
    }


class TestHTMLReportGenerator:
    """Test cases for the HTMLReportGenerator class."""

    def setup_method(self):
        """Set up test environment."""
        self.generator = HTMLReportGenerator(template_name="standard")
        # Create a temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()

    def teardown_method(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    @patch("src.reporting.html_generator.Environment")
    def test_initialization(self, mock_env):
        """Test that the HTML generator initializes correctly."""
        generator = HTMLReportGenerator(template_name="executive")
        assert generator.template_name == "executive"
        mock_env.assert_called_once()

    def test_prepare_template_data(self, sample_scan_data):
        """Test that template data is prepared correctly."""
        data = self.generator._prepare_template_data(sample_scan_data, True)
        
        # Check basic data structure
        assert "title" in data
        assert "metadata" in data
        assert "findings" in data
        assert "findings_by_severity" in data
        assert "stats" in data
        
        # Check that findings are grouped by severity
        findings_by_severity = data["findings_by_severity"]
        assert len(findings_by_severity["critical"]) == 1
        assert len(findings_by_severity["high"]) == 1
        assert len(findings_by_severity["medium"]) == 1
        
        # Check statistics
        stats = data["stats"]
        assert stats["total"] == 3
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert "risk_score" in stats
        
        # Check that evidence flag is passed through
        assert data["include_evidence"] is True

    @patch("src.reporting.html_generator.Environment")
    def test_generate(self, mock_env, sample_scan_data):
        """Test that the generate method creates an HTML file."""
        # Set up mock for template rendering
        mock_template = MagicMock()
        mock_template.render.return_value = "<html>Test HTML content</html>"
        
        mock_env_instance = MagicMock()
        mock_env_instance.get_template.return_value = mock_template
        mock_env.return_value = mock_env_instance
        
        # Create output path
        output_file = os.path.join(self.temp_dir.name, "test_report.html")
        
        # Test the generate method
        generator = HTMLReportGenerator(template_name="standard")
        result = generator.generate(sample_scan_data, output_file, True)
        
        # Verify the output
        assert result == output_file
        assert os.path.exists(output_file)
        
        # Check file content
        with open(output_file, "r") as f:
            content = f.read()
            assert content == "<html>Test HTML content</html>"
        
        # Verify template was retrieved with correct name
        mock_env_instance.get_template.assert_called_once_with("standard.html")
        
        # Verify template was rendered with data
        mock_template.render.assert_called_once()
        
    def test_group_findings_by_severity(self, sample_scan_data):
        """Test that findings are correctly grouped by severity."""
        findings = sample_scan_data["findings"]
        
        result = self.generator._group_findings_by_severity(findings)
        
        assert len(result["critical"]) == 1
        assert len(result["high"]) == 1
        assert len(result["medium"]) == 1
        assert len(result["low"]) == 0
        
        # Test with unknown severity (should go to info)
        findings.append({
            "title": "Unknown Severity Finding",
            "severity": "unknown",
            "type": "info",
            "description": "Test finding with unknown severity",
            "location": "/test.php"
        })
        
        result = self.generator._group_findings_by_severity(findings)
        assert len(result["info"]) == 1
        
    def test_calculate_risk_score(self):
        """Test that risk score calculation works correctly."""
        # Test with mixed severities
        severity_counts = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5
        }
        
        score = self.generator._calculate_risk_score(severity_counts)
        assert 0 <= score <= 10
        
        # Test with no findings
        empty_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        score = self.generator._calculate_risk_score(empty_counts)
        assert score == 0
        
        # Test with only critical
        critical_counts = {
            "critical": 5,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        score = self.generator._calculate_risk_score(critical_counts)
        assert score == 10  # Should be maximum score 