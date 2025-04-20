"""Tests for tool-specific finding normalizers."""

from typing import Any, Dict, List

import pytest

from src.results.normalizers.nmap_normalizer import NmapFindingNormalizer
from src.results.normalizers.wappalyzer_normalizer import WappalyzerFindingNormalizer
from src.results.normalizers.zap_normalizer import ZAPFindingNormalizer
from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    TechnologyFinding,
    WebFinding,
)


class TestNmapNormalizer:
    """Tests for the Nmap finding normalizer."""

    def test_init(self) -> None:
        """Test initializing the Nmap normalizer."""
        normalizer = NmapFindingNormalizer()
        assert normalizer.tool_name == "nmap"
        assert isinstance(normalizer.severity_map, dict)
        assert isinstance(normalizer.high_risk_services, list)
        assert isinstance(normalizer.critical_risk_services, list)

    def test_normalize_severity_by_service(self) -> None:
        """Test severity normalization based on service."""
        normalizer = NmapFindingNormalizer()

        # Create port findings with different services
        findings = [
            PortFinding(
                port=1234,  # Non-standard port
                protocol="tcp",
                service="mysql",  # High-risk service
                target="192.168.1.1",
                severity=FindingSeverity.INFO,  # Should be upgraded
                description="Open port",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
            PortFinding(
                port=8080,  # Standard HTTP alt port
                protocol="tcp",
                service="unknown",  # Not in service map
                target="192.168.1.1",
                severity=FindingSeverity.INFO,
                description="Open port",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # MySQL service should be upgraded to HIGH
        mysql_finding = next(
            f for f in normalized if isinstance(f, PortFinding) and f.service == "mysql"
        )
        assert mysql_finding.severity == FindingSeverity.HIGH

        # Unknown service on standard port should follow port-based severity
        unknown_finding = next(
            f
            for f in normalized
            if isinstance(f, PortFinding) and f.service == "unknown"
        )
        assert unknown_finding.severity == FindingSeverity.MEDIUM  # Based on port 8080

    def test_normalize_severity_by_port(self) -> None:
        """Test severity normalization based on port number."""
        normalizer = NmapFindingNormalizer()

        # Create port findings with different ports
        findings = [
            PortFinding(
                port=22,  # SSH port
                protocol="tcp",
                service=None,  # No service info
                target="192.168.1.1",
                severity=FindingSeverity.INFO,
                description="Open port",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
            PortFinding(
                port=9999,  # Non-standard port
                protocol="tcp",
                service=None,
                target="192.168.1.1",
                severity=FindingSeverity.INFO,
                description="Open port",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # SSH port should be MEDIUM
        ssh_finding = next(
            f for f in normalized if isinstance(f, PortFinding) and f.port == 22
        )
        assert ssh_finding.severity == FindingSeverity.MEDIUM

        # Non-standard port should remain INFO
        nonstandard_finding = next(
            f for f in normalized if isinstance(f, PortFinding) and f.port == 9999
        )
        assert nonstandard_finding.severity == FindingSeverity.INFO

    def test_normalize_description(self) -> None:
        """Test description normalization for port findings."""
        normalizer = NmapFindingNormalizer()

        # Create port findings with different attributes
        findings = [
            PortFinding(
                port=22,
                protocol="tcp",
                service="ssh",
                banner="OpenSSH 8.2p1",
                target="192.168.1.1",
                severity=FindingSeverity.MEDIUM,
                description="Old description",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
            PortFinding(
                port=80,
                protocol="tcp",
                service="http",
                banner=None,  # No banner
                target="192.168.1.1",
                severity=FindingSeverity.MEDIUM,
                description="Old description",
                source_tool="nmap",
                raw_evidence={"state": "open"},  # Add state information
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # SSH finding should have banner in description
        ssh_finding = next(
            f for f in normalized if isinstance(f, PortFinding) and f.port == 22
        )
        assert "ssh (open) on" in ssh_finding.description
        assert "Port: 22" in ssh_finding.description
        assert "Protocol: tcp" in ssh_finding.description
        assert "Service: ssh" in ssh_finding.description
        assert (
            "properly configured and required" in ssh_finding.description
        )  # Medium risk context

        # HTTP finding should not have banner info
        http_finding = next(
            f for f in normalized if isinstance(f, PortFinding) and f.port == 80
        )
        assert "http (open) on" in http_finding.description
        assert "Port: 80" in http_finding.description
        assert "Service: http" in http_finding.description


class TestWappalyzerNormalizer:
    """Tests for the Wappalyzer finding normalizer."""

    def test_init(self) -> None:
        """Test initializing the Wappalyzer normalizer."""
        normalizer = WappalyzerFindingNormalizer()
        assert normalizer.tool_name == "wappalyzer"
        assert isinstance(normalizer.high_risk_techs, set)
        assert isinstance(normalizer.vulnerable_version_patterns, dict)
        assert isinstance(normalizer.category_severity_map, dict)

    def test_normalize_severity_by_version(self) -> None:
        """Test severity normalization based on known vulnerable versions."""
        normalizer = WappalyzerFindingNormalizer()

        # Create technology findings with different versions
        findings = [
            TechnologyFinding(
                technology_name="WordPress",
                version="4.9.8",  # Vulnerable version
                categories=["CMS"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="WordPress detected",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="WordPress",
                version="5.9.0",  # Non-vulnerable version
                categories=["CMS"],
                target="example.org",
                severity=FindingSeverity.INFO,
                description="WordPress detected",
                source_tool="wappalyzer",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # Vulnerable WordPress should be HIGH
        vulnerable_wp = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.version == "4.9.8"
        )
        assert vulnerable_wp.severity == FindingSeverity.HIGH

        # Non-vulnerable WordPress should be MEDIUM (based on high_risk_techs)
        safe_wp = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.version == "5.9.0"
        )
        assert safe_wp.severity == FindingSeverity.MEDIUM

    def test_normalize_severity_by_tech(self) -> None:
        """Test severity normalization based on high-risk technologies."""
        normalizer = WappalyzerFindingNormalizer()

        # Create technology findings with high-risk and low-risk techs
        findings = [
            TechnologyFinding(
                technology_name="jQuery",  # High-risk tech
                version=None,
                categories=["JavaScript libraries"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="jQuery detected",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="Custom Tech",  # Not in high-risk list
                version=None,
                categories=["JavaScript libraries"],
                target="example.org",
                severity=FindingSeverity.INFO,
                description="Custom tech detected",
                source_tool="wappalyzer",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # jQuery should be upgraded to MEDIUM
        jquery_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.technology_name == "jQuery"
        )
        assert jquery_finding.severity == FindingSeverity.MEDIUM

        # Custom tech should remain INFO or be set based on category
        custom_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.technology_name == "Custom Tech"
        )
        assert (
            custom_finding.severity == FindingSeverity.LOW
        )  # Based on JavaScript libraries category

    def test_normalize_severity_by_category(self) -> None:
        """Test severity normalization based on technology category."""
        normalizer = WappalyzerFindingNormalizer()

        # Create technology findings with different categories
        findings = [
            TechnologyFinding(
                technology_name="CustomCMS",  # Not in high-risk list
                version=None,
                categories=["CMS"],  # Medium risk category
                target="example.com",
                severity=FindingSeverity.INFO,
                description="CMS detected",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="CustomTech",  # Not in high-risk list
                version=None,
                categories=["Other"],  # Unknown category
                target="example.org",
                severity=FindingSeverity.INFO,
                description="Custom tech detected",
                source_tool="wappalyzer",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # CMS should be upgraded to MEDIUM based on category
        cms_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and "CMS" in f.categories
        )
        assert cms_finding.severity == FindingSeverity.MEDIUM

        # Unknown category should remain INFO
        other_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and "Other" in f.categories
        )
        assert other_finding.severity == FindingSeverity.INFO

    def test_normalize_title_and_description(self) -> None:
        """Test title and description normalization for technology findings."""
        normalizer = WappalyzerFindingNormalizer()

        # Create technology findings with different severities
        findings = [
            TechnologyFinding(
                technology_name="WordPress",
                version="4.9.8",  # Vulnerable version -> HIGH severity
                categories=["CMS"],
                target="example.com",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="Old description",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="jQuery",  # High-risk tech -> MEDIUM severity
                version="3.5.0",  # Not vulnerable
                categories=["JavaScript libraries"],
                target="example.org",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="Old description",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="CustomTech",  # Not in high-risk list -> INFO severity
                version=None,
                categories=["Other"],
                target="example.net",
                severity=FindingSeverity.INFO,
                description="Old description",
                source_tool="wappalyzer",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # Check title formatting for HIGH severity
        high_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.technology_name == "WordPress"
        )
        assert "Outdated Technology" in high_finding.title
        assert high_finding.version in high_finding.title
        assert "outdated version" in high_finding.description
        assert "known vulnerabilities" in high_finding.description

        # Check title formatting for MEDIUM severity
        medium_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.technology_name == "jQuery"
        )
        assert "Sensitive Technology" in medium_finding.title
        assert medium_finding.version in medium_finding.title
        assert "commonly targeted" in medium_finding.description

        # Check title formatting for INFO severity
        info_finding = next(
            f
            for f in normalized
            if isinstance(f, TechnologyFinding) and f.technology_name == "CustomTech"
        )
        assert "Technology Detected" in info_finding.title
        assert "Detected" in info_finding.description


class TestZAPNormalizer:
    """Tests for the ZAP finding normalizer."""

    def test_init(self) -> None:
        """Test initializing the ZAP normalizer."""
        normalizer = ZAPFindingNormalizer()
        assert normalizer.tool_name == "zap"

    def test_normalize_severity_by_vuln_type(self) -> None:
        """Test severity normalization based on vulnerability type."""
        normalizer = ZAPFindingNormalizer()

        # Create web findings with vulnerability indicators in title
        findings = [
            WebFinding(
                url="http://example.com/login",
                title="SQL Injection Vulnerability",  # SQL injection -> CRITICAL
                parameter="username",
                method="POST",
                target="example.com",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="SQL Injection found in login form",
                source_tool="zap",
            ),
            WebFinding(
                url="http://example.com/profile",
                title="Information Disclosure",  # Info disclosure -> MEDIUM
                parameter=None,
                method="GET",
                target="example.com",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="Information disclosure found in profile page",
                source_tool="zap",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # SQL Injection should be CRITICAL and title should contain "at /login"
        sql_finding = next(
            f
            for f in normalized
            if isinstance(f, WebFinding) and "Sql Injection at /login" in f.title
        )
        assert sql_finding.severity == FindingSeverity.CRITICAL

        # Information Disclosure should be MEDIUM and title should contain "at /profile"
        info_finding = next(
            f
            for f in normalized
            if isinstance(f, WebFinding) and "Information Disclosure at /profile" in f.title
        )
        assert info_finding.severity == FindingSeverity.MEDIUM

    def test_normalize_severity_by_raw_evidence(self) -> None:
        """Test severity normalization based on raw evidence."""
        normalizer = ZAPFindingNormalizer()

        # Create web findings with raw evidence containing vulnerability indicators
        findings = [
            WebFinding(
                url="http://example.com/search",
                title="Suspicious behavior",
                parameter="q",
                method="GET",
                target="example.com",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="Possible vulnerability",
                source_tool="zap",
                raw_evidence={
                    "evidence": "'or 1=1--",  # SQL injection pattern
                    "request": "GET /search?q='or+1%3D1-- HTTP/1.1",
                    "response": "HTTP/1.1 200 OK",
                },
            ),
            WebFinding(
                url="http://example.com/upload",
                title="Suspicious behavior",
                parameter="file",
                method="POST",
                target="example.com",
                severity=FindingSeverity.INFO,  # Will be upgraded
                description="Possible vulnerability",
                source_tool="zap",
                raw_evidence={
                    "evidence": "../../../etc/passwd",  # Path traversal
                    "request": "POST /upload HTTP/1.1",
                    "response": "HTTP/1.1 200 OK",
                },
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # SQL injection pattern should be HIGH
        sql_finding = next(
            f
            for f in normalized
            if isinstance(f, WebFinding)
            and f.raw_evidence
            and "'or 1=1--" in f.raw_evidence.get("evidence", "")
        )
        assert sql_finding.severity == FindingSeverity.HIGH

        # Path traversal pattern should be HIGH as well
        path_finding = next(
            f
            for f in normalized
            if isinstance(f, WebFinding)
            and f.raw_evidence
            and "../../../etc/passwd" in f.raw_evidence.get("evidence", "")
        )
        assert path_finding.severity == FindingSeverity.HIGH

    def test_normalize_url(self) -> None:
        """Test URL normalization for web findings."""
        normalizer = ZAPFindingNormalizer()

        # Create web findings with different URL formats
        findings = [
            WebFinding(
                url="example.com/login",  # Missing protocol
                title="Test Finding",
                parameter="username",
                method="POST",
                target="example.com",
                severity=FindingSeverity.MEDIUM,
                description="Test description",
                source_tool="zap",
            ),
            WebFinding(
                url="https://example.com/profile?id=123&section=personal",  # With query params
                title="Test Finding",
                parameter=None,
                method="GET",
                target="example.com",
                severity=FindingSeverity.MEDIUM,
                description="Test description",
                source_tool="zap",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # Missing protocol should be prefixed with http://
        missing_protocol = next(
            f
            for f in normalized
            if isinstance(f, WebFinding) and f.url.endswith("/login")
        )
        assert missing_protocol.url.startswith("http://")
        assert "example.com/login" in missing_protocol.url

        # URL with query params should be preserved
        with_params = next(
            f for f in normalized if isinstance(f, WebFinding) and "profile" in f.url
        )
        assert "https://example.com/profile" in with_params.url
        assert "id=123" in with_params.url
        assert "section=personal" in with_params.url

    def test_normalize_title(self) -> None:
        """Test title normalization for web findings."""
        normalizer = ZAPFindingNormalizer()

        # Create web findings with titles that will be normalized
        findings = [
            WebFinding(
                url="http://example.com/login",
                title="sql injection vulnerability",  # Lowercase
                parameter="username",
                method="POST",
                target="example.com",
                severity=FindingSeverity.HIGH,
                description="Test description",
                source_tool="zap",
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # Title should contain "Sql Injection at /login"
        sql_finding = next(
            f for f in normalized if isinstance(f, WebFinding)
        )
        assert "Sql Injection at /login" in sql_finding.title

    def test_normalize_description_from_raw_evidence(self) -> None:
        """Test description enhancement from raw evidence."""
        normalizer = ZAPFindingNormalizer()

        # Create web finding with raw evidence
        findings = [
            WebFinding(
                url="http://example.com/login",
                title="SQL Injection",
                parameter="username",
                method="POST",
                target="example.com",
                severity=FindingSeverity.HIGH,
                description="Basic description",
                source_tool="zap",
                raw_evidence={
                    "evidence": "'or 1=1--",
                    "request": "POST /login HTTP/1.1\nHost: example.com\n\nusername='or+1%3D1--&password=test",
                    "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Login successful</html>",
                    "cwe": "CWE-89",
                    "impact": "High impact allowing authentication bypass",
                    "description": "A detailed description of the SQL injection vulnerability",
                    "solution": "Use parameterized queries"
                },
            ),
        ]

        # Normalize findings
        normalized = normalizer.normalize(findings)  # type: ignore

        # Finding description should come from raw_evidence
        finding = next(f for f in normalized if isinstance(f, WebFinding))
        
        # If raw_evidence.description exists, it should be used
        if "description" in finding.raw_evidence:
            assert finding.raw_evidence["description"] in finding.description
            
        # If raw_evidence.solution exists, it should be mentioned
        if "solution" in finding.raw_evidence:
            assert "Solution:" in finding.description
            assert finding.raw_evidence["solution"] in finding.description
