"""Tests for tool-specific finding normalizers."""

import pytest
from typing import Any, Dict, List

from src.results.normalizers.nmap_normalizer import NmapFindingNormalizer
from src.results.normalizers.wappalyzer_normalizer import WappalyzerFindingNormalizer
from src.results.normalizers.zap_normalizer import ZAPFindingNormalizer
from src.results.types import (
    BaseFinding, 
    FindingSeverity, 
    PortFinding, 
    TechnologyFinding, 
    WebFinding
)


class TestNmapNormalizer:
    """Tests for the Nmap finding normalizer."""
    
    def test_init(self) -> None:
        """Test initializing the Nmap normalizer."""
        normalizer = NmapFindingNormalizer()
        assert normalizer.tool_name == "nmap"
        assert isinstance(normalizer.service_severity_map, dict)
        assert isinstance(normalizer.port_severity_map, dict)
    
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
                source_tool="nmap"
            ),
            PortFinding(
                port=8080,  # Standard HTTP alt port
                protocol="tcp",
                service="unknown",  # Not in service map
                target="192.168.1.1",
                severity=FindingSeverity.INFO,
                description="Open port",
                source_tool="nmap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # MySQL service should be upgraded to HIGH
        mysql_finding = next(f for f in normalized if f.service == "mysql")
        assert mysql_finding.severity == FindingSeverity.HIGH
        
        # Unknown service on standard port should follow port-based severity
        unknown_finding = next(f for f in normalized if f.service == "unknown")
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
                source_tool="nmap"
            ),
            PortFinding(
                port=9999,  # Non-standard port
                protocol="tcp",
                service=None,
                target="192.168.1.1",
                severity=FindingSeverity.INFO,
                description="Open port",
                source_tool="nmap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # SSH port should be MEDIUM
        ssh_finding = next(f for f in normalized if f.port == 22)
        assert ssh_finding.severity == FindingSeverity.MEDIUM
        
        # Non-standard port should remain INFO
        nonstandard_finding = next(f for f in normalized if f.port == 9999)
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
                source_tool="nmap"
            ),
            PortFinding(
                port=80,
                protocol="tcp",
                service="http",
                banner=None,  # No banner
                target="192.168.1.1",
                severity=FindingSeverity.MEDIUM,
                description="Old description",
                source_tool="nmap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # SSH finding should have banner in description
        ssh_finding = next(f for f in normalized if f.port == 22)
        assert "Port 22/tcp is open" in ssh_finding.description
        assert "running ssh" in ssh_finding.description
        assert "with banner: OpenSSH 8.2p1" in ssh_finding.description
        assert "should be properly secured" in ssh_finding.description  # Medium risk context
        
        # HTTP finding should not have banner info
        http_finding = next(f for f in normalized if f.port == 80)
        assert "Port 80/tcp is open" in http_finding.description
        assert "running http" in http_finding.description
        assert "banner" not in http_finding.description


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
                source_tool="wappalyzer"
            ),
            TechnologyFinding(
                technology_name="WordPress",
                version="5.9.0",  # Non-vulnerable version
                categories=["CMS"],
                target="example.org",
                severity=FindingSeverity.INFO,
                description="WordPress detected",
                source_tool="wappalyzer"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # Vulnerable WordPress should be HIGH
        vulnerable_wp = next(f for f in normalized if f.version == "4.9.8")
        assert vulnerable_wp.severity == FindingSeverity.HIGH
        
        # Non-vulnerable WordPress should be MEDIUM (based on high_risk_techs)
        safe_wp = next(f for f in normalized if f.version == "5.9.0")
        assert safe_wp.severity == FindingSeverity.MEDIUM
    
    def test_normalize_severity_by_tech(self) -> None:
        """Test severity normalization based on high-risk technologies."""
        normalizer = WappalyzerFindingNormalizer()
        
        # Create technology findings for different technologies
        findings = [
            TechnologyFinding(
                technology_name="Apache",  # High-risk
                categories=["Web Servers"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="Apache detected",
                source_tool="wappalyzer"
            ),
            TechnologyFinding(
                technology_name="React",  # Not high-risk
                categories=["JavaScript Frameworks"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="React detected",
                source_tool="wappalyzer"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # Apache should be MEDIUM
        apache_finding = next(f for f in normalized if f.technology_name == "Apache")
        assert apache_finding.severity == FindingSeverity.MEDIUM
        
        # React should be LOW (from JavaScript Frameworks category)
        react_finding = next(f for f in normalized if f.technology_name == "React")
        assert react_finding.severity == FindingSeverity.LOW
    
    def test_normalize_severity_by_category(self) -> None:
        """Test severity normalization based on technology category."""
        normalizer = WappalyzerFindingNormalizer()
        
        # Create technology finding with a specific category
        finding = TechnologyFinding(
            technology_name="Unknown CMS",  # Not in high-risk techs
            categories=["CMS"],  # Medium-risk category
            target="example.com",
            severity=FindingSeverity.INFO,
            description="CMS detected",
            source_tool="wappalyzer"
        )
        
        # Normalize the finding
        normalized = normalizer.normalize([finding])[0]
        
        # Should be MEDIUM based on the CMS category
        assert normalized.severity == FindingSeverity.MEDIUM
    
    def test_normalize_title_and_description(self) -> None:
        """Test title and description normalization."""
        normalizer = WappalyzerFindingNormalizer()
        
        # Create technology findings with different severities
        findings = [
            TechnologyFinding(
                technology_name="WordPress",
                version="4.9.8",  # Will be normalized to HIGH
                categories=["CMS"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="Old description",
                source_tool="wappalyzer"
            ),
            TechnologyFinding(
                technology_name="Apache",  # Will be normalized to MEDIUM
                categories=["Web Servers"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="Old description",
                source_tool="wappalyzer"
            ),
            TechnologyFinding(
                technology_name="React",  # Will be normalized to LOW
                categories=["JavaScript Frameworks"],
                target="example.com",
                severity=FindingSeverity.INFO,
                description="Old description",
                source_tool="wappalyzer"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # High severity finding should have "Outdated" in title
        high_finding = next(f for f in normalized if f.technology_name == "WordPress")
        assert high_finding.title.startswith("Outdated Technology: WordPress")
        assert "outdated version" in high_finding.description.lower()
        
        # Medium severity finding should have "Sensitive" in title
        medium_finding = next(f for f in normalized if f.technology_name == "Apache")
        assert medium_finding.title.startswith("Sensitive Technology: Apache")
        assert "commonly targeted" in medium_finding.description.lower()
        
        # Low severity finding should have "Technology Detected" in title
        low_finding = next(f for f in normalized if f.technology_name == "React")
        assert low_finding.title.startswith("Technology Detected: React")
        assert "commonly targeted" not in low_finding.description.lower()
        assert "outdated version" not in low_finding.description.lower()


class TestZAPNormalizer:
    """Tests for the ZAP finding normalizer."""
    
    def test_init(self) -> None:
        """Test initializing the ZAP normalizer."""
        normalizer = ZAPFindingNormalizer()
        assert normalizer.tool_name == "zap"
        assert isinstance(normalizer.zap_severity_map, dict)
        assert isinstance(normalizer.vulnerability_severity_map, dict)
    
    def test_normalize_severity_by_vuln_type(self) -> None:
        """Test severity normalization based on vulnerability type."""
        normalizer = ZAPFindingNormalizer()
        
        # Create web findings with different vulnerability types
        findings = [
            WebFinding(
                url="https://example.com/login",
                method="POST",
                target="example.com",
                title="SQL Injection vulnerability",  # Critical severity type
                severity=FindingSeverity.MEDIUM,  # Should be upgraded
                description="SQL injection detected",
                source_tool="zap"
            ),
            WebFinding(
                url="https://example.com/page",
                method="GET",
                target="example.com",
                title="Information Disclosure",  # Medium severity type
                severity=FindingSeverity.LOW,  # Should be upgraded
                description="Information leak detected",
                source_tool="zap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # SQL Injection should be CRITICAL
        sqli_finding = next(f for f in normalized if "sql injection" in f.title.lower())
        assert sqli_finding.severity == FindingSeverity.CRITICAL
        
        # Information Disclosure should be MEDIUM
        info_finding = next(f for f in normalized if "information disclosure" in f.title.lower())
        assert info_finding.severity == FindingSeverity.MEDIUM
    
    def test_normalize_severity_by_raw_evidence(self) -> None:
        """Test severity normalization based on raw evidence from ZAP."""
        normalizer = ZAPFindingNormalizer()
        
        # Create web findings with raw evidence containing risk levels
        findings = [
            WebFinding(
                url="https://example.com/page1",
                method="GET",
                target="example.com",
                title="Finding 1",
                severity=FindingSeverity.INFO,
                description="Description 1",
                raw_evidence={"risk": "high"},  # Should map to HIGH
                source_tool="zap"
            ),
            WebFinding(
                url="https://example.com/page2",
                method="GET",
                target="example.com",
                title="Finding 2",
                severity=FindingSeverity.INFO,
                description="Description 2",
                raw_evidence={"riskcode": "2"},  # Should map to MEDIUM
                source_tool="zap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # Finding with "risk": "high" should be HIGH
        high_finding = next(f for f in normalized if f.url.endswith("/page1"))
        assert high_finding.severity == FindingSeverity.HIGH
        
        # Finding with "riskcode": "2" should be MEDIUM
        medium_finding = next(f for f in normalized if f.url.endswith("/page2"))
        assert medium_finding.severity == FindingSeverity.MEDIUM
    
    def test_normalize_url(self) -> None:
        """Test URL normalization for web findings."""
        normalizer = ZAPFindingNormalizer()
        
        # Create web findings with different URL formats
        findings = [
            WebFinding(
                url="example.com/path",  # Missing scheme
                method="GET",
                target="example.com",
                title="Finding 1",
                severity=FindingSeverity.MEDIUM,
                description="Description 1",
                source_tool="zap"
            ),
            WebFinding(
                url="https://example.org/path/",  # Trailing slash
                method="GET",
                target="example.org",
                title="Finding 2",
                severity=FindingSeverity.MEDIUM,
                description="Description 2",
                source_tool="zap"
            )
        ]
        
        # Normalize findings
        normalized = normalizer.normalize(findings)
        
        # URL without scheme should have http:// added
        without_scheme = next(f for f in normalized if "example.com" in f.url)
        assert without_scheme.url == "http://example.com/path"
        
        # URL with trailing slash should have it removed
        with_trailing_slash = next(f for f in normalized if "example.org" in f.url)
        assert with_trailing_slash.url == "https://example.org/path"
    
    def test_normalize_title(self) -> None:
        """Test title normalization for web findings."""
        normalizer = ZAPFindingNormalizer()
        
        # Create web finding
        finding = WebFinding(
            url="https://example.com/login",
            method="POST",
            target="example.com",
            title="Generic Finding Title",
            severity=FindingSeverity.HIGH,
            description="This is an XSS vulnerability",  # Contains vulnerability type
            source_tool="zap"
        )
        
        # Normalize the finding
        normalized = normalizer.normalize([finding])[0]
        
        # Title should now include the path and vulnerability type from description
        assert normalized.title == "Xss at /login"
    
    def test_normalize_description_from_raw_evidence(self) -> None:
        """Test description normalization using raw evidence."""
        normalizer = ZAPFindingNormalizer()
        
        # Create web finding with raw evidence containing detailed info
        finding = WebFinding(
            url="https://example.com/api",
            method="GET",
            target="example.com",
            title="Finding Title",
            severity=FindingSeverity.MEDIUM,
            description="",  # Empty description
            raw_evidence={
                "description": "This is a serious vulnerability.",
                "solution": "Apply security patches.",
                "reference": "https://example.com/cve"
            },
            source_tool="zap"
        )
        
        # Normalize the finding
        normalized = normalizer.normalize([finding])[0]
        
        # Description should be constructed from raw evidence
        assert "This is a serious vulnerability." in normalized.description
        assert "Solution: Apply security patches." in normalized.description
        assert "Reference: https://example.com/cve" in normalized.description 