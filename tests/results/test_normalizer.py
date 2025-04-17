"""Tests for the result normalization system."""

from typing import List

import pytest

from src.results.normalizer import FindingNormalizer, ResultNormalizer
from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    TechnologyFinding,
    WebFinding,
)


class TestFindingNormalizer:
    """Tests for the base FindingNormalizer class."""

    def test_init(self) -> None:
        """Test initializing a FindingNormalizer."""
        normalizer = FindingNormalizer("test-tool")
        assert normalizer.tool_name == "test-tool"

    def test_normalize_basic(self) -> None:
        """Test basic normalization functionality."""
        normalizer = FindingNormalizer("test-tool")

        # Create a test finding
        finding = BaseFinding(
            title="Test Finding",
            description="This is a test finding.",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            source_tool="wrong-tool",  # Intentionally wrong
        )

        # Normalize the finding
        normalized = normalizer.normalize([finding])[0]

        # Check that source_tool was corrected
        assert normalized.source_tool == "test-tool"

        # Severity should remain unchanged by the base normalizer
        assert normalized.severity == FindingSeverity.MEDIUM


class TestResultNormalizer:
    """Tests for the ResultNormalizer class."""

    def test_init(self) -> None:
        """Test initializing a ResultNormalizer."""
        normalizer = ResultNormalizer()
        assert isinstance(normalizer.normalizers, dict)

    def test_register_normalizer(self) -> None:
        """Test registering a custom normalizer."""
        result_normalizer = ResultNormalizer()
        custom_normalizer = FindingNormalizer("custom-tool")

        # Register the custom normalizer
        result_normalizer.register_normalizer(custom_normalizer)

        # Check that it was registered
        assert "custom-tool" in result_normalizer.normalizers
        assert result_normalizer.normalizers["custom-tool"] is custom_normalizer

    def test_normalize_findings_with_tool_name(self) -> None:
        """Test normalizing findings for a specific tool."""
        result_normalizer = ResultNormalizer()

        # Create a custom normalizer that changes severity
        class CustomNormalizer(FindingNormalizer):
            def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
                return FindingSeverity.HIGH

        custom_normalizer = CustomNormalizer("custom-tool")
        result_normalizer.register_normalizer(custom_normalizer)

        # Create test findings
        findings = [
            BaseFinding(
                title="Finding 1",
                description="Description 1",
                severity=FindingSeverity.LOW,
                target="example.com",
                source_tool="custom-tool",
            ),
            BaseFinding(
                title="Finding 2",
                description="Description 2",
                severity=FindingSeverity.MEDIUM,
                target="example.org",
                source_tool="other-tool",
            ),
        ]

        # Normalize findings for custom-tool only
        normalized = result_normalizer.normalize_findings(findings, "custom-tool")

        # Check that only one finding was normalized and its severity was changed
        assert len(normalized) == 1
        assert normalized[0].title == "Finding 1"
        assert normalized[0].severity == FindingSeverity.HIGH

    def test_normalize_findings_all_tools(self) -> None:
        """Test normalizing findings from all tools."""
        result_normalizer = ResultNormalizer()

        # Create custom normalizers with different behaviors
        class CustomNormalizer1(FindingNormalizer):
            def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
                return FindingSeverity.HIGH

        class CustomNormalizer2(FindingNormalizer):
            def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
                return FindingSeverity.LOW

        # Register the custom normalizers
        result_normalizer.register_normalizer(CustomNormalizer1("tool1"))
        result_normalizer.register_normalizer(CustomNormalizer2("tool2"))

        # Create test findings
        findings = [
            BaseFinding(
                title="Finding 1",
                description="Description 1",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                source_tool="tool1",
            ),
            BaseFinding(
                title="Finding 2",
                description="Description 2",
                severity=FindingSeverity.MEDIUM,
                target="example.org",
                source_tool="tool2",
            ),
            BaseFinding(
                title="Finding 3",
                description="Description 3",
                severity=FindingSeverity.MEDIUM,
                target="example.net",
                source_tool="tool3",  # No registered normalizer
            ),
        ]

        # Normalize all findings
        normalized = result_normalizer.normalize_findings(findings)

        # Check that all findings were normalized appropriately
        assert len(normalized) == 3

        # Finding from tool1 should have HIGH severity
        tool1_finding = next(f for f in normalized if f.source_tool == "tool1")
        assert tool1_finding.severity == FindingSeverity.HIGH

        # Finding from tool2 should have LOW severity
        tool2_finding = next(f for f in normalized if f.source_tool == "tool2")
        assert tool2_finding.severity == FindingSeverity.LOW

        # Finding from tool3 should have unchanged severity
        tool3_finding = next(f for f in normalized if f.source_tool == "tool3")
        assert tool3_finding.severity == FindingSeverity.MEDIUM

    def test_deduplicate_port_findings(self) -> None:
        """Test deduplication of port findings."""
        normalizer = ResultNormalizer()

        # Create duplicate port findings
        findings = [
            PortFinding(
                port=80,
                protocol="tcp",
                service="http",
                target="192.168.1.1",
                severity=FindingSeverity.MEDIUM,
                description="Open port",
                source_tool="nmap",
            ),
            PortFinding(
                port=80,
                protocol="tcp",
                service=None,  # Less information
                target="192.168.1.1",
                severity=FindingSeverity.LOW,  # Lower severity
                description="Open port",
                source_tool="nmap",
            ),
            PortFinding(
                port=443,  # Different port
                protocol="tcp",
                target="192.168.1.1",
                severity=FindingSeverity.LOW,
                description="Open port",
                source_tool="nmap",
            ),
        ]

        # Deduplicate findings
        deduplicated = normalizer.deduplicate_findings(findings)

        # Should have two findings (port 80 and port 443)
        assert len(deduplicated) == 2

        # The port 80 finding should be the one with more information
        port_80_finding = next(f for f in deduplicated if f.port == 80)
        assert port_80_finding.service == "http"
        assert port_80_finding.severity == FindingSeverity.MEDIUM

    def test_deduplicate_technology_findings(self) -> None:
        """Test deduplication of technology findings."""
        normalizer = ResultNormalizer()

        # Create duplicate technology findings
        findings = [
            TechnologyFinding(
                technology_name="Apache",
                version="2.4.41",
                categories=["Web Server"],
                target="example.com",
                severity=FindingSeverity.LOW,
                description="Apache detected",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="Apache",
                version=None,  # Less information
                categories=["Web Server", "HTTP Server"],  # More categories
                target="example.com",
                severity=FindingSeverity.MEDIUM,  # Higher severity
                description="Apache detected",
                source_tool="wappalyzer",
            ),
            TechnologyFinding(
                technology_name="PHP",  # Different technology
                target="example.com",
                severity=FindingSeverity.LOW,
                description="PHP detected",
                source_tool="wappalyzer",
            ),
        ]

        # Deduplicate findings
        deduplicated = normalizer.deduplicate_findings(findings)

        # Should have two findings (Apache and PHP)
        assert len(deduplicated) == 2

        # The Apache finding should have the version information and the higher severity
        apache_finding = next(f for f in deduplicated if f.technology_name == "Apache")
        assert apache_finding.version == "2.4.41"
        assert apache_finding.severity == FindingSeverity.MEDIUM
        assert len(apache_finding.categories) == 1  # Original categories

    def test_correlate_findings(self) -> None:
        """Test correlation of findings by target."""
        normalizer = ResultNormalizer()

        # Create findings for different targets
        findings = [
            BaseFinding(
                title="Finding 1",
                description="Description 1",
                severity=FindingSeverity.LOW,
                target="example.com",
                source_tool="tool1",
            ),
            BaseFinding(
                title="Finding 2",
                description="Description 2",
                severity=FindingSeverity.MEDIUM,
                target="example.com",  # Same target
                source_tool="tool2",
            ),
            BaseFinding(
                title="Finding 3",
                description="Description 3",
                severity=FindingSeverity.HIGH,
                target="example.org",  # Different target
                source_tool="tool1",
            ),
        ]

        # Correlate findings
        correlated = normalizer.correlate_findings(findings)

        # Should have two targets
        assert len(correlated) == 2
        assert "example.com" in correlated
        assert "example.org" in correlated

        # example.com should have two findings
        assert len(correlated["example.com"]) == 2

        # example.org should have one finding
        assert len(correlated["example.org"]) == 1
        assert correlated["example.org"][0].severity == FindingSeverity.HIGH
