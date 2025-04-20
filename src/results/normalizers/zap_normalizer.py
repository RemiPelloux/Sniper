"""
OWASP ZAP findings normalizer for Sniper CLI.

This module defines the normalizer for ZAP web scanning findings.
"""

import logging
import re
from typing import Dict, List, Optional, Set

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity, WebFinding

log = logging.getLogger(__name__)


class ZAPFindingNormalizer(FindingNormalizer):
    """Normalizer for OWASP ZAP web scanner findings."""

    def __init__(self) -> None:
        """Initialize the ZAP normalizer."""
        super().__init__("zap")

        # Map ZAP risk levels to standardized severities
        self.zap_severity_map: Dict[str, FindingSeverity] = {
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "informational": FindingSeverity.INFO,
            # Default mappings
            "0": FindingSeverity.INFO,  # Informational
            "1": FindingSeverity.LOW,  # Low
            "2": FindingSeverity.MEDIUM,  # Medium
            "3": FindingSeverity.HIGH,  # High
        }

        # Map common vulnerability types to severities
        self.vulnerability_severity_map: Dict[str, FindingSeverity] = {
            "sql injection": FindingSeverity.CRITICAL,
            "remote code execution": FindingSeverity.CRITICAL,
            "xss": FindingSeverity.HIGH,
            "cross site scripting": FindingSeverity.HIGH,
            "directory traversal": FindingSeverity.HIGH,
            "path traversal": FindingSeverity.HIGH,
            "information disclosure": FindingSeverity.MEDIUM,
            "csrf": FindingSeverity.MEDIUM,
            "cross site request forgery": FindingSeverity.MEDIUM,
            "open redirect": FindingSeverity.MEDIUM,
            "insecure headers": FindingSeverity.LOW,
            "cookie without httponly": FindingSeverity.LOW,
            "cookie without secure": FindingSeverity.LOW,
        }

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """Normalize severity based on vulnerability type and ZAP risk level.

        For ZAP findings, severity is determined by:
        1. Vulnerability type (e.g., SQL injection, XSS)
        2. ZAP's own risk level (if available in raw_evidence)
        3. Check for patterns in raw evidence (SQL injection, path traversal)
        4. Default to the original severity

        Args:
            finding: The finding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # First check for specific vulnerability types in the title
        title_lower = finding.title.lower()
        for vuln_type, severity in self.vulnerability_severity_map.items():
            if vuln_type in title_lower:
                return severity

        # Then check if the raw evidence contains a ZAP risk level
        if isinstance(finding.raw_evidence, dict):
            if "risk" in finding.raw_evidence:
                risk = str(finding.raw_evidence["risk"]).lower()
                if risk in self.zap_severity_map:
                    return self.zap_severity_map[risk]

            # ZAP might also use 'riskcode' (numeric)
            if "riskcode" in finding.raw_evidence:
                risk_code = str(finding.raw_evidence["riskcode"])
                if risk_code in self.zap_severity_map:
                    return self.zap_severity_map[risk_code]

            # Check for patterns in evidence that indicate specific vulnerabilities
            if "evidence" in finding.raw_evidence:
                evidence = str(finding.raw_evidence["evidence"])

                # SQL Injection patterns
                if any(
                    pattern in evidence
                    for pattern in ["'or 1=1", "' or '1'='1", "1=1--", "'; --"]
                ):
                    return FindingSeverity.HIGH

                # Path Traversal patterns
                if any(
                    pattern in evidence
                    for pattern in ["../", "..\\", "/etc/passwd", "\\windows\\system32"]
                ):
                    return FindingSeverity.HIGH

        # Default to the original severity
        return finding.severity

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """Normalize a list of ZAP findings.

        Args:
            raw_findings: List of ZAP findings

        Returns:
            List of normalized findings
        """
        normalized_findings = []

        for finding in raw_findings:
            # Set standard source tool
            finding.source_tool = self.tool_name

            # Apply severity normalization
            finding.severity = self._normalize_severity(finding)

            # For WebFinding objects, normalize the URL format
            if isinstance(finding, WebFinding):
                finding.url = self._normalize_url(finding.url)
                # Update target if needed to ensure consistency
                finding.target = self._extract_target_from_url(finding.url)

            # Normalize title and description
            finding.title = self._normalize_title(finding)
            finding.description = self._normalize_description(finding)

            normalized_findings.append(finding)

        return normalized_findings

    def _normalize_url(self, url: str) -> str:
        """Normalize URL format for consistency.

        Args:
            url: The URL to normalize

        Returns:
            Normalized URL
        """
        # Ensure URL starts with a scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Remove trailing slashes for consistency
        while url.endswith("/"):
            url = url[:-1]

        return url

    def _extract_target_from_url(self, url: str) -> str:
        """Extract the base target from a URL.

        Args:
            url: The URL to extract from

        Returns:
            Base target (scheme + host)
        """
        # Extract scheme + host from URL
        match = re.match(r"(https?://[^/]+)", url)
        if match:
            return match.group(1)
        return url

    def _normalize_title(self, finding: BaseFinding) -> str:
        """Create a standardized title for findings.

        Args:
            finding: The finding

        Returns:
            Normalized title
        """
        # For WebFinding, include the path in the title
        if isinstance(finding, WebFinding):
            # Extract path from URL
            url_path = re.sub(r"https?://[^/]+", "", finding.url) or "/"

            # If original title doesn't include the vulnerability type,
            # try to extract it from description
            vuln_type = "Vulnerability"
            for known_vuln in self.vulnerability_severity_map.keys():
                if known_vuln in finding.title.lower():
                    vuln_type = known_vuln.title()
                    break
                elif finding.description and known_vuln in finding.description.lower():
                    vuln_type = known_vuln.title()
                    break

            # Format the title with the path
            return f"{vuln_type} at {url_path}"

        # For non-WebFinding, keep the original title but ensure it includes severity
        severity_prefix = ""
        if finding.severity == FindingSeverity.CRITICAL:
            severity_prefix = "Critical: "
        elif finding.severity == FindingSeverity.HIGH:
            severity_prefix = "High: "

        if not finding.title.startswith(severity_prefix) and (
            finding.severity == FindingSeverity.CRITICAL
            or finding.severity == FindingSeverity.HIGH
        ):
            return f"{severity_prefix}{finding.title}"

        return finding.title

    def _normalize_description(self, finding: BaseFinding) -> str:
        """Create a standardized description for findings.

        Args:
            finding: The finding

        Returns:
            Normalized description
        """
        # If the finding has a valid description, return it
        if finding.description and len(finding.description) > 20:
            # Just ensure it ends with a period
            if not finding.description.endswith((".", "!", "?")):
                return finding.description + "."
            return finding.description

        # Otherwise build a description from raw evidence if available
        if isinstance(finding.raw_evidence, dict):
            description_parts = []

            # Try to use ZAP's description field
            if "description" in finding.raw_evidence:
                description_parts.append(finding.raw_evidence["description"])

            # Add solution if available
            if "solution" in finding.raw_evidence:
                description_parts.append(
                    f"Solution: {finding.raw_evidence['solution']}"
                )

            # Add reference if available
            if "reference" in finding.raw_evidence:
                description_parts.append(
                    f"Reference: {finding.raw_evidence['reference']}"
                )

            if description_parts:
                return " ".join(description_parts)

        # Fallback to a generic description based on the title
        return f"Found a potential security issue: {finding.title} on {finding.target}."
