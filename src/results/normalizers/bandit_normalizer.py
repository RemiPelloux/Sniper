"""
Normalizer for Bandit scan findings.

This module defines a normalizer that converts raw Bandit security scan output into
standardized code vulnerability findings format.
"""

import logging
from typing import Any, Dict, List, Optional, cast

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity

log = logging.getLogger(__name__)


class BanditFindingNormalizer(FindingNormalizer):
    """Normalizer for findings from Bandit Python security scans."""

    def __init__(self) -> None:
        """Initialize the Bandit normalizer with severity and confidence mappings."""
        super().__init__("bandit")

        # Map Bandit severity levels to our severity levels
        self.severity_map: Dict[str, FindingSeverity] = {
            "HIGH": FindingSeverity.CRITICAL,
            "MEDIUM": FindingSeverity.HIGH,
            "LOW": FindingSeverity.MEDIUM,
        }

        # Map confidence levels to adjust severity
        self.confidence_map: Dict[str, int] = {
            "HIGH": 0,  # No adjustment
            "MEDIUM": -1,  # Decrease severity by one
            "LOW": -2,  # Decrease severity by two
        }

        # Default severity if not in our map
        self.default_severity: FindingSeverity = FindingSeverity.LOW

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """
        Normalize Bandit findings.

        Args:
            raw_findings: List of raw Bandit findings to normalize

        Returns:
            List of normalized Bandit findings
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Use BaseFinding directly
            base_finding = finding

            # Set correct tool name
            base_finding.source_tool = self.tool_name

            # Store original bandit severity/confidence in raw_evidence if not already there
            if base_finding.raw_evidence and isinstance(
                base_finding.raw_evidence, dict
            ):
                if (
                    "bandit_severity" not in base_finding.raw_evidence
                    and "severity" in base_finding.raw_evidence
                ):
                    base_finding.raw_evidence["bandit_severity"] = (
                        base_finding.raw_evidence["severity"]
                    )
                if (
                    "bandit_confidence" not in base_finding.raw_evidence
                    and "confidence" in base_finding.raw_evidence
                ):
                    base_finding.raw_evidence["bandit_confidence"] = (
                        base_finding.raw_evidence["confidence"]
                    )

            base_finding.severity = self._normalize_severity(base_finding)

            # Create a standardized description
            base_finding.description = self._normalize_description(base_finding)

            normalized_findings.append(base_finding)

        return normalized_findings

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """
        Normalize severity based on Bandit severity level and confidence.

        Args:
            finding: The Bandit BaseFinding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # Default to LOW severity
        severity: FindingSeverity = self.default_severity

        # Get Bandit severity and confidence from raw_evidence
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        bandit_severity: Optional[str] = metadata.get("severity")
        bandit_confidence: Optional[str] = metadata.get("confidence")

        # Map raw severity to our scale if available
        if bandit_severity:
            bandit_severity = str(bandit_severity).upper()
            severity = self.severity_map.get(bandit_severity, self.default_severity)

        # Adjust severity based on confidence
        if bandit_confidence:
            bandit_confidence = str(bandit_confidence).upper()
            confidence_adj = self.confidence_map.get(bandit_confidence, 0)

            # Apply confidence adjustment
            severity_value = max(
                0, min(int(severity) + confidence_adj, len(FindingSeverity) - 1)
            )
            severity = FindingSeverity(severity_value)

        return severity

    def _normalize_description(self, finding: BaseFinding) -> str:
        """
        Create a standardized description for a Bandit finding.

        Args:
            finding: The Bandit BaseFinding to generate a description for

        Returns:
            Standardized description
        """
        # Use raw_evidence to get Bandit-specific fields
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        # Start with the finding name if available
        if finding.title:
            desc = finding.title
        elif metadata.get("issue_text"):
            desc = metadata["issue_text"]
        else:
            # Create a title based on metadata or code issue
            if metadata and "test_id" in metadata:
                desc = f"Security issue detected: {metadata['test_id']}"
            else:
                desc = "Python security vulnerability detected"

        # Add file and line information from metadata
        file_path = metadata.get("filename")
        line_number = metadata.get("line_number")
        if file_path:
            desc += f"\nFile: {file_path}"
            if line_number:
                desc += f":{line_number}"

        # Add code snippet if available
        code_snippet = metadata.get("code")
        if code_snippet:
            desc += f"\n\nVulnerable Code:\n```python\n{code_snippet}\n```"

        # Add detailed information section
        desc += "\n\nDetails:"

        # Add metadata information
        if metadata:
            if "test_id" in metadata:
                desc += f"\nTest ID: {metadata['test_id']}"

            if "test_name" in metadata:
                desc += f"\nTest Name: {metadata['test_name']}"

            if (
                "issue_text" in metadata and desc != metadata["issue_text"]
            ):  # Avoid repeating title
                desc += f"\nIssue: {metadata['issue_text']}"

            # Report original severity/confidence
            if "severity" in metadata:
                desc += f"\nBandit Severity: {metadata['severity']}"

            if "confidence" in metadata:
                desc += f"\nConfidence: {metadata['confidence']}"

            # Add CWE if available (may be nested)
            cwe_info = metadata.get("cwe")
            if cwe_info:
                if isinstance(cwe_info, dict) and "id" in cwe_info:
                    desc += f"\nCWE: CWE-{cwe_info['id']}"
                elif isinstance(cwe_info, (str, int)):
                    desc += f"\nCWE: CWE-{cwe_info}"

        # Add recommendation based on severity
        desc += "\n\nRecommendation: "

        if finding.severity == FindingSeverity.CRITICAL:
            desc += (
                "This is a CRITICAL finding that requires immediate attention. "
                "This issue likely represents a severe security vulnerability that "
                "could lead to remote code execution, data exfiltration, or system compromise. "
                "Fix this issue as soon as possible."
            )
        elif finding.severity == FindingSeverity.HIGH:
            desc += (
                "This is a HIGH severity finding. It represents a significant security "
                "vulnerability that should be addressed promptly. Consider implementing "
                "proper input validation, output encoding, or other security controls "
                "depending on the specific issue."
            )
        elif finding.severity == FindingSeverity.MEDIUM:
            desc += (
                "This is a MEDIUM severity finding. While not as severe as critical or high "
                "findings, it still represents a potential security concern that should be "
                "addressed. Review the code and implement appropriate security controls."
            )
        elif finding.severity == FindingSeverity.LOW:
            desc += (
                "This is a LOW severity finding. It may represent a code quality issue or "
                "a minor security concern. Consider addressing this issue during regular "
                "code maintenance."
            )

        return desc
