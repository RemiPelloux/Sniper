"""
Normalizer for Semgrep scan findings.

This module defines a normalizer that converts raw Semgrep scan output into
standardized code vulnerability findings format.
"""

import logging
import os
from typing import Any, Dict, List, Optional, cast

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity

log = logging.getLogger(__name__)


class SemgrepFindingNormalizer(FindingNormalizer):
    """Normalizer for findings from Semgrep code scans."""

    def __init__(self) -> None:
        """Initialize the Semgrep normalizer with severity mappings."""
        super().__init__("semgrep")

        # Map Semgrep severity levels to our severity levels
        self.severity_map: Dict[str, FindingSeverity] = {
            "ERROR": FindingSeverity.CRITICAL,
            "WARNING": FindingSeverity.HIGH,
            "INFO": FindingSeverity.MEDIUM,
        }

        # Default severity if not in our map
        self.default_severity: FindingSeverity = FindingSeverity.LOW

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """
        Normalize Semgrep findings.

        Args:
            raw_findings: List of raw Semgrep findings to normalize

        Returns:
            List of normalized Semgrep findings
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Use BaseFinding directly
            base_finding = finding

            # Set correct tool name
            base_finding.source_tool = self.tool_name

            # Store original semgrep severity in raw_evidence if not already there
            if base_finding.raw_evidence and isinstance(
                base_finding.raw_evidence, dict
            ):
                if (
                    "semgrep_severity" not in base_finding.raw_evidence
                    and "severity" in base_finding.raw_evidence
                ):
                    base_finding.raw_evidence["semgrep_severity"] = (
                        base_finding.raw_evidence["severity"]
                    )

            base_finding.severity = self._normalize_severity(base_finding)

            # Create a standardized description
            base_finding.description = self._normalize_description(base_finding)

            normalized_findings.append(base_finding)

        return normalized_findings

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """
        Normalize severity based on Semgrep severity level.

        Args:
            finding: The Semgrep BaseFinding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # Default to LOW severity
        severity: FindingSeverity = self.default_severity

        # Get Semgrep severity from raw_evidence (which holds original output)
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        if "severity" in metadata:
            semgrep_severity: str = str(metadata["severity"]).upper()

            # Map to our severity using our severity map
            severity = self.severity_map.get(semgrep_severity, self.default_severity)

            # Check rule_type from metadata within raw_evidence
            rule_type = metadata.get("check_id")  # Semgrep often uses check_id
            if (
                rule_type
                and isinstance(rule_type, str)
                and any(
                    kw in rule_type.lower()
                    for kw in [
                        "security",
                        "injection",
                        "authentication",
                    ]
                )
            ):
                if severity.value < FindingSeverity.HIGH.value:
                    severity = FindingSeverity.HIGH

        return severity

    def _normalize_description(self, finding: BaseFinding) -> str:
        """
        Create a standardized description for a Semgrep finding.

        Args:
            finding: The Semgrep BaseFinding to generate a description for

        Returns:
            Standardized description
        """
        # Use raw_evidence to get Semgrep-specific fields
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )
        extra = (
            metadata.get("extra", {}) if isinstance(metadata.get("extra"), dict) else {}
        )

        # Start with the finding name if available
        if finding.title:
            desc = finding.title
        elif extra.get("message"):
            desc = extra["message"]
        else:
            # Create a title based on metadata or code issue
            if metadata and "check_id" in metadata:
                desc = f"Code issue detected: {metadata['check_id']}"
            else:
                desc = "Code vulnerability detected"

        # Add file and line information from metadata
        file_path = metadata.get("path")
        line_number = extra.get("lines") or metadata.get("start", {}).get("line")
        if file_path:
            desc += f"\nFile: {file_path}"
            if line_number:
                desc += f":{line_number}"

        # Add code snippet if available
        code_snippet = extra.get("lines")
        if code_snippet:
            desc += f"\n\nVulnerable Code:\n```\n{code_snippet}\n```"

        # Add detailed information section
        desc += "\n\nDetails:"

        # Add metadata information
        if metadata:
            if "check_id" in metadata:
                desc += f"\nRule ID: {metadata['check_id']}"

            if extra.get("message"):
                desc += f"\nMessage: {extra['message']}"

            if extra.get("metadata"):
                semgrep_meta = extra["metadata"]
                if isinstance(semgrep_meta, dict):
                    # Add common Semgrep metadata fields
                    if "confidence" in semgrep_meta:
                        desc += f"\nConfidence: {semgrep_meta['confidence']}"
                    if "category" in semgrep_meta:
                        desc += f"\nCategory: {semgrep_meta['category']}"
                    if "impact" in semgrep_meta:
                        desc += f"\nImpact: {semgrep_meta['impact']}"
                    if "likelihood" in semgrep_meta:
                        desc += f"\nLikelihood: {semgrep_meta['likelihood']}"

                    # Add CWE/OWASP if available
                    cwe = semgrep_meta.get("cwe")
                    if cwe:
                        cwe_str = (
                            f"CWE: {', '.join(cwe) if isinstance(cwe, list) else cwe}"
                        )
                        desc += f"\n{cwe_str}"
                    owasp = semgrep_meta.get("owasp")
                    if owasp:
                        owasp_str = f"OWASP: {', '.join(owasp) if isinstance(owasp, list) else owasp}"
                        desc += f"\n{owasp_str}"

            # Report original severity from Semgrep
            if "severity" in metadata:
                desc += f"\nSemgrep Severity: {metadata['severity']}"

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
