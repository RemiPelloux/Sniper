"""
Normalizer for TruffleHog scan findings.

This module defines a normalizer that converts raw TruffleHog scan output into
standardized secret findings format.
"""

import logging
from typing import Any, Dict, List, Optional, cast

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity

log = logging.getLogger(__name__)


class TruffleHogFindingNormalizer(FindingNormalizer):
    """Normalizer for findings from TruffleHog secret scans."""

    def __init__(self) -> None:
        """Initialize the TruffleHog normalizer with severity mappings."""
        super().__init__("trufflehog")

        # Map TruffleHog detector types to severity levels
        self.severity_map: Dict[str, FindingSeverity] = {
            # High severity secrets
            "AWS": FindingSeverity.CRITICAL,
            "AZURE": FindingSeverity.CRITICAL,
            "GCP": FindingSeverity.CRITICAL,
            "PRIVATE_KEY": FindingSeverity.CRITICAL,
            "GITHUB": FindingSeverity.CRITICAL,
            # Medium severity secrets
            "SLACK": FindingSeverity.HIGH,
            "NPM": FindingSeverity.HIGH,
            "TWILIO": FindingSeverity.HIGH,
            "SENDGRID": FindingSeverity.HIGH,
            "OKTA": FindingSeverity.HIGH,
            "JWT": FindingSeverity.HIGH,
            "STRIPE": FindingSeverity.HIGH,
            # Lower severity secrets
            "GENERIC_API_KEY": FindingSeverity.MEDIUM,
            "GENERIC_SECRET": FindingSeverity.MEDIUM,
            "BASIC_AUTH": FindingSeverity.MEDIUM,
        }

        # Default severity if detector type isn't in our map
        self.default_severity: FindingSeverity = FindingSeverity.MEDIUM

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """
        Normalize TruffleHog findings.

        Args:
            raw_findings: List of raw TruffleHog findings to normalize

        Returns:
            List of normalized TruffleHog findings
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Use BaseFinding directly
            base_finding = finding

            # Set correct tool name
            base_finding.source_tool = self.tool_name

            # Store original detector type in raw_evidence if not already there
            if base_finding.raw_evidence and isinstance(
                base_finding.raw_evidence, dict
            ):
                if (
                    "detector_type" not in base_finding.raw_evidence
                    and "detector_type" in base_finding.raw_evidence
                ):  # Check if key exists in dict
                    base_finding.raw_evidence["detector_type"] = (
                        base_finding.raw_evidence["detector_type"]
                    )

            base_finding.severity = self._normalize_severity(base_finding)

            # Create a standardized description
            base_finding.description = self._normalize_description(base_finding)

            normalized_findings.append(base_finding)

        return normalized_findings

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """
        Normalize severity based on the secret detector type.

        Args:
            finding: The TruffleHog BaseFinding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # Default to MEDIUM severity
        severity: FindingSeverity = self.default_severity

        # Get detector type from raw_evidence
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        detector_type_str = metadata.get("detector_type")
        if detector_type_str and isinstance(detector_type_str, str):
            detector_type: str = detector_type_str.upper()

            # Map to severity using our severity map
            severity = self.severity_map.get(detector_type, self.default_severity)

            # Special case: if it's a private key with a passphrase, lower the severity
            if detector_type == "PRIVATE_KEY" and metadata.get("has_passphrase", False):
                severity = FindingSeverity.HIGH

        return severity

    def _normalize_description(self, finding: BaseFinding) -> str:
        """
        Create a standardized description for a TruffleHog finding.

        Args:
            finding: The TruffleHog BaseFinding to generate a description for

        Returns:
            Standardized description
        """
        # Use raw_evidence to get TruffleHog-specific fields
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        # Start with the finding name if available
        if finding.title:
            desc = finding.title
        else:
            # Create a title based on metadata
            detector_type = "Unknown Type"
            if metadata and "detector_type" in metadata:
                detector_type = metadata["detector_type"]

            desc = f"Secret detected: {detector_type}"

        # Add file and line information from metadata
        file_path = (
            metadata.get("SourceMetadata", {})
            .get("Data", {})
            .get("Git", {})
            .get("file")
        )
        line_number = (
            metadata.get("SourceMetadata", {})
            .get("Data", {})
            .get("Git", {})
            .get("line")
        )
        if file_path:
            desc += f"\nFile: {file_path}"
            if line_number:
                desc += f":{line_number}"

        # Add repository information if available
        repository = (
            metadata.get("SourceMetadata", {})
            .get("Data", {})
            .get("Git", {})
            .get("repository")
        )
        if repository:
            desc += f"\nRepository: {repository}"

        # Add detailed information section
        desc += "\n\nDetails:"

        # Add metadata information
        if metadata:
            if "detector_name" in metadata:
                desc += f"\nDetector Name: {metadata['detector_name']}"
            if "detector_type" in metadata:
                desc += f"\nDetector Type: {metadata['detector_type']}"

            # Git specific metadata
            git_meta = metadata.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            if git_meta:
                if "commit" in git_meta:
                    desc += f"\nCommit: {git_meta['commit']}"
                if "email" in git_meta:
                    desc += f"\nEmail: {git_meta['email']}"
                if "author" in git_meta:
                    desc += f"\nAuthor: {git_meta['author']}"
                if "timestamp" in git_meta:
                    desc += f"\nDate: {git_meta['timestamp']}"

            # Other potential metadata
            if "verified" in metadata:
                desc += f"\nVerified: {metadata['verified']}"

            if "extra_data" in metadata and metadata["extra_data"]:
                has_passphrase = metadata["extra_data"].get("has_passphrase")
                if has_passphrase is not None:
                    has_passphrase_str = "Yes" if has_passphrase else "No"
                    desc += f"\nHas Passphrase: {has_passphrase_str}"

        # Add recommendation based on severity
        desc += "\n\nRecommendation: "

        if finding.severity == FindingSeverity.CRITICAL:
            desc += (
                "This is a CRITICAL finding that requires immediate attention. "
                "Revoke and rotate this credential immediately. Investigate whether "
                "it has been accessed or used by unauthorized parties. Review "
                "logs for suspicious activity associated with this credential."
            )
        elif finding.severity == FindingSeverity.HIGH:
            desc += (
                "This is a HIGH severity finding. Rotate this credential as soon as possible. "
                "Consider implementing secret rotation policies and using a secure "
                "credentials management system rather than hardcoding secrets."
            )
        elif finding.severity == FindingSeverity.MEDIUM:
            desc += (
                "This is a MEDIUM severity finding. Review the use of this credential "
                "and consider moving it to a secure storage solution like a secrets manager. "
                "Rotate the credential as part of your remediation."
            )

        return desc
