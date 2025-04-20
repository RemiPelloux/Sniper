"""
Normalizer for Nuclei vulnerability scanner findings.

This module defines a normalizer for converting Nuclei raw scan output into
standardized infrastructure findings format.
"""

import logging
import os
from typing import Any, Dict, List, Optional, cast

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity

log = logging.getLogger(__name__)


class NucleiFindingNormalizer(FindingNormalizer):
    """Normalizer for findings from Nuclei vulnerability scanner."""

    def __init__(self) -> None:
        """Initialize the Nuclei normalizer with severity mappings."""
        super().__init__("nuclei")

        # Map Nuclei severity levels to standardized severity levels
        self.severity_map: Dict[str, FindingSeverity] = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
            "unknown": FindingSeverity.INFO,
        }

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """
        Normalize Nuclei findings.

        Args:
            raw_findings: List of raw Nuclei findings to normalize

        Returns:
            List of normalized Nuclei findings
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Use BaseFinding directly
            base_finding = finding

            # Set correct tool name
            base_finding.source_tool = self.tool_name

            # Store original nuclei severity in raw_evidence if not already there
            if base_finding.raw_evidence and isinstance(
                base_finding.raw_evidence, dict
            ):
                if (
                    "nuclei_severity" not in base_finding.raw_evidence
                    and "severity" in base_finding.raw_evidence
                ):
                    base_finding.raw_evidence["nuclei_severity"] = (
                        base_finding.raw_evidence["severity"]
                    )

            base_finding.severity = self._normalize_severity(base_finding)

            # Ensure description is properly formatted
            base_finding.description = self._normalize_description(base_finding)

            normalized_findings.append(base_finding)

        return normalized_findings

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """
        Normalize the severity of a Nuclei finding.

        Args:
            finding: The finding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # Default to INFO if no severity information is available
        raw_severity = "info"

        # Try getting severity from raw_evidence (which might hold original Nuclei output)
        if (
            finding.raw_evidence
            and isinstance(finding.raw_evidence, dict)
            and "severity" in finding.raw_evidence
        ):
            raw_severity = str(finding.raw_evidence["severity"]).lower()
        # Fallback to checking BaseFinding severity field itself (less likely for raw input)
        elif isinstance(finding.severity, str):
            raw_severity = finding.severity.lower()

        return self.severity_map.get(raw_severity, FindingSeverity.INFO)

    def _normalize_description(self, finding: BaseFinding) -> str:
        """
        Create a standardized description for a Nuclei finding.

        Args:
            finding: The Nuclei BaseFinding to generate a description for

        Returns:
            Standardized description
        """
        # Use raw_evidence to get Nuclei-specific fields
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        # Use name or template-id as the title
        if finding.title:
            desc = finding.title
        elif metadata and "template-id" in metadata:
            desc = f"Nuclei finding: {metadata['template-id']}"
        elif metadata and "info" in metadata and "name" in metadata["info"]:
            desc = (
                f"Nuclei finding: {metadata['info']["name"]}"  # Common Nuclei structure
            )
        else:
            desc = "Nuclei vulnerability finding"

        # Add target information
        if finding.target:
            desc += f"\nTarget: {finding.target}"

        # Add protocol, host, port from metadata if available
        host_info = metadata.get("host", finding.target)  # Use target as fallback
        port_info = metadata.get("port", "")
        protocol_info = metadata.get("scheme", "")
        if host_info or port_info or protocol_info:
            desc += f"\nLocation: {protocol_info}://{host_info}:{port_info}"

        # Add metadata information
        if metadata:
            # Add matcher-name if available
            if "matcher-name" in metadata:
                desc += f"\nMatcher: {metadata['matcher-name']}"

            # Add template information
            template_info = []
            if "template" in metadata:
                template_info.append(f"Template: {metadata['template']}")

            if "template-id" in metadata:
                template_info.append(f"Template ID: {metadata['template-id']}")

            if "template-author" in metadata:
                template_info.append(f"Author: {metadata['template-author']}")

            # Check inside 'info' block which is common in Nuclei JSON
            nuclei_info = metadata.get("info", {})
            if isinstance(nuclei_info, dict):
                if "author" in nuclei_info and not any(
                    "Author:" in s for s in template_info
                ):
                    template_info.append(f"Author: {nuclei_info['author']}")

            if template_info:
                desc += f"\n{', '.join(template_info)}"

            # Add additional template metadata
            tags = metadata.get("tags") or nuclei_info.get("tags")
            if tags:
                if isinstance(tags, list):
                    desc += f"\nTags: {', '.join(tags)}"
                else:
                    desc += f"\nTags: {tags}"

            # Add extracted information if available
            extracted = metadata.get("extracted-results")
            if extracted:
                if isinstance(extracted, list):
                    desc += "\n\nExtracted results:"
                    for result in extracted:
                        desc += f"\n- {result}"
                else:
                    desc += f"\n\nExtracted results: {extracted}"

            # Add CVE information if available
            classification = nuclei_info.get("classification", {})
            if isinstance(classification, dict):
                if "cve-id" in classification and classification["cve-id"]:
                    desc += f"\nCVE: {', '.join(classification['cve-id']) if isinstance(classification['cve-id'], list) else classification['cve-id']}"
                if "cvss-metrics" in classification and classification["cvss-metrics"]:
                    desc += f"\nCVSS Metrics: {classification['cvss-metrics']}"
                if "cvss-score" in classification and classification["cvss-score"]:
                    desc += f"\nCVSS Score: {classification['cvss-score']}"
                if "cwe-id" in classification and classification["cwe-id"]:
                    desc += f"\nCWE: {', '.join(classification['cwe-id']) if isinstance(classification['cwe-id'], list) else classification['cwe-id']}"

            # Add references if available
            references = metadata.get("reference") or nuclei_info.get("reference")
            if references:
                if isinstance(references, list):
                    desc += "\n\nReferences:"
                    for ref in references:
                        desc += f"\n- {ref}"
                else:
                    desc += f"\n\nReference: {references}"

            # Add description if available
            nuclei_description = metadata.get("description") or nuclei_info.get(
                "description"
            )
            if nuclei_description:
                desc += f"\n\nDetails: {nuclei_description}"

            # Add remediation if available
            remediation = metadata.get("remediation") or nuclei_info.get("remediation")
            if remediation:
                desc += f"\n\nRemediation: {remediation}"

        # Add severity-based context
        if finding.severity == FindingSeverity.CRITICAL:
            desc += (
                "\n\nThis is a CRITICAL vulnerability that requires immediate attention. "
                "It could allow attackers to gain complete control of the system "
                "or access sensitive information with minimal effort."
            )
        elif finding.severity == FindingSeverity.HIGH:
            desc += (
                "\n\nThis is a HIGH severity vulnerability that should be addressed "
                "promptly to prevent potential exploitation."
            )
        elif finding.severity == FindingSeverity.MEDIUM:
            desc += (
                "\n\nThis is a MEDIUM severity vulnerability that should be included "
                "in your remediation plan."
            )

        return desc
