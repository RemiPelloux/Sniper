"""
Normalizer for NMAP scan findings.

This module defines a normalizer that converts raw NMAP scan output into
standardized infrastructure findings format.
"""

import logging
import re
from typing import Any, Dict, List, Optional, cast

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity, PortFinding

log = logging.getLogger(__name__)


class NmapFindingNormalizer(FindingNormalizer):
    """Normalizer for NMAP scan findings."""

    def __init__(self) -> None:
        """Initialize the NMAP normalizer with severity mappings."""
        super().__init__("nmap")

        # Map service states to severity levels
        self.severity_map: Dict[str, FindingSeverity] = {
            "open": FindingSeverity.MEDIUM,  # Open ports are medium severity
            "filtered": FindingSeverity.LOW,  # Filtered ports are low severity
            "open|filtered": FindingSeverity.LOW,  # Ambiguous state - low severity
            "closed|filtered": FindingSeverity.INFO,  # Mostly closed - informational
            "closed": FindingSeverity.INFO,  # Closed ports are informational
        }

        # Services that warrant higher severity if found open
        self.high_risk_services: List[str] = [
            "telnet",
            "ftp",
            "rsh",
            "rlogin",
            "rexec",  # Unencrypted legacy services
            "mysql",
            "mssql",
            "postgresql",
            "mongodb",
            "redis",  # Databases
            "smb",
            "netbios",
            "ldap",  # Windows/directory services
            "vnc",
            "rdp",  # Remote access
            "snmp",  # Network management
        ]

        # Critical severity for these services if found open
        self.critical_risk_services: List[str] = [
            "ms-sql-s",
            "oracle",
            "mysql-alt",  # Database servers
            "elasticsearch",  # Search engines that might have data
            "kibana",
            "grafana",  # Dashboards
            "jenkins",
            "tomcat",  # DevOps and web services
            "mongodb",
            "redis",
            "memcached",  # NoSQL databases
        ]

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """
        Normalize NMAP scan findings.

        Args:
            raw_findings: List of raw NMAP findings to normalize

        Returns:
            List of normalized NMAP findings
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Expecting PortFinding, but handle BaseFinding gracefully
            if not isinstance(finding, PortFinding):
                log.warning(
                    f"Expected PortFinding but received {type(finding).__name__}, using BaseFinding logic"
                )
                # Fallback: basic normalization for BaseFinding
                finding.source_tool = self.tool_name
                finding.severity = self._normalize_severity_base(
                    finding
                )  # Use a generic severity logic
                normalized_findings.append(finding)
                continue  # Skip PortFinding specific logic

            port_finding = cast(PortFinding, finding)

            # Set correct tool name
            port_finding.source_tool = self.tool_name

            # Normalize severity based on port state and service
            port_finding.severity = self._normalize_severity_port(port_finding)

            # Create a standardized description
            port_finding.description = self._normalize_description_port(port_finding)

            # Store original Nmap metadata if not already present
            if (
                port_finding.raw_evidence
                and isinstance(port_finding.raw_evidence, dict)
                and "nmap_metadata" not in port_finding.raw_evidence
            ):
                # Assuming the original finding data was stored in raw_evidence if needed
                pass  # Or copy relevant fields if raw_evidence structure is known

            normalized_findings.append(port_finding)

        return normalized_findings

    def _normalize_severity_base(self, finding: BaseFinding) -> FindingSeverity:
        """
        Normalize severity for a BaseFinding (fallback).

        Args:
            finding: The BaseFinding to normalize severity for.

        Returns:
            Normalized FindingSeverity
        """
        # Use existing severity if valid, otherwise default
        if isinstance(finding.severity, FindingSeverity):
            return finding.severity
        log.warning(
            f"Invalid severity '{finding.severity}' for finding '{finding.title}', defaulting to INFO."
        )
        return FindingSeverity.INFO

    def _normalize_severity_port(self, finding: PortFinding) -> FindingSeverity:
        """
        Normalize severity based on port state and service for PortFinding.

        Args:
            finding: The NMAP PortFinding to normalize

        Returns:
            Normalized FindingSeverity
        """
        # Default to INFO severity, use existing severity if it's higher
        current_severity = finding.severity
        severity = FindingSeverity.INFO
        if (
            isinstance(current_severity, FindingSeverity)
            and current_severity.value > severity.value
        ):
            severity = current_severity

        # Use raw_evidence if metadata is needed and not directly on PortFinding
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        # Get port state from metadata (assuming it's in raw_evidence)
        if "state" in metadata:
            port_state = str(metadata["state"]).lower()
            # Get base severity from state
            base_severity = self.severity_map.get(port_state, FindingSeverity.INFO)
            severity = base_severity

            # Use finding.service directly if available, otherwise check metadata
            service_name = finding.service or metadata.get("service")

            if port_state == "open":
                # If service is identified, check it against our lists
                if service_name:
                    service = str(service_name).lower()

                    # Check for critical services
                    for critical_service in self.critical_risk_services:
                        if critical_service in service:
                            return FindingSeverity.CRITICAL

                    # Check for high risk services
                    for high_risk in self.high_risk_services:
                        if high_risk in service:
                            return FindingSeverity.HIGH

                    # Check for common web services
                    if any(web_svc in service for web_svc in ["http", "https", "www"]):
                        severity = FindingSeverity.MEDIUM
                else:
                    # No service identified, check port number
                    port = finding.port

                    # Common/important ports should remain MEDIUM
                    common_ports = [
                        21,
                        22,
                        23,
                        25,
                        53,
                        80,
                        110,
                        111,
                        135,
                        139,
                        143,
                        389,
                        443,
                        445,
                        993,
                        995,
                        1433,
                        1521,
                        3306,
                        3389,
                        5432,
                        8080,
                        8443,
                    ]

                    if port in common_ports:
                        severity = FindingSeverity.MEDIUM
                    else:
                        # Non-standard ports with no identified service revert to original severity or INFO
                        severity = (
                            current_severity
                            if current_severity != FindingSeverity.MEDIUM
                            else FindingSeverity.INFO
                        )

        return severity

    def _normalize_description_port(self, finding: PortFinding) -> str:
        """
        Create a standardized description for an NMAP finding.

        Args:
            finding: The NMAP PortFinding to generate a description for

        Returns:
            Standardized description
        """
        # target might be domain or IP, PortFinding has port/protocol directly
        target_info = finding.target or "Unknown Target"
        port = finding.port
        protocol = finding.protocol

        # Use finding's title if it exists, otherwise generate one
        desc = finding.title

        # Use raw_evidence if metadata is needed and not directly on PortFinding
        metadata = (
            finding.raw_evidence if isinstance(finding.raw_evidence, dict) else {}
        )

        # Append service/state info to title if not already there
        service_name = finding.service or str(
            metadata.get("service", "Unknown service")
        )
        state = str(metadata.get("state", "Unknown state"))
        port_info_str = f"{service_name} ({state}) on {target_info}:{port}/{protocol}"
        if port_info_str not in desc:
            desc = f"{desc} - {port_info_str}"

        # Start description body
        # Start description body
        desc_body = f"\nTarget: {target_info}"
        desc_body += "\n\nDetails:"
        desc_body += f"\nPort: {port}"
        desc_body += f"\nProtocol: {protocol}"
        if finding.service:
            desc_body += f"\nService: {finding.service}"
        else:
            desc_body += (
                f"\nService: {str(metadata.get('service', 'N/A'))}"  # From metadata
            )

        # Add metadata information from raw_evidence
        if "state" in metadata:
            desc_body += f"\nState: {metadata['state']}"

        if "service" in metadata:
            desc_body += f"\nService: {metadata['service']}"

        if "product" in metadata:
            desc_body += f"\nProduct: {metadata['product']}"

        if "version" in metadata:
            desc_body += f"\nVersion: {metadata['version']}"

        if "extrainfo" in metadata:
            desc_body += f"\nExtra Info: {metadata['extrainfo']}"

        if "reason" in metadata:
            desc_body += f"\nReason: {metadata['reason']}"

        if "cpe" in metadata:
            if isinstance(metadata["cpe"], list):
                desc_body += "\n\nCPE:"
                for cpe in metadata["cpe"]:
                    desc_body += f"\n- {cpe}"
            else:
                desc_body += f"\n\nCPE: {metadata['cpe']}"

        if "scripts" in metadata:
            desc_body += "\n\nScript Output:"
            scripts = metadata["scripts"]
            if isinstance(scripts, dict):
                for script_name, output in scripts.items():
                    desc_body += (
                        f"\n\n{script_name}:\n{str(output)}"  # Ensure output is string
                    )

        # Add severity-specific context to the body
        if finding.severity == FindingSeverity.CRITICAL:
            desc_body += (
                "\n\nThis is a CRITICAL finding that requires immediate attention. "
                "The service identified is considered high-risk and may provide "
                "direct access to sensitive systems or data with minimal authentication."
            )
        elif finding.severity == FindingSeverity.HIGH:
            desc_body += (
                "\n\nThis is a HIGH severity finding. The service identified is "
                "considered risky and should be properly secured or disabled if not needed."
            )
        elif finding.severity == FindingSeverity.MEDIUM:
            desc_body += (
                "\n\nThis is a MEDIUM severity finding. The service should be reviewed "
                "to ensure it's properly configured and required for business operations."
            )

        # Combine title and body
        return f"{desc}{desc_body}"
