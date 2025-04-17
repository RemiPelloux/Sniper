"""
Nmap findings normalizer for Sniper CLI.

This module defines the normalizer for Nmap port scan findings.
"""

import logging
from typing import Dict, List, Optional

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity, PortFinding

log = logging.getLogger(__name__)


class NmapFindingNormalizer(FindingNormalizer):
    """Normalizer for Nmap port scanning findings."""
    
    def __init__(self) -> None:
        """Initialize the Nmap normalizer."""
        super().__init__("nmap")
        # Define service-based severity mappings
        self.service_severity_map: Dict[str, FindingSeverity] = {
            # Common high-risk services 
            "ssh": FindingSeverity.MEDIUM,
            "telnet": FindingSeverity.HIGH,
            "ftp": FindingSeverity.MEDIUM,
            "mysql": FindingSeverity.HIGH,
            "mssql": FindingSeverity.HIGH,
            "oracle": FindingSeverity.HIGH,
            "postgres": FindingSeverity.HIGH,
            "mongodb": FindingSeverity.HIGH,
            "redis": FindingSeverity.HIGH,
            "memcached": FindingSeverity.HIGH,
            "vnc": FindingSeverity.HIGH,
            "rdp": FindingSeverity.HIGH,
            # Common web services
            "http": FindingSeverity.MEDIUM,
            "https": FindingSeverity.LOW,
            # Default for other services
            "default": FindingSeverity.INFO,
        }
        
        # Define port-based severity mappings
        self.port_severity_map: Dict[int, FindingSeverity] = {
            # SSH port
            22: FindingSeverity.MEDIUM,
            # Telnet port 
            23: FindingSeverity.HIGH,
            # FTP ports
            20: FindingSeverity.MEDIUM,
            21: FindingSeverity.MEDIUM,
            # Database ports
            1433: FindingSeverity.HIGH,  # MSSQL
            1521: FindingSeverity.HIGH,  # Oracle
            3306: FindingSeverity.HIGH,  # MySQL
            5432: FindingSeverity.HIGH,  # PostgreSQL
            27017: FindingSeverity.HIGH, # MongoDB
            6379: FindingSeverity.HIGH,  # Redis
            11211: FindingSeverity.HIGH, # Memcached
            # Remote access ports
            3389: FindingSeverity.HIGH,  # RDP
            5900: FindingSeverity.HIGH,  # VNC
            # Web ports
            80: FindingSeverity.MEDIUM,  # HTTP
            443: FindingSeverity.LOW,    # HTTPS
            8080: FindingSeverity.MEDIUM, # HTTP alt
            8443: FindingSeverity.LOW,   # HTTPS alt
        }
    
    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """Normalize severity based on port and service information.
        
        For Nmap findings, severity is determined by:
        1. The service running on the port (if known)
        2. The port number itself
        3. Default to INFO if neither matches
        
        Args:
            finding: The finding to normalize
            
        Returns:
            Normalized FindingSeverity
        """
        if not isinstance(finding, PortFinding):
            return FindingSeverity.INFO
            
        # Check service first (more specific)
        if finding.service:
            service_lower = finding.service.lower()
            
            # Look for known service patterns
            for known_service, severity in self.service_severity_map.items():
                if known_service in service_lower:
                    return severity
        
        # Check port number next            
        if finding.port in self.port_severity_map:
            return self.port_severity_map[finding.port]
            
        # Default severity for unrecognized ports
        return FindingSeverity.INFO
        
    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """Normalize a list of Nmap findings.
        
        Args:
            raw_findings: List of Nmap findings (as PortFinding objects)
            
        Returns:
            List of normalized port findings
        """
        normalized_findings = []
        
        for finding in raw_findings:
            if not isinstance(finding, PortFinding):
                log.warning(f"Non-PortFinding found in Nmap results: {finding}")
                continue
                
            # Set standard source tool
            finding.source_tool = self.tool_name
            
            # Apply severity normalization
            finding.severity = self._normalize_severity(finding)
            
            # Normalize description to ensure consistency
            finding.description = self._normalize_description(finding)
            
            normalized_findings.append(finding)
            
        return normalized_findings
    
    def _normalize_description(self, finding: PortFinding) -> str:
        """Create a standardized description for port findings.
        
        Args:
            finding: The port finding
            
        Returns:
            Normalized description
        """
        description_parts = [f"Port {finding.port}/{finding.protocol} is open"]
        
        if finding.service:
            description_parts.append(f"running {finding.service}")
            
        if finding.banner:
            # Limit banner length to avoid overly long descriptions
            banner = finding.banner
            if len(banner) > 100:
                banner = banner[:97] + "..."
            description_parts.append(f"with banner: {banner}")
        
        description = " ".join(description_parts) + "."
        
        # Add risk context based on severity
        if finding.severity == FindingSeverity.HIGH:
            description += " This service may present a significant security risk if exposed."
        elif finding.severity == FindingSeverity.MEDIUM:
            description += " This service should be properly secured if exposed."
            
        return description 