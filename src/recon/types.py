from dataclasses import dataclass, field
from typing import List, Optional

# Optional: Add fields like resolved IP if enumeration is performed

@dataclass
class DnsRecord:
    """Represents a single DNS record."""
    record_type: str
    value: str
    # Additional fields like TTL could be added if needed


@dataclass
class DnsResults:
    """Holds the results of DNS enumeration for a domain."""
    domain: str
    a_records: List[DnsRecord] = field(default_factory=list)
    aaaa_records: List[DnsRecord] = field(default_factory=list)
    mx_records: List[DnsRecord] = field(default_factory=list)
    ns_records: List[DnsRecord] = field(default_factory=list)
    txt_records: List[DnsRecord] = field(default_factory=list)
    # Add other record types as needed (e.g., CNAME, SOA)

@dataclass
class Subdomain:
    """Represents a discovered subdomain."""
    name: str
    # Optional: Add fields like resolved IP if enumeration is performed

@dataclass
class WhoisInfo:
    """Holds parsed WHOIS information."""
    registrar: Optional[str] = None
    creation_date: Optional[str] = None # Keep as string for simplicity, parsing can be complex
    expiration_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    # Add more fields as needed (e.g., registrant info - CAUTION: PII/GDPR)

# --- Future Recon Data Models --- 

@dataclass
class SslCertInfo:
    """Holds relevant SSL/TLS certificate details."""
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None # Keep as string (ISO format)
    valid_until: Optional[str] = None # Keep as string (ISO format)
    sans: List[str] = field(default_factory=list) # Subject Alternative Names
    # Could add: serial number, signature algorithm, public key info, etc.

@dataclass
class TechInfo:
    """Holds basic technology fingerprinting information."""
    server_header: Optional[str] = None
    powered_by_header: Optional[str] = None
    detected_technologies: List[str] = field(default_factory=list) # e.g., ["Nginx", "PHP"] 

@dataclass
class PortInfo:
    """Holds information about a single open port."""
    port_number: int
    protocol: str # e.g., "tcp", "udp"
    state: str # e.g., "open", "filtered", "closed"
    service_name: Optional[str] = None # e.g., "http", "ssh"
    service_version: Optional[str] = None # e.g., "OpenSSH 8.2p1"
    # Add other nmap fields if needed (reason, product, etc.)

@dataclass
class HostScanResults:
    """Holds the results of scanning a single host (IP or domain)."""
    host: str # IP address or domain name scanned
    status: str # e.g., "up", "down"
    open_ports: List[PortInfo] = field(default_factory=list)

# ... Add other data structures for Ports, etc. ...