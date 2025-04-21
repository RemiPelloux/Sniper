from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Standardized severity levels for findings."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class BaseFinding(BaseModel):
    """Base model for all findings."""

    title: str = Field(..., description="Concise title summarizing the finding.")
    description: str = Field(
        ..., description="Detailed description of the finding and its implications."
    )
    severity: FindingSeverity = Field(..., description="Severity level of the finding.")
    target: str = Field(
        ...,
        description="The specific target (URL, IP, domain) related to this finding.",
    )
    source_tool: str = Field(
        ..., description="Name of the tool that generated this finding."
    )
    raw_evidence: Optional[Any] = Field(
        None, description="Raw output or data from the tool for reference."
    )


class PortFinding(BaseFinding):
    """Model for findings related to open ports."""

    port: int = Field(..., description="The network port number.")
    protocol: str = Field("tcp", description="Network protocol (e.g., tcp, udp).")
    service: Optional[str] = Field(
        None, description="Service identified running on the port."
    )
    banner: Optional[str] = Field(
        None, description="Service banner information, if available."
    )

    # Example customization for title
    def __init__(self, **data: Any):
        if "title" not in data:
            data["title"] = (
                f"Open Port: {data.get('port')}/{data.get('protocol', 'tcp')}"
            )
        super().__init__(**data)


class WebFinding(BaseFinding):
    """Model for findings related to web paths or vulnerabilities."""

    url: str = Field(..., description="Specific URL where the finding occurred.")
    method: Optional[str] = Field(
        None, description="HTTP method associated with the finding (GET, POST, etc.)."
    )
    parameter: Optional[str] = Field(
        None, description="Specific parameter involved, if applicable."
    )
    status_code: Optional[int] = Field(
        None, description="HTTP status code observed, if relevant."
    )
    evidence: Optional[str] = Field(
        None, description="Specific evidence of the vulnerability."
    )

    # Example customization for title
    def __init__(self, **data: Any):
        if "title" not in data:
            path = data.get("url", "").split("//", 1)[-1].split("/", 1)[-1]
            status = data.get("status_code")
            title_parts = [f"Web Path Found: /{path}"]
            if status:
                title_parts.append(f"(Status: {status})")
            data["title"] = " ".join(title_parts)
        super().__init__(**data)


class SubdomainFinding(BaseFinding):
    """Model for discovered subdomains."""

    subdomain: str = Field(..., description="The discovered subdomain name.")

    # Example customization for title
    def __init__(self, **data: Any):
        if "title" not in data:
            data["title"] = f"Subdomain Found: {data.get('subdomain')}"
        super().__init__(**data)


class TechnologyFinding(BaseFinding):
    """Model for detected technologies on a web target."""

    technology_name: str = Field(..., description="Name of the detected technology.")
    version: Optional[str] = Field(
        None, description="Detected version of the technology."
    )
    categories: List[str] = Field(
        default_factory=list, description="Categories the technology belongs to."
    )
    # Wappalyzer often provides confidence scores, could add later
    # confidence: Optional[int] = Field(None, description="Confidence score (0-100)")

    def __init__(self, **data: Any):
        if "title" not in data:
            tech_name = data.get("technology_name", "Unknown Technology")
            version_str = f" (v{data['version']})" if data.get("version") else ""
            data["title"] = f"Technology Detected: {tech_name}{version_str}"
        if "severity" not in data:
            # Technology detection is usually informational
            data["severity"] = FindingSeverity.INFO
        if "description" not in data:
            tech_name = data.get("technology_name", "Unknown")
            version_str = f"version {data['version']} " if data.get("version") else ""
            cat_str = (
                f" (Categories: {', '.join(data.get('categories', []))})"
                if data.get("categories")
                else ""
            )
            data["description"] = (
                f"Detected {tech_name} {version_str}on {data.get('target')}.{cat_str}"
            )
        super().__init__(**data)


# We can add more specific finding types later, e.g.:
# class VulnerabilityFinding(WebFinding):
#     cwe: Optional[str] = None
#     cvss_score: Optional[float] = None


class ScanResult(BaseModel):
    """Model representing a complete scan result."""

    scan_id: str = Field(..., description="Unique identifier for the scan.")
    target: str = Field(..., description="Target of the scan (domain, IP, etc.).")
    start_time: Optional[datetime] = Field(None, description="When the scan started.")
    end_time: Optional[datetime] = Field(None, description="When the scan completed.")
    findings: List[BaseFinding] = Field(
        default_factory=list, description="List of findings from the scan."
    )
    raw_results: Dict[str, Any] = Field(
        default_factory=dict, description="Raw tool outputs by tool name."
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None, description="Additional metadata about the scan."
    )
