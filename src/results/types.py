from enum import Enum
from typing import Any

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
    raw_evidence: Any | None = Field(
        None, description="Raw output or data from the tool for reference."
    )


class PortFinding(BaseFinding):
    """Model for findings related to open ports."""

    port: int = Field(..., description="The network port number.")
    protocol: str = Field("tcp", description="Network protocol (e.g., tcp, udp).")
    service: str | None = Field(
        None, description="Service identified running on the port."
    )
    banner: str | None = Field(
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
    method: str | None = Field(
        None, description="HTTP method associated with the finding (GET, POST, etc.)."
    )
    parameter: str | None = Field(
        None, description="Specific parameter involved, if applicable."
    )
    status_code: int | None = Field(
        None, description="HTTP status code observed, if relevant."
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


# We can add more specific finding types later, e.g.:
# class VulnerabilityFinding(WebFinding):
#     cwe: str | None = None
#     cvss_score: float | None = None
