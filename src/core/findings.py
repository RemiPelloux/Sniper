"""Core findings module for scan results."""

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Base class for all findings."""

    title: str
    description: str
    severity: Severity
    confidence: int
    target: str
    tool: str
    raw_data: Optional[Dict[str, Any]] = None

    class Config:
        """Pydantic model configuration."""

        use_enum_values = True
