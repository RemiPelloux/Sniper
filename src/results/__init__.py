"""Results module for Sniper CLI.

This module handles the standardization, normalization and processing
of findings from various security tools.
"""

# Export finding types for easy import
from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    SubdomainFinding,
    TechnologyFinding,
    WebFinding,
)

# Export normalizers
from src.results.normalizer import FindingNormalizer, ResultNormalizer

# Export all
__all__ = [
    # Finding types
    "BaseFinding",
    "FindingSeverity",
    "PortFinding",
    "SubdomainFinding",
    "TechnologyFinding",
    "WebFinding",
    # Normalizers
    "FindingNormalizer",
    "ResultNormalizer",
] 