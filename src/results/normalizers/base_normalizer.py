"""
Base Normalizer Module

This module provides the abstract base class for all result normalizers in the Sniper
security scanning tool. Normalizers are responsible for converting tool-specific output
formats into a standardized format that can be consistently processed and reported.

The BaseNormalizer defines the interface that all concrete normalizers must implement
to ensure consistency across different tool integrations.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from src.results.types import BaseFinding

logger = logging.getLogger(__name__)


class BaseNormalizer(ABC):
    """
    Abstract base class for all finding normalizers.

    A normalizer is responsible for converting tool-specific findings
    into standardized BaseFinding objects that can be consistently
    processed and reported by the Sniper platform.
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """
        Return the name of the tool this normalizer handles.

        Returns:
            str: The name of the associated security tool.
        """
        pass

    @abstractmethod
    def normalize(self, raw_findings: Any) -> List[BaseFinding]:
        """
        Normalize raw findings from a security tool into standard BaseFinding objects.

        Args:
            raw_findings: Tool-specific findings in their original format.
                          The type varies based on the tool's output format.

        Returns:
            List[BaseFinding]: A list of normalized findings.

        Raises:
            ValueError: If the input format is invalid or cannot be processed.
        """
        pass

    def normalize_severity(
        self,
        original_severity: Union[str, int, float],
        severity_mapping: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Normalize the severity level from tool-specific values to standardized levels.

        Args:
            original_severity: The severity as reported by the tool.
            severity_mapping: Optional mapping from tool-specific to standard severities.

        Returns:
            str: One of the standardized severity levels ("critical", "high", "medium",
                 "low", "info").
        """
        # Default mapping if none provided
        if severity_mapping is None:
            severity_mapping = {
                # String-based mappings
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
                "informational": "info",
                # Common numeric mappings (assuming 0-4 scale)
                "4": "critical",
                "3": "high",
                "2": "medium",
                "1": "low",
                "0": "info",
            }

        # Convert numeric values to strings for mapping
        if isinstance(original_severity, (int, float)):
            original_severity = str(original_severity)

        # Convert to lowercase for case-insensitive matching
        if isinstance(original_severity, str):
            orig_lower = original_severity.lower()

            # Try direct mapping
            if orig_lower in severity_mapping:
                return severity_mapping[orig_lower]

            # Try matching substrings for common patterns
            for key, value in severity_mapping.items():
                if key in orig_lower:
                    return value

        # If no match found, default to "info" and log a warning
        logger.warning(
            f"Unrecognized severity level '{original_severity}', defaulting to 'info'"
        )
        return "info"

    def create_id(self, finding: Dict[str, Any]) -> str:
        """
        Create a unique identifier for a finding based on its attributes.

        Args:
            finding: Dictionary containing the finding data.

        Returns:
            str: A unique identifier for the finding.
        """
        # Create a unique ID based on tool, title and target
        # This is a simple implementation that can be overridden by subclasses
        tool = finding.get("tool", self.tool_name)
        title = finding.get("title", "unknown")
        target = finding.get("target", "unknown")

        # Remove any troublesome characters
        title = title.replace(" ", "_").replace("/", "_").replace("\\", "_")
        target = target.replace(" ", "_").replace("/", "_").replace("\\", "_")

        return f"{tool}_{title}_{target}"

    def __repr__(self) -> str:
        """Return string representation of the normalizer."""
        return f"{self.__class__.__name__}(tool={self.tool_name})"
