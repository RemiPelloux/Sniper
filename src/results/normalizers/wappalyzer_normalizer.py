"""
Wappalyzer findings normalizer for Sniper CLI.

This module defines the normalizer for Wappalyzer technology detection findings.
"""

import logging
import re
from typing import Dict, List, Optional, Set

from src.results.normalizer import FindingNormalizer
from src.results.types import BaseFinding, FindingSeverity, TechnologyFinding

log = logging.getLogger(__name__)


class WappalyzerFindingNormalizer(FindingNormalizer):
    """Normalizer for Wappalyzer technology detection findings."""

    def __init__(self) -> None:
        """Initialize the Wappalyzer normalizer."""
        super().__init__("wappalyzer")

        # Define high-risk technologies or outdated versions
        self.high_risk_techs: Set[str] = {
            "wordpress",
            "joomla",
            "drupal",
            "magento",  # Common CMS platforms often targeted
            "apache",
            "nginx",
            "iis",  # Web servers
            "php",
            "asp.net",  # Server-side technologies
            "jquery",  # Common JavaScript libraries that might be outdated
        }

        # Define known vulnerable version patterns
        self.vulnerable_version_patterns: Dict[str, List[str]] = {
            "wordpress": [r"^[1-4]\.", r"^5\.[0-7]\."],  # WordPress < 5.8
            "php": [r"^5\.", r"^7\.[0-3]\."],  # PHP < 7.4
            "apache": [r"^1\.", r"^2\.[0-3]\."],  # Apache < 2.4
            "nginx": [r"^0\.", r"^1\.[0-9]\."],  # Nginx < 1.10
            "jquery": [r"^1\.", r"^2\."],  # jQuery < 3.0
            "drupal": [r"^[1-7]\."],  # Drupal < 8.0
            "joomla": [r"^[1-2]\."],  # Joomla < 3.0
        }

        # Define category-based severity
        self.category_severity_map: Dict[str, FindingSeverity] = {
            "cms": FindingSeverity.MEDIUM,
            "e-commerce": FindingSeverity.MEDIUM,
            "web servers": FindingSeverity.LOW,
            "databases": FindingSeverity.MEDIUM,
            "security": FindingSeverity.LOW,
            "javascript frameworks": FindingSeverity.LOW,
            "default": FindingSeverity.INFO,
        }

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """Normalize severity based on technology type and version.

        For Wappalyzer findings, severity is determined by:
        1. Known vulnerable versions
        2. High-risk technologies
        3. Technology category
        4. Default to INFO

        Args:
            finding: The finding to normalize

        Returns:
            Normalized FindingSeverity
        """
        if not isinstance(finding, TechnologyFinding):
            return FindingSeverity.INFO

        tech_name = finding.technology_name.lower()

        # Check for known vulnerable versions
        if finding.version and tech_name in self.vulnerable_version_patterns:
            for pattern in self.vulnerable_version_patterns[tech_name]:
                if re.match(pattern, finding.version):
                    return FindingSeverity.HIGH

        # Check if it's a high-risk technology
        for high_risk_tech in self.high_risk_techs:
            if high_risk_tech in tech_name:
                return FindingSeverity.MEDIUM

        # Check category-based severity
        for category in finding.categories:
            category_lower = category.lower()
            for known_category, severity in self.category_severity_map.items():
                if known_category in category_lower:
                    return severity

        # Default severity
        return FindingSeverity.INFO

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """Normalize a list of Wappalyzer findings.

        Args:
            raw_findings: List of Wappalyzer findings (as TechnologyFinding objects)

        Returns:
            List of normalized technology findings
        """
        normalized_findings = []

        for finding in raw_findings:
            if not isinstance(finding, TechnologyFinding):
                log.warning(
                    f"Non-TechnologyFinding found in Wappalyzer results: {finding}"
                )
                continue

            # Set standard source tool
            finding.source_tool = self.tool_name

            # Apply severity normalization
            finding.severity = self._normalize_severity(finding)

            # Normalize description to ensure consistency
            finding.description = self._normalize_description(finding)

            # Normalize title
            finding.title = self._normalize_title(finding)

            normalized_findings.append(finding)

        return normalized_findings

    def _normalize_description(self, finding: TechnologyFinding) -> str:
        """Create a standardized description for technology findings.

        Args:
            finding: The technology finding

        Returns:
            Normalized description
        """
        tech_name = finding.technology_name
        target = finding.target
        version_info = f" version {finding.version}" if finding.version else ""
        categories_str = (
            f" (Categories: {', '.join(finding.categories)})"
            if finding.categories
            else ""
        )

        description = f"Detected {tech_name}{version_info} on {target}.{categories_str}"

        # Add risk context based on severity
        if finding.severity == FindingSeverity.HIGH:
            description += f" This appears to be an outdated version of {tech_name} with known vulnerabilities."
        elif finding.severity == FindingSeverity.MEDIUM:
            description += f" This technology is commonly targeted by attackers and should be properly secured."

        return description

    def _normalize_title(self, finding: TechnologyFinding) -> str:
        """Create a standardized title for technology findings.

        Args:
            finding: The technology finding

        Returns:
            Normalized title
        """
        tech_name = finding.technology_name
        version_str = f" (v{finding.version})" if finding.version else ""

        # Add severity indicator for higher risk findings
        if finding.severity == FindingSeverity.HIGH:
            return f"Outdated Technology: {tech_name}{version_str}"
        elif finding.severity == FindingSeverity.MEDIUM:
            return f"Sensitive Technology: {tech_name}{version_str}"
        else:
            return f"Technology Detected: {tech_name}{version_str}"
