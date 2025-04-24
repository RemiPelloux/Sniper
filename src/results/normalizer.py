"""
Result Normalization System for Sniper CLI.

This module defines the core functionality for standardizing and normalizing
findings from different security tools into a consistent format.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Type, Union, cast

from src.results.types import (
    BaseFinding,
    FindingSeverity,
    PortFinding,
    SubdomainFinding,
    TechnologyFinding,
    WebFinding,
)
from src.core.findings import Finding

log = logging.getLogger(__name__)


class FindingNormalizer:
    """Base class for normalizing findings from a specific tool."""

    def __init__(self, tool_name: str) -> None:
        """Initialize the normalizer for a specific tool.

        Args:
            tool_name: Name of the tool whose findings will be normalized.
        """
        self.tool_name = tool_name

    def normalize(self, raw_findings: List[BaseFinding]) -> List[BaseFinding]:
        """Normalize a list of raw findings from a specific tool.

        This default implementation assumes findings are already in BaseFinding format
        and just performs basic normalization like severity standardization.

        Args:
            raw_findings: List of BaseFinding objects to normalize

        Returns:
            List of normalized BaseFinding objects
        """
        normalized_findings: List[BaseFinding] = []

        for finding in raw_findings:
            # Ensure tool name is set correctly
            if finding.source_tool != self.tool_name:
                finding.source_tool = self.tool_name

            # Apply severity normalization
            finding.severity = self._normalize_severity(finding)

            normalized_findings.append(finding)

        return normalized_findings

    def _normalize_severity(self, finding: BaseFinding) -> FindingSeverity:
        """Normalize the severity of a finding based on predefined rules.

        Override this method in subclasses to implement tool-specific severity mapping.

        Args:
            finding: The finding whose severity needs normalization

        Returns:
            Normalized FindingSeverity
        """
        # Default implementation keeps the severity as is
        return finding.severity


class ResultNormalizer:
    """Main class for normalizing results from multiple tools."""

    def __init__(self) -> None:
        """Initialize the result normalizer."""
        self.normalizers: Dict[str, FindingNormalizer] = {}
        self._register_default_normalizers()

    def _register_default_normalizers(self) -> None:
        """Register default normalizers for built-in tools."""
        try:
            # Import normalizers - using delayed import to avoid circular references
            from src.results.normalizers.nmap_normalizer import NmapFindingNormalizer
            from src.results.normalizers.wappalyzer_normalizer import (
                WappalyzerFindingNormalizer,
            )
            from src.results.normalizers.zap_normalizer import ZAPFindingNormalizer

            # Register the normalizers
            self.register_normalizer(NmapFindingNormalizer())
            self.register_normalizer(WappalyzerFindingNormalizer())
            self.register_normalizer(ZAPFindingNormalizer())

            log.debug("Registered default tool normalizers")
        except ImportError as e:
            log.warning(f"Failed to register some normalizers: {e}")

    def register_normalizer(self, normalizer: FindingNormalizer) -> None:
        """Register a new normalizer for a specific tool.

        Args:
            normalizer: Normalizer instance to register
        """
        self.normalizers[normalizer.tool_name] = normalizer
        log.debug(f"Registered normalizer for {normalizer.tool_name}")

    def normalize_findings(
        self, findings: List[BaseFinding], tool_name: Optional[str] = None
    ) -> List[BaseFinding]:
        """Normalize a list of findings from one or multiple tools.

        Args:
            findings: List of findings to normalize
            tool_name: Optional tool name to filter findings

        Returns:
            List of normalized findings
        """
        if tool_name:
            # Filter findings by tool name
            tool_findings = [f for f in findings if f.source_tool == tool_name]

            # Get the appropriate normalizer
            normalizer = self.normalizers.get(tool_name)
            if normalizer:
                return normalizer.normalize(tool_findings)
            else:
                # Use default normalization if no specific normalizer exists
                default_normalizer = FindingNormalizer(tool_name)
                return default_normalizer.normalize(tool_findings)
        else:
            # Process all findings by grouping them by tool
            tool_groups: Dict[str, List[BaseFinding]] = defaultdict(list)

            for finding in findings:
                tool_groups[finding.source_tool].append(finding)

            # Normalize each group separately
            normalized_findings: List[BaseFinding] = []
            for tool, tool_findings in tool_groups.items():
                normalizer = self.normalizers.get(tool)
                if normalizer:
                    normalized_findings.extend(normalizer.normalize(tool_findings))
                else:
                    # Use default normalization
                    default_normalizer = FindingNormalizer(tool)
                    normalized_findings.extend(
                        default_normalizer.normalize(tool_findings)
                    )

            return normalized_findings

    def deduplicate_findings(self, findings: List[BaseFinding]) -> List[BaseFinding]:
        """Remove duplicate findings based on specific attributes.

        This method identifies and removes duplicate findings, preferring to keep
        findings with more detailed information.

        Args:
            findings: List of findings to deduplicate

        Returns:
            List of deduplicated findings
        """
        # Group findings by type
        findings_by_type: Dict[Type[BaseFinding], List[BaseFinding]] = defaultdict(list)

        for finding in findings:
            findings_by_type[type(finding)].append(finding)

        # Process each type separately using type-specific deduplication
        deduplicated: List[BaseFinding] = []

        # Handle port findings
        port_findings = [
            cast(PortFinding, f)
            for f in findings_by_type.get(PortFinding, [])
            if isinstance(f, PortFinding)
        ]
        deduplicated.extend(self._deduplicate_port_findings(port_findings))

        # Handle web findings
        web_findings = [
            cast(WebFinding, f)
            for f in findings_by_type.get(WebFinding, [])
            if isinstance(f, WebFinding)
        ]
        deduplicated.extend(self._deduplicate_web_findings(web_findings))

        # Handle subdomain findings
        subdomain_findings = [
            cast(SubdomainFinding, f)
            for f in findings_by_type.get(SubdomainFinding, [])
            if isinstance(f, SubdomainFinding)
        ]
        deduplicated.extend(self._deduplicate_subdomain_findings(subdomain_findings))

        # Handle technology findings
        tech_findings = [
            cast(TechnologyFinding, f)
            for f in findings_by_type.get(TechnologyFinding, [])
            if isinstance(f, TechnologyFinding)
        ]
        deduplicated.extend(self._deduplicate_technology_findings(tech_findings))

        # For any other types, just add them as is (no deduplication)
        for finding_type, findings_list in findings_by_type.items():
            if finding_type not in {
                PortFinding,
                WebFinding,
                SubdomainFinding,
                TechnologyFinding,
            }:
                deduplicated.extend(findings_list)

        return deduplicated

    def _deduplicate_port_findings(
        self, findings: List[PortFinding]
    ) -> List[PortFinding]:
        """Deduplicate port findings based on target, port, and protocol.

        Args:
            findings: List of port findings to deduplicate

        Returns:
            List of deduplicated port findings
        """
        # Dictionary to track unique findings by their key attributes
        unique_findings: Dict[tuple, PortFinding] = {}

        for finding in findings:
            # Create a unique key for this port finding
            key = (finding.target, finding.port, finding.protocol)

            if key in unique_findings:
                # Finding exists - keep the one with more information
                existing = unique_findings[key]

                # Update the existing finding if this one has more information
                if (
                    (finding.service and not existing.service)
                    or (finding.banner and not existing.banner)
                    or (finding.severity.value > existing.severity.value)
                ):
                    unique_findings[key] = finding
            else:
                # New unique finding
                unique_findings[key] = finding

        return list(unique_findings.values())

    def _deduplicate_web_findings(self, findings: List[WebFinding]) -> List[WebFinding]:
        """Deduplicate web findings based on URL and method.

        Args:
            findings: List of web findings to deduplicate

        Returns:
            List of deduplicated web findings
        """
        unique_findings: Dict[tuple, WebFinding] = {}

        for finding in findings:
            # Create a unique key for this web finding
            key = (finding.url, finding.method or "")

            if key in unique_findings:
                # Finding exists - prefer the one with higher severity
                existing = unique_findings[key]

                if finding.severity.value > existing.severity.value:
                    unique_findings[key] = finding
            else:
                # New unique finding
                unique_findings[key] = finding

        return list(unique_findings.values())

    def _deduplicate_subdomain_findings(
        self, findings: List[SubdomainFinding]
    ) -> List[SubdomainFinding]:
        """Deduplicate subdomain findings based on the subdomain name.

        Args:
            findings: List of subdomain findings to deduplicate

        Returns:
            List of deduplicated subdomain findings
        """
        unique_findings: Dict[str, SubdomainFinding] = {}

        for finding in findings:
            # Use subdomain as the key
            key = finding.subdomain.lower()  # Case-insensitive comparison

            if key in unique_findings:
                # Keep the finding with more information
                # For subdomains, there's not much difference, so we could keep either
                # For now, prefer the one with higher severity if different
                existing = unique_findings[key]

                if finding.severity.value > existing.severity.value:
                    unique_findings[key] = finding
            else:
                unique_findings[key] = finding

        return list(unique_findings.values())

    def _deduplicate_technology_findings(
        self, findings: List[TechnologyFinding]
    ) -> List[TechnologyFinding]:
        """Deduplicate technology findings based on target and technology name.

        Args:
            findings: List of technology findings to deduplicate

        Returns:
            List of deduplicated technology findings
        """
        unique_findings: Dict[tuple, TechnologyFinding] = {}

        for finding in findings:
            # Create a unique key for this technology finding
            key = (finding.target, finding.technology_name.lower())  # Case-insensitive

            if key in unique_findings:
                # Finding exists - prefer the one with more information
                existing = unique_findings[key]

                # Determine which version to keep (prioritize non-None values)
                version = existing.version
                if finding.version is not None:
                    version = finding.version

                # Create a merged finding with the best properties from both
                merged_finding = TechnologyFinding(
                    technology_name=existing.technology_name,
                    target=existing.target,
                    # Keep version if it exists in either finding, prioritizing the non-None value
                    version=version,
                    # Keep the categories from the original finding
                    categories=existing.categories,
                    # Use the higher severity
                    severity=(
                        finding.severity
                        if finding.severity.value > existing.severity.value
                        else existing.severity
                    ),
                    # Keep other properties from the existing finding
                    description=existing.description,
                    source_tool=existing.source_tool,
                )

                unique_findings[key] = merged_finding
            else:
                # New unique finding
                unique_findings[key] = finding

        return list(unique_findings.values())

    def correlate_findings(
        self, findings: List[Finding]
    ) -> Dict[str, List[Finding]]:
        """Correlate and deduplicate findings.
        
        Args:
            findings: List of findings to correlate
            
        Returns:
            Dictionary mapping target names to lists of findings
        """
        if not findings:
            return {}
            
        # Group findings by target
        grouped_by_target: Dict[str, List[Finding]] = {}
        for finding in findings:
            target_findings = grouped_by_target.setdefault(finding.target, [])
            target_findings.append(finding)
            
        # For each target, group and correlate findings by title
        correlated_by_target: Dict[str, List[Finding]] = {}
        for target, target_findings in grouped_by_target.items():
            # Group by title
            findings_by_title: Dict[str, List[Finding]] = {}
            for finding in target_findings:
                title_findings = findings_by_title.setdefault(finding.title, [])
                title_findings.append(finding)
            
            # Correlate findings with the same title
            correlated_findings = []
            for title_findings in findings_by_title.values():
                if len(title_findings) == 1:
                    correlated_findings.append(title_findings[0])
                else:
                    # Merge multiple findings with the same title
                    correlated_findings.append(self._merge_findings(title_findings))
            
            # Sort findings by severity
            correlated_findings.sort(key=lambda f: f.severity, reverse=True)
            correlated_by_target[target] = correlated_findings
            
        return correlated_by_target

    def _merge_findings(self, findings: List[Finding]) -> Finding:
        """Merge multiple findings into one.
        
        Args:
            findings: List of findings to merge
            
        Returns:
            Merged finding
        """
        # Use the finding with highest severity as base instead of confidence
        base = max(findings, key=lambda f: f.severity)
        
        # Combine descriptions and raw data
        description = base.description
        raw_data = base.raw_data or {}
        
        for finding in findings:
            if finding != base:
                # Use source_tool instead of tool which might not exist on BaseFinding
                source = getattr(finding, 'source_tool', 'unknown tool')
                description += f"\n\nAlso reported by {source}:\n{finding.description}"
                if hasattr(finding, 'raw_data') and finding.raw_data:
                    raw_data.update(finding.raw_data)
        
        # Handle confidence attribute which may not exist on BaseFinding
        confidence = getattr(base, 'confidence', None)
                    
        return Finding(
            title=base.title,
            description=description,
            severity=base.severity,
            confidence=confidence,
            target=base.target,
            tool=f"{getattr(base, 'source_tool', 'multiple tools')} (correlated)",
            raw_data=raw_data
        )
