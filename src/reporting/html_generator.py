"""
HTML Report Generator Module.

This module provides functionality to generate HTML reports using Jinja2 templates.
It supports different report templates for various reporting needs including standard,
executive, and detailed technical reports.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.results.types import BaseFinding


class HTMLReportGenerator:
    """Generates HTML reports using Jinja2 templates."""

    TEMPLATE_DIR = Path(__file__).parent / "templates"

    def __init__(self, template_name: str = "standard"):
        """
        Initialize the HTML report generator.

        Args:
            template_name: Name of the template to use (standard, executive, detailed)
        """
        self.template_name = template_name
        self.env = Environment(
            loader=FileSystemLoader(self.TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(
        self, scan_data: Dict[str, Any], output_file: str, include_evidence: bool = True
    ) -> str:
        """
        Generate an HTML report from scan data.

        Args:
            scan_data: Dictionary containing scan results and metadata
            output_file: Path where the HTML report will be saved
            include_evidence: Whether to include detailed evidence in the report

        Returns:
            Path to the generated HTML report file
        """
        # Prepare data for the template
        template_data = self._prepare_template_data(scan_data, include_evidence)

        # Render the template
        template = self.env.get_template(f"{self.template_name}.html")
        rendered_html = template.render(**template_data)

        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

        # Write the rendered HTML to the output file
        with open(output_file, "w") as f:
            f.write(rendered_html)

        return output_file

    def _prepare_template_data(
        self, scan_data: Dict[str, Any], include_evidence: bool
    ) -> Dict[str, Any]:
        """
        Prepare data for the template.

        Args:
            scan_data: Dictionary containing scan results and metadata
            include_evidence: Whether to include detailed evidence

        Returns:
            Dictionary containing prepared data for the template
        """
        # Get basic scan metadata
        metadata = scan_data.get("scan_metadata", {})
        findings = scan_data.get("findings", [])

        # Group findings by severity
        findings_by_severity = self._group_findings_by_severity(findings)

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        # Format dates and timestamps
        timestamp = metadata.get("timestamp")
        formatted_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if timestamp:
            try:
                formatted_date = datetime.fromisoformat(timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except (ValueError, TypeError):
                pass

        return {
            "title": f"Security Scan Report - {metadata.get('target', 'Unknown Target')}",
            "generation_date": formatted_date,
            "report_type": self.template_name.capitalize(),
            "metadata": metadata,
            "findings": findings,
            "findings_by_severity": findings_by_severity,
            "stats": stats,
            "include_evidence": include_evidence,
            "generator_version": "1.0.0",  # Version of the report generator
        }

    def _group_findings_by_severity(
        self, findings: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """
        Group findings by severity level.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary with severity levels as keys and lists of findings as values
        """
        result = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

        for finding in findings:
            severity = finding.get("severity", "").lower()
            if severity in result:
                result[severity].append(finding)
            else:
                result["info"].append(finding)

        return result

    def _calculate_statistics(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate statistics about findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary containing statistics about findings
        """
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Count by severity
        for finding in findings:
            severity = finding.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["info"] += 1

        # Count by type
        type_counts = {}
        for finding in findings:
            finding_type = finding.get("type", "Unknown")
            if finding_type in type_counts:
                type_counts[finding_type] += 1
            else:
                type_counts[finding_type] = 1

        return {
            "total": len(findings),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "risk_score": self._calculate_risk_score(severity_counts),
        }

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """
        Calculate overall risk score based on severity counts.

        Args:
            severity_counts: Dictionary with severity levels as keys and counts as values

        Returns:
            Risk score between 0 and 10
        """
        # Weights for different severity levels
        weights = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0.5}

        # Calculate weighted sum
        weighted_sum = sum(
            severity_counts[severity] * weights[severity]
            for severity in severity_counts
        )

        # Calculate maximum possible score (if all findings were critical)
        total_findings = sum(severity_counts.values())
        max_score = total_findings * weights["critical"] if total_findings > 0 else 1

        # Calculate normalized score (0-10)
        normalized_score = (weighted_sum / max_score) * 10 if max_score > 0 else 0

        return round(normalized_score, 1)
