import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class HTMLReportRenderer:
    """
    HTML Report Renderer for generating comprehensive security scan reports.

    This renderer creates a complete HTML report structure with:
    - Main index page showing findings summary by category
    - Category-specific pages showing all findings in a category
    - Detailed pages for each individual finding
    """

    def __init__(self, template_dir: str = None):
        """
        Initialize the HTML report renderer.

        Args:
            template_dir: Directory containing HTML templates. If None, uses the default
                         templates directory in the reporting module.
        """
        if template_dir is None:
            # Use default template directory relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(current_dir, "templates")

        self.template_dir = template_dir
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Add filters if needed
        self.env.filters["pprint"] = self._pretty_format

    def _pretty_format(self, value: Any) -> str:
        """Format complex objects for display in templates."""
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, sort_keys=True)
        return str(value)

    def _prepare_output_directory(self, output_dir: str) -> None:
        """
        Prepare the output directory structure.

        Args:
            output_dir: Path to the output directory
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Create directories for categorized findings
        os.makedirs(os.path.join(output_dir, "findings"), exist_ok=True)

        # Copy static assets if they exist
        static_dir = os.path.join(self.template_dir, "static")
        if os.path.exists(static_dir):
            output_static_dir = os.path.join(output_dir, "static")
            os.makedirs(output_static_dir, exist_ok=True)
            for item in os.listdir(static_dir):
                src = os.path.join(static_dir, item)
                dst = os.path.join(output_static_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)

    def _categorize_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings by category.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping categories to lists of findings
        """
        categorized = {}

        for finding in findings:
            # Get the category, defaulting to "other" if not present
            category = finding.get("category", "other").lower()

            if category not in categorized:
                categorized[category] = []

            categorized[category].append(finding)

        return categorized

    def _count_findings_by_severity(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Count findings by severity level.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping severity levels to counts
        """
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1
            else:
                # If unknown severity, count as info
                counts["info"] += 1

        return counts

    def _generate_main_report(
        self,
        output_dir: str,
        target: str,
        scan_date: str,
        categorized_findings: Dict[str, List[Dict[str, Any]]],
        severity_counts: Dict[str, int],
    ) -> None:
        """
        Generate the main index.html report.

        Args:
            output_dir: Output directory path
            target: Target that was scanned
            scan_date: Date of the scan
            categorized_findings: Findings grouped by category
            severity_counts: Counts of findings by severity
        """
        template = self.env.get_template("main_report.html")

        # Create category summaries
        categories = []
        for category, findings in categorized_findings.items():
            categories.append(
                {
                    "name": category,
                    "count": len(findings),
                    "file": f"findings/{category}.html",
                    "findings": findings[:3],  # Preview up to 3 findings
                    "severity_counts": self._count_findings_by_severity(findings),
                }
            )

        # Sort categories by count (descending)
        categories.sort(key=lambda x: x["count"], reverse=True)

        # Render the template
        html = template.render(
            target=target,
            scan_date=scan_date,
            categories=categories,
            severity_counts=severity_counts,
            total_findings=sum(severity_counts.values()),
        )

        # Write to index.html
        with open(os.path.join(output_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)

    def _generate_category_reports(
        self,
        output_dir: str,
        target: str,
        scan_date: str,
        categorized_findings: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        """
        Generate individual category reports.

        Args:
            output_dir: Output directory path
            target: Target that was scanned
            scan_date: Date of the scan
            categorized_findings: Findings grouped by category
        """
        template = self.env.get_template("category_report.html")

        for category, findings in categorized_findings.items():
            # Sort findings by severity (critical first, then high, etc.)
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            findings.sort(
                key=lambda x: severity_order.get(x.get("severity", "info").lower(), 999)
            )

            # Render the template
            html = template.render(
                category=category, findings=findings, target=target, scan_date=scan_date
            )

            # Write to category file
            category_file = os.path.join(output_dir, "findings", f"{category}.html")
            with open(category_file, "w", encoding="utf-8") as f:
                f.write(html)

    def _generate_finding_details(
        self,
        output_dir: str,
        target: str,
        scan_date: str,
        categorized_findings: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        """
        Generate detailed pages for individual findings.

        Args:
            output_dir: Output directory path
            target: Target that was scanned
            scan_date: Date of the scan
            categorized_findings: Findings grouped by category
        """
        template = self.env.get_template("detail_report.html")

        # Create directories for each category
        for category, findings in categorized_findings.items():
            category_dir = os.path.join(output_dir, "findings", category)
            os.makedirs(category_dir, exist_ok=True)

            for i, finding in enumerate(findings):
                # Create a unique ID for the finding if it doesn't have one
                finding_id = finding.get("id", f"{i+1}")

                # Render the template
                html = template.render(
                    finding=finding,
                    target=target,
                    scan_date=scan_date,
                    category=category,
                    category_page=f"{category}.html",
                )

                # Write to detail file
                detail_file = os.path.join(category_dir, f"{finding_id}.html")
                with open(detail_file, "w", encoding="utf-8") as f:
                    f.write(html)

    def render(
        self,
        findings: List[Dict[str, Any]],
        output_dir: str,
        target: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Render the full HTML report from findings data.

        Args:
            findings: List of finding dictionaries
            output_dir: Directory where the report will be saved
            target: Target that was scanned
            metadata: Additional metadata for the report

        Returns:
            Path to the generated index.html file
        """
        if not findings:
            logger.warning("No findings to report")
            findings = []

        # Get metadata
        metadata = metadata or {}
        scan_date = metadata.get(
            "scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # Prepare output directory
        self._prepare_output_directory(output_dir)

        # Categorize findings
        categorized_findings = self._categorize_findings(findings)

        # Count findings by severity
        severity_counts = self._count_findings_by_severity(findings)

        # Generate main report
        self._generate_main_report(
            output_dir=output_dir,
            target=target,
            scan_date=scan_date,
            categorized_findings=categorized_findings,
            severity_counts=severity_counts,
        )

        # Generate category reports
        self._generate_category_reports(
            output_dir=output_dir,
            target=target,
            scan_date=scan_date,
            categorized_findings=categorized_findings,
        )

        # Generate finding details
        self._generate_finding_details(
            output_dir=output_dir,
            target=target,
            scan_date=scan_date,
            categorized_findings=categorized_findings,
        )

        # Return the path to the main report file
        report_path = os.path.join(output_dir, "index.html")
        logger.info(f"HTML report generated at {report_path}")
        return report_path
