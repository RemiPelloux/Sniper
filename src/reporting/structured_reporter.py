"""
Structured Report Generator for Sniper Security Platform.

This module is responsible for generating structured reports with a hierarchical folder
organization based on scan results.
"""

import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class StructuredReporter:
    """
    Creates a well-organized folder structure for scan reports with findings
    categorized by severity and type, with a global report at the root.
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the structured reporter.

        Args:
            output_dir: Base directory where all reports will be stored
        """
        self.output_dir = output_dir
        self.templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(self.templates_dir))

    def normalize_target_name(self, target: str) -> str:
        """
        Normalize the target name to be used as a directory name.

        Args:
            target: The target URL or IP

        Returns:
            A normalized string suitable for use as a directory name
        """
        # Remove protocol (http://, https://, etc.)
        normalized = re.sub(r"^https?://", "", target)
        # Remove trailing slashes
        normalized = normalized.rstrip("/")
        # Replace invalid characters with underscores
        normalized = re.sub(r"[^\w\-\.]", "_", normalized)
        # Add timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{normalized}_{timestamp}"

    def create_report_structure(
        self, target: str, findings: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        """
        Create a structured report directory with categorized findings.

        Args:
            target: The target URL or IP
            findings: Dictionary of findings organized by category

        Returns:
            Path to the created report directory
        """
        # Normalize target name for directory
        target_dir_name = self.normalize_target_name(target)
        target_dir = os.path.join(self.output_dir, target_dir_name)

        # Create main directory if it doesn't exist
        os.makedirs(target_dir, exist_ok=True)

        # Create category directories and save findings
        for category, category_findings in findings.items():
            category_dir = os.path.join(target_dir, category)
            os.makedirs(category_dir, exist_ok=True)

            # Save each finding as a separate JSON file
            for i, finding in enumerate(category_findings):
                finding_file = os.path.join(category_dir, f"finding_{i+1}.json")
                with open(finding_file, "w") as f:
                    json.dump(finding, f, indent=2)

            # Create category report HTML
            self._generate_category_report(
                target, category, category_findings, target_dir
            )

        # Generate main report HTML
        self._generate_main_report(target, findings, target_dir)

        logger.info(f"Structured report created at: {target_dir}")
        return target_dir

    def _generate_main_report(
        self, target: str, findings: Dict[str, List[Dict[str, Any]]], target_dir: str
    ):
        """
        Generate the main HTML report at the root of the target directory.

        Args:
            target: The target URL or IP
            findings: Dictionary of findings organized by category
            target_dir: Target directory path
        """
        template = self.jinja_env.get_template("main_report.html")

        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        total_findings = 0
        for category, category_findings in findings.items():
            for finding in category_findings:
                total_findings += 1
                severity = finding.get("severity", "").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Render the template
        html_content = template.render(
            target=target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            severity_counts=severity_counts,
            total_findings=total_findings,
            categories=list(findings.keys()),
        )

        # Write the HTML report
        report_path = os.path.join(target_dir, "index.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        # Copy any assets if needed (CSS, JS, etc.)
        assets_dir = os.path.join(self.templates_dir, "assets")
        if os.path.exists(assets_dir):
            target_assets_dir = os.path.join(target_dir, "assets")
            os.makedirs(target_assets_dir, exist_ok=True)
            for asset in os.listdir(assets_dir):
                src = os.path.join(assets_dir, asset)
                dst = os.path.join(target_assets_dir, asset)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

    def _generate_category_report(
        self,
        target: str,
        category: str,
        findings: List[Dict[str, Any]],
        target_dir: str,
    ):
        """
        Generate a category-specific HTML report.

        Args:
            target: The target URL or IP
            category: The category name
            findings: List of findings for this category
            target_dir: Target directory path
        """
        template = self.jinja_env.get_template("category_report.html")

        # Render the template
        html_content = template.render(
            target=target,
            category=category,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
        )

        # Write the HTML report
        report_path = os.path.join(target_dir, f"{category}.html")
        with open(report_path, "w") as f:
            f.write(html_content)

    def save_scan_results(self, target: str, results: Dict[str, Any]) -> str:
        """
        Process scan results and create a structured report.

        Args:
            target: The target URL or IP
            results: The scan results dictionary

        Returns:
            Path to the created report directory
        """
        # Organize findings by category (severity and type)
        findings = self._categorize_findings(results)

        # Create the report structure with findings
        return self.create_report_structure(target, findings)

    def _categorize_findings(
        self, results: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize findings by severity and type.

        Args:
            results: The scan results dictionary

        Returns:
            Dictionary of findings organized by category
        """
        categories = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
            "vulnerabilities": [],
            "technologies": [],
            "prioritized_urls": [],
            "performance": [],
        }

        # Process vulnerabilities by severity
        if "vulnerabilities" in results:
            for vuln in results["vulnerabilities"]:
                severity = vuln.get("severity", "").lower()
                if severity in categories:
                    categories[severity].append(vuln)
                categories["vulnerabilities"].append(vuln)

        # Process technologies
        if "technologies" in results:
            categories["technologies"] = results["technologies"]

        # Process prioritized URLs
        if "prioritized_urls" in results:
            categories["prioritized_urls"] = [
                {"url": url, "confidence": confidence, "severity": "info"}
                for url, confidence in results["prioritized_urls"].items()
            ]

        # Process performance metrics
        if "performance" in results:
            categories["performance"] = [
                {"metric": key, "value": value, "severity": "info"}
                for key, value in results["performance"].items()
            ]

        # Filter out empty categories
        return {k: v for k, v in categories.items() if v}

    def archive_report(self, report_dir: str, format: str = "zip") -> str:
        """
        Archive the report directory.

        Args:
            report_dir: Path to the report directory
            format: Archive format (zip, tar, etc.)

        Returns:
            Path to the archive file
        """
        if format.lower() == "zip":
            archive_path = f"{report_dir}.zip"
            shutil.make_archive(report_dir, "zip", report_dir)
            return archive_path
        else:
            raise ValueError(f"Unsupported archive format: {format}")


def create_structured_report(
    target: str,
    findings: Dict[str, List[Dict[str, Any]]],
    output_dir: str = "reports",
    scan_info: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Convenience function to create a structured report.

    Args:
        target: The target URL or IP address
        findings: Dictionary of findings categorized by type
        output_dir: Base directory for output reports
        scan_info: Additional information about the scan

    Returns:
        Path to the report root directory
    """
    reporter = StructuredReporter(output_dir)
    return reporter.create_report_structure(target, findings)
