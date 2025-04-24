"""
Structured Reports Module

This module handles the creation of structured reports with organized folder hierarchies
for security scan findings. It creates a main folder named after the target domain/IP,
with subfolders for each category of findings, and generates both individual category
reports and a final global report at the root of the main folder.
"""

import datetime
import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import jinja2

# Configure logging
logger = logging.getLogger(__name__)

# Default categories for organizing findings
DEFAULT_CATEGORIES = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "prioritized_urls",
    "technologies",
    "performance",
]


def normalize_target_name(target: str) -> str:
    """
    Normalize a target URL or IP to create a valid folder name.

    Args:
        target: The target URL or IP address

    Returns:
        A normalized string suitable for use as a folder name
    """
    # Remove protocol (http://, https://)
    target = re.sub(r"^https?://", "", target)

    # Remove trailing slashes
    target = target.rstrip("/")

    # Replace invalid characters with underscores
    target = re.sub(r'[\\/*?:"<>|]', "_", target)

    # Replace dots with underscores for better folder naming
    target = target.replace(".", "_")

    return target


def create_report_structure(
    target: str, output_dir: str = "reports", categories: Optional[List[str]] = None
) -> Dict[str, str]:
    """
    Create a structured report directory hierarchy.

    Args:
        target: The target URL or IP address
        output_dir: The base output directory for reports
        categories: List of categories to create folders for

    Returns:
        Dictionary mapping category names to their respective folder paths
    """
    if categories is None:
        categories = DEFAULT_CATEGORIES

    # Create a normalized target name for the folder
    target_name = normalize_target_name(target)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir = os.path.join(output_dir, f"{target_name}_{timestamp}")

    # Create the main target directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)

    # Create subdirectories for each category
    category_paths = {}
    for category in categories:
        category_dir = os.path.join(target_dir, category)
        os.makedirs(category_dir, exist_ok=True)
        category_paths[category] = category_dir

    logger.info(f"Created report structure at {target_dir}")

    return {"base_dir": target_dir, "categories": category_paths}


def save_finding_to_category(
    finding: Dict[str, Any], category: str, structure: Dict[str, Any]
) -> str:
    """
    Save a finding to its appropriate category folder.

    Args:
        finding: The finding data
        category: The category the finding belongs to
        structure: The report structure dictionary from create_report_structure

    Returns:
        The path to the saved finding file
    """
    if category not in structure["categories"]:
        logger.warning(
            f"Category {category} not found in report structure. Creating it."
        )
        category_dir = os.path.join(structure["base_dir"], category)
        os.makedirs(category_dir, exist_ok=True)
        structure["categories"][category] = category_dir

    category_dir = structure["categories"][category]

    # Generate a filename based on the finding
    finding_id = finding.get("id", finding.get("title", None))
    if finding_id is None:
        # Use timestamp if no id or title is available
        finding_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    # Normalize the filename
    filename = re.sub(r'[\\/*?:"<>|]', "_", str(finding_id))
    filename = f"{filename}.json"
    file_path = os.path.join(category_dir, filename)

    # Save the finding as JSON
    with open(file_path, "w") as f:
        json.dump(finding, f, indent=2)

    logger.debug(f"Saved finding to {file_path}")

    return file_path


def categorize_finding(finding: Dict[str, Any]) -> str:
    """
    Determine the category for a finding based on its attributes.

    Args:
        finding: The finding data

    Returns:
        The category name
    """
    # Check if finding has an explicit category
    if "category" in finding:
        return finding["category"]

    # Categorize by severity if available
    if "severity" in finding:
        severity = finding["severity"].lower()
        if severity in DEFAULT_CATEGORIES:
            return severity

    # Check for other specific attributes
    if "technology" in finding or "technologies" in finding:
        return "technologies"

    if "prioritized" in finding or "priority" in finding:
        return "prioritized_urls"

    if "performance" in finding:
        return "performance"

    # Default to info category
    return "info"


def generate_category_report(
    category: str,
    structure: Dict[str, Any],
    template_path: str = "src/reporting/templates/category_report.html",
    target: str = "",
) -> str:
    """
    Generate an HTML report for a specific category.

    Args:
        category: The category to generate a report for
        structure: The report structure dictionary from create_report_structure
        template_path: Path to the Jinja2 template for category reports
        target: The target URL or domain

    Returns:
        Path to the generated HTML report
    """
    category_dir = structure["categories"].get(category)
    if not category_dir:
        logger.warning(f"Category {category} not found in report structure")
        return ""

    # Load findings from the category directory
    findings = []
    for filename in os.listdir(category_dir):
        if filename.endswith(".json"):
            file_path = os.path.join(category_dir, filename)
            with open(file_path, "r") as f:
                try:
                    finding = json.load(f)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode JSON from {file_path}")

    # Sort findings by severity if available, otherwise by title
    findings.sort(
        key=lambda x: (
            x.get("severity", "LOWEST"),  # Sort by severity first
            x.get("title", ""),  # Then by title
        )
    )

    # Load the template
    try:
        template_loader = jinja2.FileSystemLoader(
            searchpath=os.path.dirname(template_path)
        )
        template_env = jinja2.Environment(loader=template_loader)
        template = template_env.get_template(os.path.basename(template_path))
    except Exception as e:
        logger.error(f"Failed to load template {template_path}: {e}")
        # Fallback to a basic template
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ category_name }} Report</title>
        </head>
        <body>
            <h1>{{ category_name }} Report</h1>
            <p>Target: {{ target }}</p>
            <p>Generated: {{ timestamp }}</p>
            <h2>Findings ({{ findings|length }})</h2>
            {% for finding in findings %}
            <div>
                <h3>{{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
            </div>
            {% endfor %}
        </body>
        </html>
        """
        template = jinja2.Template(template_str)

    # Render the template
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = template.render(
        category=category,
        category_name=category.replace("_", " ").title(),
        findings=findings,
        target=target,
        timestamp=timestamp,
    )

    # Save the HTML report
    report_path = os.path.join(structure["base_dir"], f"{category}.html")
    with open(report_path, "w") as f:
        f.write(html_content)

    logger.info(f"Generated category report at {report_path}")

    return report_path


def generate_main_report(
    structure: Dict[str, Any],
    target: str,
    template_path: str = "src/reporting/templates/main_report.html",
    scan_metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate the main HTML report that links to all category reports.

    Args:
        structure: The report structure dictionary from create_report_structure
        target: The target URL or domain
        template_path: Path to the Jinja2 template for the main report
        scan_metadata: Additional metadata about the scan

    Returns:
        Path to the generated HTML report
    """
    # Collect statistics for each category
    category_stats = {}
    finding_stats = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    # Collect findings for the executive summary
    key_findings = []

    for category, category_dir in structure["categories"].items():
        # Count JSON files in the category directory
        count = len([f for f in os.listdir(category_dir) if f.endswith(".json")])
        category_stats[category] = count

        # Update finding statistics based on category
        if category in finding_stats:
            finding_stats[category] = count
            finding_stats["total"] += count

        # For critical and high findings, collect them for the executive summary
        if category in ["critical", "high"]:
            for filename in os.listdir(category_dir):
                if filename.endswith(".json"):
                    file_path = os.path.join(category_dir, filename)
                    with open(file_path, "r") as f:
                        try:
                            finding = json.load(f)
                            # Add category to the finding for reference
                            finding["category"] = category
                            key_findings.append(finding)
                        except json.JSONDecodeError:
                            logger.error(f"Failed to decode JSON from {file_path}")

    # Sort key findings by severity
    key_findings.sort(key=lambda x: x.get("severity", "LOWEST"))

    # Load the template
    try:
        template_loader = jinja2.FileSystemLoader(
            searchpath=os.path.dirname(template_path)
        )
        template_env = jinja2.Environment(loader=template_loader)
        template = template_env.get_template(os.path.basename(template_path))
    except Exception as e:
        logger.error(f"Failed to load template {template_path}: {e}")
        # Fallback to a basic template
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {{ target }}</title>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Target: {{ target }}</p>
            <p>Generated: {{ timestamp }}</p>
            <h2>Findings Summary</h2>
            <p>Total: {{ finding_stats.total }}</p>
            <ul>
                {% for category, count in category_stats.items() %}
                <li>{{ category }}: {{ count }}</li>
                {% endfor %}
            </ul>
        </body>
        </html>
        """
        template = jinja2.Template(template_str)

    # Prepare metadata
    if scan_metadata is None:
        scan_metadata = {}

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_metadata.update({"timestamp": timestamp, "target": target})

    # Render the template
    html_content = template.render(
        target=target,
        timestamp=timestamp,
        category_stats=category_stats,
        finding_stats=finding_stats,
        key_findings=key_findings,
        metadata=scan_metadata,
    )

    # Save the HTML report
    report_path = os.path.join(structure["base_dir"], "index.html")
    with open(report_path, "w") as f:
        f.write(html_content)

    logger.info(f"Generated main report at {report_path}")

    return report_path


def create_structured_report(
    findings: List[Dict[str, Any]],
    target: str,
    output_dir: str = "reports",
    scan_metadata: Optional[Dict[str, Any]] = None,
    main_template: str = "src/reporting/templates/main_report.html",
    category_template: str = "src/reporting/templates/category_report.html",
) -> str:
    """
    Create a complete structured report from a list of findings.

    Args:
        findings: List of finding dictionaries
        target: The target URL or domain
        output_dir: Base directory for reports
        scan_metadata: Additional metadata about the scan
        main_template: Path to the main report template
        category_template: Path to the category report template

    Returns:
        Path to the generated main report
    """
    # Create the report structure
    structure = create_report_structure(target, output_dir)

    # Categorize and save each finding
    for finding in findings:
        category = categorize_finding(finding)
        save_finding_to_category(finding, category, structure)

    # Generate reports for each category
    for category in structure["categories"]:
        generate_category_report(
            category, structure, template_path=category_template, target=target
        )

    # Generate the main report
    main_report_path = generate_main_report(
        structure, target, template_path=main_template, scan_metadata=scan_metadata
    )

    logger.info(f"Created structured report at {main_report_path}")

    return main_report_path
