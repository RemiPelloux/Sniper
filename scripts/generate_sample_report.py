#!/usr/bin/env python3
"""
Generate a sample HTML security report using the HTMLReportRenderer.

This script loads sample findings data from a JSON file and generates
a complete HTML report with the new HTMLReportRenderer.

Usage:
    python3 generate_sample_report.py [input_json] [output_dir]

Arguments:
    input_json - Path to JSON file containing findings (default: examples/sample_findings.json)
    output_dir - Directory to save the report (default: reports/sample)
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to the Python path so we can import our modules
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from src.reporting.html_report_renderer import HTMLReportRenderer

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    # Parse command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = os.path.join(project_root, "examples", "sample_findings.json")

    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    else:
        output_dir = os.path.join(project_root, "reports", "sample")

    # Ensure input file exists
    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    logger.info(f"Loading findings from: {input_file}")

    # Load findings data
    with open(input_file, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON file: {e}")
            sys.exit(1)

    # Extract findings and metadata
    findings = []
    metadata = {}

    if isinstance(data, dict):
        # Handle structured data with metadata
        findings = data.get("findings", [])
        metadata = {k: v for k, v in data.items() if k != "findings"}
    elif isinstance(data, list):
        # Handle simple list of findings
        findings = data
    else:
        logger.error(f"Invalid findings data format")
        sys.exit(1)

    # Get target from metadata or use default
    target = metadata.get("target", "example.com")

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Initialize the renderer
    renderer = HTMLReportRenderer()

    # Generate the report
    logger.info(f"Generating HTML report with {len(findings)} findings...")

    try:
        report_path = renderer.render(
            findings=findings, output_dir=output_dir, target=target, metadata=metadata
        )
        logger.info(f"Report generated successfully at: {report_path}")
        logger.info(f"Full report directory: {os.path.abspath(output_dir)}")

        # Print summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        categories = {}

        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["info"] += 1

            # Count by category
            category = finding.get("category", "other").lower()
            if category not in categories:
                categories[category] = 0
            categories[category] += 1

        logger.info("Findings by Severity:")
        for severity, count in severity_counts.items():
            if count > 0:
                logger.info(f"  {severity.upper()}: {count}")

        logger.info("Findings by Category:")
        for category, count in sorted(
            categories.items(), key=lambda x: x[1], reverse=True
        ):
            if count > 0:
                logger.info(f"  {category}: {count}")

    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
