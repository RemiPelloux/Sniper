#!/usr/bin/env python
"""
Example script to demonstrate HTML report generation.

This script loads example scan data and generates HTML reports using
different templates to showcase the reporting capabilities.
"""

import json
import os
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reporting.html_generator import HTMLReportGenerator


def generate_reports():
    """Generate HTML reports using different templates."""
    # Get the path to the example scan results
    script_dir = Path(__file__).parent
    input_file = script_dir / "scan_results.json"
    output_dir = script_dir / "reports"

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    print(f"Loading scan data from {input_file}")

    try:
        # Load the scan data
        with open(input_file, "r") as f:
            scan_data = json.load(f)

        # Generate reports with different templates
        templates = ["standard", "executive", "detailed"]

        for template in templates:
            print(f"Generating {template} HTML report...")

            # Create the HTML generator with the specified template
            generator = HTMLReportGenerator(template_name=template)

            # Generate the report
            output_file = output_dir / f"{template}_report.html"
            generator.generate(
                scan_data=scan_data, output_file=str(output_file), include_evidence=True
            )

            print(f"  Report saved to {output_file}")

        print(f"\nAll reports have been generated in {output_dir}")
        print("Open these HTML files in a web browser to view the reports.")

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(generate_reports())
