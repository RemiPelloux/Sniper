import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import List, Optional

import markdown
import typer
from rich.console import Console

from src.reporting.html_generator import HTMLReportGenerator

app = typer.Typer(name="report", help="Generate and manage scan reports.")
log = logging.getLogger(__name__)
console = Console()


class ReportFormat(str, Enum):
    """Supported report formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    ALL = "all"


class ReportTemplate(str, Enum):
    """Available report templates."""

    STANDARD = "standard"
    EXECUTIVE = "executive"
    DETAILED = "detailed"


@app.command("generate")
def generate_report(
    input_file: str = typer.Argument(
        ...,
        help="Input file containing scan results in JSON format.",
    ),
    output_dir: str = typer.Option(
        "./reports",
        "--output-dir",
        "-o",
        help="Directory where reports will be saved.",
    ),
    format: List[ReportFormat] = typer.Option(
        [ReportFormat.MARKDOWN],
        "--format",
        "-f",
        help="Output format(s) for the report.",
    ),
    template: ReportTemplate = typer.Option(
        ReportTemplate.STANDARD,
        "--template",
        "-t",
        help="Report template to use.",
    ),
    include_evidence: bool = typer.Option(
        True,
        "--include-evidence/--no-evidence",
        help="Whether to include detailed evidence in the report.",
    ),
) -> None:
    """Generate a report from scan results.

    This command takes scan results from a JSON file and generates formatted
    reports based on the specified options.
    """
    # Check if input file exists
    if not os.path.isfile(input_file):
        typer.echo(f"Error: Input file '{input_file}' not found.", err=True)
        raise typer.Exit(code=1)

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Load scan results from JSON file
        typer.echo(f"Loading scan results from {input_file}...")
        with open(input_file, "r") as f:
            scan_data = json.load(f)

        # Generate reports in specified formats
        if ReportFormat.ALL in format:
            formats_to_generate = [f for f in ReportFormat if f != ReportFormat.ALL]
        else:
            formats_to_generate = format

        # Process each format
        for report_format in formats_to_generate:
            output_file = os.path.join(
                output_dir,
                f"{os.path.splitext(os.path.basename(input_file))[0]}_{report_format.value}.{report_format.value}",
            )
            typer.echo(f"Generating {report_format.value} report to {output_file}...")

            if report_format == ReportFormat.JSON:
                # For JSON, just pretty-print the data
                with open(output_file, "w") as f:
                    json.dump(scan_data, f, indent=2)
            elif report_format == ReportFormat.HTML:
                # Generate HTML report using our HTML generator
                html_generator = HTMLReportGenerator(template_name=template.value)
                html_generator.generate(
                    scan_data=scan_data,
                    output_file=output_file,
                    include_evidence=include_evidence,
                )
            elif report_format == ReportFormat.MARKDOWN:
                # Generate a markdown report
                with open(output_file, "w") as f:
                    generate_markdown_report(
                        scan_data=scan_data,
                        template=template.value,
                        include_evidence=include_evidence,
                        file=f,
                    )

        typer.echo(f"Report generation complete. Reports saved to {output_dir}")

    except Exception as e:
        typer.echo(f"Error generating report: {str(e)}", err=True)
        log.error(f"Report generation failed: {str(e)}", exc_info=True)
        raise typer.Exit(code=1)


def generate_markdown_report(scan_data, template, include_evidence, file):
    """
    Generate a markdown report from scan data.

    Args:
        scan_data: Dictionary containing scan results
        template: Template name to use
        include_evidence: Whether to include detailed evidence
        file: File object to write to
    """
    metadata = scan_data.get("scan_metadata", {})
    findings = scan_data.get("findings", [])

    # Write report header
    file.write(
        f"# Security Scan Report - {metadata.get('target', 'Unknown Target')}\n\n"
    )
    file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    file.write(f"Template: {template}\n\n")

    # Write metadata
    file.write("## Scan Details\n\n")
    file.write(f"- **Target:** {metadata.get('target', 'Unknown')}\n")
    file.write(f"- **Scan Date:** {metadata.get('timestamp', 'Unknown')}\n")
    file.write(f"- **Duration:** {metadata.get('scan_duration', 'Unknown')}\n")
    file.write(f"- **Tools Used:** {', '.join(metadata.get('tools_used', []))}\n\n")

    # Group findings by severity
    findings_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
    }

    for finding in findings:
        severity = finding.get("severity", "").lower()
        if severity in findings_by_severity:
            findings_by_severity[severity].append(finding)
        else:
            findings_by_severity["info"].append(finding)

    # Write findings sections
    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        if findings_by_severity[severity]:
            file.write(f"## {severity.title()} Severity Findings\n\n")

            for finding in findings_by_severity[severity]:
                file.write(f"### {finding.get('title', 'Untitled Finding')}\n\n")
                file.write(f"- **Location:** {finding.get('location', 'Unknown')}\n")
                file.write(f"- **Type:** {finding.get('type', 'Unknown')}\n")
                file.write(f"- **Confidence:** {finding.get('confidence', 'Medium')}\n")
                if "cve" in finding:
                    file.write(f"- **CVE:** {finding['cve']}\n")
                file.write("\n")

                file.write(
                    f"**Description:** {finding.get('description', 'No description')}\n\n"
                )

                if finding.get("remediation"):
                    file.write(f"**Remediation:** {finding['remediation']}\n\n")

                if include_evidence and finding.get("evidence"):
                    file.write("**Evidence:**\n\n```\n")
                    file.write(finding["evidence"])
                    file.write("\n```\n\n")

                if finding.get("references"):
                    file.write("**References:**\n\n")
                    for ref in finding["references"]:
                        file.write(f"- {ref}\n")
                    file.write("\n")

    # If no findings were found
    if sum(len(findings_by_severity[sev]) for sev in severity_order) == 0:
        file.write("## Findings\n\n")
        file.write("No security issues were found during the scan.\n\n")


@app.command("list-templates")
def list_templates() -> None:
    """List available report templates."""
    console.print("[bold]Available Report Templates:[/bold]")

    templates = {
        ReportTemplate.STANDARD: "Standard template with findings organized by severity",
        ReportTemplate.EXECUTIVE: "Executive summary focused on high-level metrics and critical issues",
        ReportTemplate.DETAILED: "Comprehensive technical report with full details and evidence",
    }

    for template, description in templates.items():
        console.print(f"  [bold cyan]{template.value}[/bold cyan]: {description}")


@app.command("formats")
def list_formats() -> None:
    """List available report formats."""
    console.print("[bold]Available Report Formats:[/bold]")

    formats = {
        ReportFormat.MARKDOWN: "Markdown format (.md) - readable plain text with formatting",
        ReportFormat.HTML: "HTML format (.html) - web page with styling and interactive elements",
        ReportFormat.JSON: "JSON format (.json) - structured data for machine processing",
        ReportFormat.ALL: "Generate reports in all available formats",
    }

    for format, description in formats.items():
        console.print(f"  [bold cyan]{format.value}[/bold cyan]: {description}")
