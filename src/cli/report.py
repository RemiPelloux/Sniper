import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pathlib import Path

import markdown
import typer
from rich.console import Console
from rich.table import Table

from src.reporting.html_generator import HTMLReportGenerator
from src.reporting.html_report_renderer import HTMLReportRenderer

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


@app.command("generate-html")
def generate_html_report(
    findings_file: str = typer.Argument(..., help="Path to JSON file containing findings data"),
    output_dir: str = typer.Option("./reports", help="Directory to save the report"),
    target: str = typer.Option(None, help="Target that was scanned (defaults to filename if not specified)"),
):
    """
    Generate an HTML report from findings data.
    """
    try:
        # Validate input file
        findings_path = Path(findings_file)
        if not findings_path.exists():
            console.print(f"[bold red]Error:[/bold red] File {findings_file} not found")
            raise typer.Exit(1)
        
        # Load findings data
        with open(findings_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                console.print(f"[bold red]Error:[/bold red] {findings_file} is not a valid JSON file")
                raise typer.Exit(1)
        
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
            console.print(f"[bold red]Error:[/bold red] Invalid findings data format")
            raise typer.Exit(1)
        
        # Default target to filename if not specified
        if target is None:
            target = findings_path.stem
        
        # Ensure metadata has scan_date
        if "scan_date" not in metadata:
            metadata["scan_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize the renderer
        renderer = HTMLReportRenderer()
        
        # Generate the report
        console.print(f"Generating HTML report from {len(findings)} findings...")
        report_path = renderer.render(
            findings=findings,
            output_dir=str(output_path),
            target=target,
            metadata=metadata
        )
        
        # Print success message
        console.print(f"[bold green]Success:[/bold green] Report generated at [link=file://{os.path.abspath(report_path)}]{report_path}[/link]")
        
        # Show summary table
        if findings:
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
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
            
            # Create severity table
            severity_table = Table("Severity", "Count")
            severity_colors = {
                "critical": "bright_red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "grey70"
            }
            
            for severity, count in severity_counts.items():
                if count > 0:
                    severity_table.add_row(
                        f"[{severity_colors.get(severity, 'white')}]{severity.upper()}[/{severity_colors.get(severity, 'white')}]",
                        str(count)
                    )
            
            # Create category table
            category_table = Table("Category", "Count")
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                category_table.add_row(category.title(), str(count))
            
            # Output tables
            console.print("\n[bold]Findings by Severity:[/bold]")
            console.print(severity_table)
            
            console.print("\n[bold]Findings by Category:[/bold]")
            console.print(category_table)
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to generate report: {str(e)}")
        logger.exception("Report generation failed")
        raise typer.Exit(1)


@app.command("list")
def list_reports(
    report_dir: str = typer.Argument("./reports", help="Directory containing reports"),
):
    """
    List available reports in the specified directory.
    """
    try:
        report_path = Path(report_dir)
        if not report_path.exists():
            console.print(f"[bold yellow]Warning:[/bold yellow] Report directory {report_dir} does not exist")
            raise typer.Exit(0)
        
        reports = []
        
        # Find all index.html files one level deep
        for item in report_path.iterdir():
            if item.is_dir():
                index_file = item / "index.html"
                if index_file.exists():
                    reports.append((item.name, index_file))
        
        # Also check for index.html in the root directory
        root_index = report_path / "index.html"
        if root_index.exists():
            reports.append(("latest", root_index))
        
        if not reports:
            console.print("No reports found")
            raise typer.Exit(0)
        
        # Create and display table
        table = Table("Report", "Path", "Last Modified")
        for name, path in reports:
            modified_time = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(
                name,
                f"[link=file://{path.absolute()}]{str(path)}[/link]",
                modified_time
            )
        
        console.print("[bold]Available Reports:[/bold]")
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to list reports: {str(e)}")
        logger.exception("Listing reports failed")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
