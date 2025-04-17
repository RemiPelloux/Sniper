import logging
import os
import json
from datetime import datetime
from enum import Enum
from typing import List, Optional

import typer
from rich.console import Console

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
        "--output-dir", "-o",
        help="Directory where reports will be saved.",
    ),
    format: List[ReportFormat] = typer.Option(
        [ReportFormat.MARKDOWN],
        "--format", "-f",
        help="Output format(s) for the report.",
    ),
    template: ReportTemplate = typer.Option(
        ReportTemplate.STANDARD,
        "--template", "-t",
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
                f"{os.path.splitext(os.path.basename(input_file))[0]}_{report_format.value}.{report_format.value}"
            )
            typer.echo(f"Generating {report_format.value} report to {output_file}...")
            
            # Placeholder for actual report generation
            # In a full implementation, this would call format-specific functions
            with open(output_file, "w") as f:
                if report_format == ReportFormat.JSON:
                    # For JSON, just pretty-print the data
                    json.dump(scan_data, f, indent=2)
                else:
                    # For other formats, just write a placeholder
                    f.write(f"# {report_format.value.upper()} Report\n\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write(f"Template: {template.value}\n")
                    f.write(f"Include Evidence: {include_evidence}\n\n")
                    f.write("Report content would be generated here.")
        
        typer.echo(f"Report generation complete. Reports saved to {output_dir}")
        
    except Exception as e:
        typer.echo(f"Error generating report: {str(e)}", err=True)
        log.error(f"Report generation failed: {str(e)}", exc_info=True)
        raise typer.Exit(code=1)


@app.command("list-templates")
def list_templates() -> None:
    """List available report templates."""
    console.print("[bold]Available Report Templates:[/bold]")
    
    templates = {
        ReportTemplate.STANDARD: "Standard template with findings organized by severity",
        ReportTemplate.EXECUTIVE: "Executive summary focused on high-level metrics and critical issues",
        ReportTemplate.DETAILED: "Comprehensive technical report with full details and evidence"
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
        ReportFormat.ALL: "Generate reports in all available formats"
    }
    
    for format, description in formats.items():
        console.print(f"  [bold cyan]{format.value}[/bold cyan]: {description}")
