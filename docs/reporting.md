# Sniper Reporting Module

## Overview

The Sniper Reporting Module allows you to generate comprehensive security scan reports in various formats, including HTML, Markdown, and JSON. The module supports different templates and customization options to meet your specific reporting needs.

## Report Formats

The following report formats are supported:

- **HTML**: Generates visually appealing web pages with interactive elements
- **Markdown**: Creates plain text reports with structured formatting
- **JSON**: Provides raw structured data for programmatic processing

## Report Templates

Three pre-defined templates are available:

1. **Standard**: The default template that organizes findings by severity with essential details
2. **Executive**: A management-focused template with high-level metrics and risk assessments
3. **Detailed**: A comprehensive technical report with full finding details and remediation guidance

## Using the CLI Command

To generate reports using the command-line interface:

```bash
# Generate an HTML report with the standard template
sniper report generate results.json --format html --template standard

# Generate multiple formats at once
sniper report generate results.json --format html --format markdown

# Generate all supported formats
sniper report generate results.json --format all

# Choose a specific template
sniper report generate results.json --format html --template executive

# Exclude detailed evidence from the report
sniper report generate results.json --format html --no-evidence
```

To list available templates:

```bash
sniper report list-templates
```

To list available formats:

```bash
sniper report formats
```

## Using the HTML Report Generator Programmatically

You can also use the HTML Report Generator directly in your Python code:

```python
from src.reporting.html_generator import HTMLReportGenerator

# Create an HTML generator with a specific template
generator = HTMLReportGenerator(template_name="executive")

# Load scan data
with open("scan_results.json", "r") as f:
    scan_data = json.load(f)

# Generate the HTML report
output_file = "report.html"
generator.generate(
    scan_data=scan_data,
    output_file=output_file,
    include_evidence=True
)
```

## Examples

Example files have been provided to help you get started with the reporting module:

1. **Example scan results**: `/examples/scan_results.json` contains a sample dataset with various types of security findings across different severity levels.

2. **Report generation script**: `/examples/generate_report.py` demonstrates how to programmatically generate HTML reports with different templates.

To run the example script:

```bash
cd /path/to/sniper
poetry run python examples/generate_report.py
```

This will generate three HTML reports (standard, executive, and detailed) in the `/examples/reports/` directory. Open these HTML files in a web browser to see how each template presents the same scan data differently.

## Customizing Reports

### Templating

The reporting module uses Jinja2 templates which are located in the `src/reporting/templates` directory:

- `base.html`: The base template that defines the overall structure and styling
- `standard.html`, `executive.html`, `detailed.html`: The specific templates for each report type
- `partials/finding_card.html`: A reusable component for displaying individual findings

To create a custom template:

1. Create a new HTML file in the templates directory (e.g., `custom.html`)
2. Extend the base template: `{% extends "base.html" %}`
3. Override the content block to customize the report layout
4. Add the template name to the `ReportTemplate` enum in `src/cli/report.py`

## Report Data Structure

The reports are generated based on a standard JSON data structure:

```json
{
  "scan_metadata": {
    "target": "https://example.com",
    "timestamp": "2023-06-15T10:30:00Z",
    "scan_duration": "00:15:30",
    "tools_used": ["nmap", "zap", "wappalyzer"]
  },
  "findings": [
    {
      "title": "SQL Injection Vulnerability",
      "severity": "critical",
      "type": "vulnerability",
      "description": "SQL injection vulnerability found in login form",
      "location": "/login.php",
      "confidence": "high",
      "evidence": "POST parameter 'username' is vulnerable to SQL injection",
      "remediation": "Use prepared statements and parameterized queries",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection"
      ]
    },
    // Additional findings...
  ]
}
```

## Template Features

The HTML templates include several features to enhance the reports:

- **Responsive Design**: Reports adapt to different screen sizes
- **Interactive Elements**: Collapsible sections for detailed findings
- **Severity Color Coding**: Visual indicators for different severity levels
- **Risk Scoring**: Automatic calculation of overall risk scores
- **Statistics Visualization**: Summary metrics for quick assessment
- **Evidence Inclusion/Exclusion**: Option to include or exclude detailed evidence

## Extending the Reporting Module

To extend the reporting module with new capabilities:

1. Add new templates to support different report styles
2. Implement additional output formats (e.g., PDF, CSV)
3. Create custom data processing functions in `HTMLReportGenerator`
4. Add visualizations or charts for better data representation 