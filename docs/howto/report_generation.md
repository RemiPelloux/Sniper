# Report Generation with Sniper

This guide explains how to generate, customize, and work with security reports in Sniper.

## Report Basics

Sniper can generate comprehensive security reports in various formats, providing detailed information about vulnerabilities, findings, and recommendations.

### Basic Report Generation

Generate a basic report after a scan:

```bash
# Run a scan and generate a report
sniper scan -t example.com --output-format html --output-file report.html

# Generate a report from an existing scan
sniper report generate --scan-id abc123 --format html --output report.html
```

### Supported Report Formats

Sniper supports multiple report formats:

```bash
# HTML report (interactive, with details and visuals)
sniper report generate --scan-id abc123 --format html --output report.html

# JSON report (machine-readable)
sniper report generate --scan-id abc123 --format json --output report.json

# Markdown report (human-readable text)
sniper report generate --scan-id abc123 --format markdown --output report.md

# PDF report (professional document)
sniper report generate --scan-id abc123 --format pdf --output report.pdf

# CSV report (tabular data for spreadsheets)
sniper report generate --scan-id abc123 --format csv --output findings.csv

# XML report (for integration with other tools)
sniper report generate --scan-id abc123 --format xml --output report.xml
```

### Report Templates

Use different report templates for different audiences:

```bash
# Executive summary (high-level overview)
sniper report generate --scan-id abc123 --template executive --output exec_summary.html

# Technical report (detailed technical information)
sniper report generate --scan-id abc123 --template technical --output technical_report.html

# Compliance report (focused on standards compliance)
sniper report generate --scan-id abc123 --template compliance --output compliance_report.html

# Remediation report (focused on fixes)
sniper report generate --scan-id abc123 --template remediation --output remediation_plan.html
```

## Customizing Reports

### Setting Report Metadata

Add custom metadata to reports:

```bash
# Set report title
sniper report generate --scan-id abc123 --title "Security Assessment - Example.com"

# Add author information
sniper report generate --scan-id abc123 --author "Security Team"

# Add company information
sniper report generate --scan-id abc123 --company "Your Company" --logo /path/to/logo.png

# Add confidentiality notice
sniper report generate --scan-id abc123 --confidentiality "Confidential - Internal Use Only"
```

### Content Selection

Control what content appears in the report:

```bash
# Include only specific sections
sniper report generate --scan-id abc123 --sections summary,findings,recommendations

# Include only findings of certain severity
sniper report generate --scan-id abc123 --min-severity high

# Filter by finding type
sniper report generate --scan-id abc123 --finding-types xss,sqli,csrf

# Exclude certain findings by ID
sniper report generate --scan-id abc123 --exclude-findings finding-001,finding-002

# Include evidence details
sniper report generate --scan-id abc123 --include-evidence

# Include remediation details
sniper report generate --scan-id abc123 --include-remediation
```

### Visual Customization

Customize the look and feel of HTML and PDF reports:

```bash
# Use a custom CSS file
sniper report generate --scan-id abc123 --format html --custom-css /path/to/style.css

# Use a custom theme
sniper report generate --scan-id abc123 --theme dark

# Set custom colors
sniper report generate --scan-id abc123 --primary-color "#4a86e8" --secondary-color "#34a853"

# Customize chart appearance
sniper report generate --scan-id abc123 --chart-type doughnut --chart-colors "#e53935,#fb8c00,#fdd835,#43a047,#3949ab"
```

## Advanced Reporting Features

### Executive Summary Generation

Create an executive summary highlighting key findings and risks:

```bash
# Generate an executive summary
sniper report executive-summary --scan-id abc123 --output exec_summary.html

# Customize executive summary
sniper report executive-summary --scan-id abc123 --risk-focus --business-impact --output exec_summary.html
```

### Comparison Reports

Compare results between different scans:

```bash
# Compare two scans
sniper report compare --scan-id1 abc123 --scan-id2 def456 --output comparison.html

# Filter comparison to show only differences
sniper report compare --scan-id1 abc123 --scan-id2 def456 --show-diff-only --output comparison.html

# Compare with previous scan of the same target
sniper report compare-with-previous --scan-id abc123 --output comparison.html
```

### Historical Trending

Generate trend reports to track security posture over time:

```bash
# Generate a trend report for a target
sniper report trend --target example.com --period 90d --output trend_report.html

# Specify metrics to track
sniper report trend --target example.com --metrics total_findings,critical,high --output trend_report.html
```

### Compliance Reporting

Generate reports focused on compliance standards:

```bash
# Generate an OWASP Top 10 compliance report
sniper report compliance --scan-id abc123 --standard owasp-top10-2021 --output owasp_compliance.html

# Generate a PCI DSS compliance report
sniper report compliance --scan-id abc123 --standard pci-dss --output pci_compliance.html

# Generate a NIST compliance report
sniper report compliance --scan-id abc123 --standard nist-800-53 --output nist_compliance.html

# Generate multiple compliance reports
sniper report compliance --scan-id abc123 --standards owasp-top10-2021,pci-dss --output compliance.html
```

## Programmatic Report Generation

### Using the CLI API

Generate reports programmatically with the CLI:

```bash
# Generate a report with a predefined configuration
sniper report generate --scan-id abc123 --config-file report_config.yaml

# Save the current report configuration for reuse
sniper report save-config --output report_config.yaml
```

### Using the REST API

Generate reports via the REST API:

```bash
# API endpoint for report generation
curl -X POST "https://your-sniper-api.com/api/v1/scans/{scan_id}/export" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "html",
    "template": "technical",
    "options": {
      "title": "Security Assessment Report",
      "min_severity": "medium",
      "include_evidence": true
    }
  }' --output report.html
```

## Custom Report Templates

### Using Built-in Templates

List and use built-in report templates:

```bash
# List available templates
sniper report list-templates

# Get template details
sniper report template-info --template technical

# Use a specific template
sniper report generate --scan-id abc123 --template technical --output report.html
```

### Creating Custom Templates

Create your own report templates:

```bash
# Create a new template based on an existing one
sniper report create-template --name custom_template --base technical

# Export a template for editing
sniper report export-template --template technical --output technical_template_files/

# Import a custom template
sniper report import-template --name my_custom_template --path my_template_files/
```

Templates use the Jinja2 templating language. For HTML templates, you can customize:

- HTML structure
- CSS styling
- JavaScript for interactive elements
- Charts and visualizations

## Working with Report Data

### Extracting Specific Data

Extract specific information from reports:

```bash
# Extract findings to CSV
sniper report extract --scan-id abc123 --field findings --output findings.csv

# Extract specific finding fields
sniper report extract --scan-id abc123 --field "findings.title,findings.severity,findings.location" --output finding_details.csv

# Extract summary metrics
sniper report extract --scan-id abc123 --field summary --output summary.json
```

### Data Manipulation

Transform report data for further analysis:

```bash
# Group findings by type
sniper report transform --scan-id abc123 --group-by type --output grouped_findings.json

# Aggregate findings by severity
sniper report transform --scan-id abc123 --aggregate-by severity --output severity_counts.json

# Sort findings by a specific field
sniper report transform --scan-id abc123 --sort-by risk_score --output sorted_findings.json
```

## Sharing Reports

### Exporting Reports

Export reports in different formats for sharing:

```bash
# Export to PDF (suitable for sharing)
sniper report generate --scan-id abc123 --format pdf --output report.pdf

# Create a ZIP archive with multiple report formats
sniper report export-all --scan-id abc123 --formats html,pdf,json --output report_package.zip

# Export with sensitive information redacted
sniper report generate --scan-id abc123 --redact-sensitive --output redacted_report.html
```

### Report Delivery

Automate report delivery:

```bash
# Send a report via email
sniper report email --scan-id abc123 --recipients "security@example.com,manager@example.com" --format pdf

# Upload a report to a file sharing service
sniper report upload --scan-id abc123 --service s3 --bucket reports --format html

# Send to an integration
sniper report send --scan-id abc123 --integration jira --project SEC
```

## Example Report Workflows

### Basic Security Assessment

```bash
# Run a scan and generate a comprehensive report
sniper scan -t example.com --output-format html --output-file comprehensive_report.html

# Generate a technical report and an executive summary
sniper report generate --scan-id abc123 --template technical --output technical_report.html
sniper report executive-summary --scan-id abc123 --output executive_summary.html
```

### Compliance Audit

```bash
# Generate compliance-focused reports for multiple standards
sniper report compliance --scan-id abc123 --standards owasp-top10-2021,pci-dss,gdpr --output compliance_report.html

# Generate a detailed report highlighting compliance issues
sniper report generate --scan-id abc123 --template compliance --sections summary,compliance,findings,recommendations --output detailed_compliance.html
```

### DevSecOps Integration

```bash
# Generate a machine-readable report for CI/CD pipeline
sniper report generate --scan-id abc123 --format json --output-file scan_results.json

# Generate a trend report to track security improvements
sniper report trend --target example.com --period 90d --output security_trend.html

# Generate a comparison with the previous scan
sniper report compare-with-previous --scan-id abc123 --output regression_check.html
```

### Custom Branded Report for Clients

```bash
# Generate a professional client-ready report
sniper report generate --scan-id abc123 \
  --format pdf \
  --template executive \
  --title "Security Assessment - Example.com" \
  --company "Your Security Company" \
  --logo /path/to/company_logo.png \
  --confidentiality "Confidential - Client Eyes Only" \
  --output client_report.pdf
```

## Troubleshooting

### Common Report Issues

1. **Missing Information**:
   ```bash
   # Ensure all evidence is included
   sniper report generate --scan-id abc123 --include-evidence
   ```

2. **Large Report Files**:
   ```bash
   # Reduce file size by limiting evidence details
   sniper report generate --scan-id abc123 --evidence-detail minimal
   
   # Split large reports into sections
   sniper report generate --scan-id abc123 --split-sections
   ```

3. **Custom Template Issues**:
   ```bash
   # Validate a custom template
   sniper report validate-template --path my_template_files/
   
   # Debug template rendering
   sniper report generate --scan-id abc123 --template my_custom_template --debug-template
   ```

### Report Generation Logs

Access logs for troubleshooting:

```bash
# Enable debug logging for report generation
sniper report generate --scan-id abc123 --log-level debug --log-file report_generation.log

# View report generation logs
sniper logs --component reporting
```

## Next Steps

After mastering report generation, you may want to explore:

- [Finding Analysis](finding_analysis.md) for understanding and triaging findings
- [Configuration Guide](configuration.md) for customizing Sniper's behavior
- [API Usage](api_usage.md) for programmatic report generation 