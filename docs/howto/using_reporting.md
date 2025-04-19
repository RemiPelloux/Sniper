# How to Use the Reporting Module

This document explains how to generate and customize reports in Sniper.

## Generating Reports

Reports are typically generated after a scan is completed. You can also generate reports for historical scans.

### Generating a Report for the Last Scan

```bash
sniper report generate
```

This command will generate a report for the most recently completed scan using the default template and output format (usually HTML).

### Generating a Report for a Specific Scan

```bash
sniper report generate <scan_id> --format <format> --template <template_name> --output <output_file>
```

-   `<scan_id>`: The ID of the scan to report on.
-   `--format`: Specify the output format (e.g., `html`, `pdf`, `json`, `csv`).
-   `--template`: Specify a custom report template name (see Customization section).
-   `--output`: Specify the path to save the generated report file.

### Listing Available Report Formats and Templates

```bash
sniper report list-formats
sniper report list-templates
```

## Report Structure

Reports typically include:
-   Scan summary (target, time, duration).
-   Executive summary (key findings, overall risk).
-   Detailed findings (vulnerabilities, issues, informational findings).
-   Evidence and reproduction steps.
-   Remediation recommendations.
-   ML insights (if applicable).
-   Compliance mapping (if configured).

## Customizing Reports

Sniper allows for report customization through templates.

### Report Templates

Report templates are located in the `src/reporting/templates/` directory. Sniper likely uses a templating engine like Jinja2.

-   **Default Templates**: Pre-defined templates exist for different formats (HTML, PDF, etc.).
-   **Custom Templates**: You can create your own templates by adding new files to the templates directory.
    -   Copy an existing template as a starting point.
    -   Modify the structure, styling, and content placeholders.
    -   Use the `--template <your_template_name>` option when generating reports.

### Template Variables

Templates have access to scan data, including:
-   Scan metadata (ID, target, start/end time).
-   Configuration used for the scan.
-   List of `Finding` objects.
-   Correlated findings.
-   ML predictions and insights.
-   Compliance information.

Refer to the existing templates and the `src/reporting/` module code for available variables and data structures.

## Configuration

Default reporting behavior can be set in `config/default.yml`:

```yaml
reporting:
  default_format: html
  default_template: standard
  output_directory: reports/
``` 