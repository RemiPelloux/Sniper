# Scan Results Visualization

This directory contains tools to visualize the results from Sniper Security Tool's autonomous tests.

## Quick Start

To visualize results from a sample scan, run:

```bash
python visualize_results.py --input-file sample_result.json --output-format html
```

This will generate an HTML report with visualizations of the vulnerabilities found.

## Available Options

The `visualize_results.py` script supports multiple input sources, output formats, and visualization options:

### Input Sources:
- `--input-file PATH`: Load results from a JSON file
- `--task-id ID --master-host HOST --master-port PORT`: Fetch results from a master node

### Output Formats:
- `--output-format FORMAT`: Choose from html, pdf, csv, json, or text (default: text)
- `--output-file PATH`: Specify the output file path (default: console output for text, auto-generated filename for other formats)

### Visualization Options:
- `--show-graphs`: Generate and display graphs (default when using html or pdf output)
- `--include-requests`: Include detailed request information in the report

## Examples

1. Generate a text summary to the console:
```bash
python visualize_results.py --input-file sample_result.json
```

2. Generate an HTML report with graphs:
```bash
python visualize_results.py --input-file sample_result.json --output-format html --output-file report.html
```

3. Generate a CSV of just the vulnerabilities:
```bash
python visualize_results.py --input-file sample_result.json --output-format csv --output-file vulnerabilities.csv
```

4. Fetch results from a master node and generate a PDF report:
```bash
python visualize_results.py --task-id task-123456 --master-host localhost --master-port 8000 --output-format pdf
```

## Sample Data

The `sample_result.json` file contains example data to demonstrate the visualization capabilities. It includes:
- 10 sample vulnerabilities of various types and severities
- Sample request information
- Basic scan metrics

Use this file to test the visualization script and understand the expected format of scan results. 