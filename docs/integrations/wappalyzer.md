# Wappalyzer Integration

This document explains the integration between Sniper and Wappalyzer, a tool for detecting technologies used on websites.

## Features

- Detects web technologies (CMS, frameworks, libraries, servers, etc.)
- Leverages the `wappalyzer` Python package which uses the official Wappalyzer browser extension logic.
- Supports different scan types (`fast`, `balanced`, `full`) for trade-offs between speed and accuracy.

## Prerequisites

For the Wappalyzer integration to work, you need:

1. The `wappalyzer` Python package installed:
   ```bash
   # Install via Poetry (recommended)
   poetry install --extras "wappalyzer"
   
   # Or install directly
   pip install wappalyzer
   ```

2. **Firefox browser installed.**

3. **Mozilla geckodriver installed and available in your system PATH.**
   - Download from: [https://github.com/mozilla/geckodriver/releases](https://github.com/mozilla/geckodriver/releases)
   - Follow installation instructions for your OS (usually involves placing the executable in a directory included in your PATH, like `/usr/local/bin` on Linux/macOS).

## Configuration

No specific configuration is required in `.env` or environment variables for basic operation. The integration uses the `wappalyzer` executable found in the PATH.

## Usage Examples

### Basic Command Line Usage

```bash
# Run a default (full) Wappalyzer scan against a target
sniper scan -t https://example.com --tools wappalyzer

# Run a faster, less comprehensive scan
sniper scan -t https://example.com --tools wappalyzer --options wappalyzer:scan_type=fast

# Increase the number of threads
sniper scan -t https://example.com --tools wappalyzer --options wappalyzer:threads=10
```

### Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_type` | Type of scan: `fast`, `balanced`, or `full` | `full` |
| `threads` | Number of concurrent threads for the tool | `5` |
| `timeout_seconds` | Timeout for the command execution | `180` |

## Integration Details

The integration works by:

1. Checking if the `wappalyzer` executable is available.
2. Constructing the command line arguments based on the target and options.
3. Executing the `wappalyzer` command using `SubprocessExecutor`.
4. Parsing the JSON output produced by the tool on stdout.
5. Converting the detected technologies into standardized `TechnologyFinding` objects.

## Result Parsing

Wappalyzer results are converted to the following finding structure:

- `title`: "Technology Detected: [Technology Name] (v[Version])"
- `severity`: `INFO` (Technology detection is informational)
- `target`: The specific URL where the technology was detected (as reported by Wappalyzer)
- `technology_name`: Name of the detected technology
- `version`: Detected version (if available)
- `categories`: List of categories the technology belongs to
- `description`: Auto-generated description summarizing the finding.
- `raw_evidence`: Complete technology details dictionary from Wappalyzer output.

## Troubleshooting

Common issues:

1. **`wappalyzer` executable not found**: Ensure the package is installed (`poetry install --extras wappalyzer` or `pip install wappalyzer`) and your PATH is configured correctly.
2. **`geckodriver` not found or Firefox issues**: Ensure Firefox is installed and `geckodriver` is correctly installed and in your PATH. Check `wappalyzer` package documentation for specific browser/driver compatibility.
3. **Scan timeouts**: The 'full' scan mode launches a headless browser and can be slow. Increase the `timeout_seconds` option if needed.
4. **Errors in stderr**: Check Wappalyzer's stderr output logged by Sniper for specific error messages from the tool.

## Reference

- [wappalyzer PyPI Package](https://pypi.org/project/wappalyzer/)
- [geckodriver Releases](https://github.com/mozilla/geckodriver/releases) 