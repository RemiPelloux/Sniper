# OWASP ZAP Integration

This document explains the integration between Sniper and OWASP ZAP (Zed Attack Proxy), an open-source web application security scanner.

## Features

- Passive scanning for information gathering
- Active scanning for vulnerability detection
- Support for both standard and AJAX spider modes
- Headless operation through the Python API
- Comprehensive parsing of security alerts
- JSON output format for integration with other tools
- Customizable scan configurations

## Prerequisites

For the ZAP integration to work, you need:

1. The Python ZAP API package:
   ```
   # Install via Poetry
   poetry install --extras "zap"
   
   # Or install directly
   pip install zaproxy
   ```

2. OWASP ZAP installed on your system with either:
   - `zap.sh` (Linux/macOS) or `zap.bat` (Windows) in your PATH
   - A running ZAP instance accessible via API

## Configuration

The ZAP integration can be configured using environment variables, a `.env` file, or a `config.yaml` file:

```yaml
# In config.yaml
tools:
  zap:
    api_key: "your_api_key"
    host: "localhost" 
    port: 8080
    use_existing_instance: false
    scan_timeout: 600
```

Or with environment variables:

```bash
# Configure ZAP settings
SNIPER_TOOL_CONFIGS__ZAP__API_KEY=your_api_key
SNIPER_TOOL_CONFIGS__ZAP__HOST=localhost
SNIPER_TOOL_CONFIGS__ZAP__PORT=8080
SNIPER_TOOL_CONFIGS__ZAP__USE_EXISTING_INSTANCE=false
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `api_key` | API key for authenticating with ZAP | `""` (empty string) |
| `host` | Host where ZAP is running | `localhost` |
| `port` | Port for the ZAP API | `8080` |
| `use_existing_instance` | Whether to use an existing ZAP instance | `false` |
| `scan_timeout` | Maximum time in seconds for scanning | `600` |
| `include_passive_scan` | Run passive scan even in active mode | `true` |
| `recursion` | Enable recursion for the spider | `true` |

## Usage Examples

### Basic Command Line Usage

```bash
# Run a passive scan against a target
poetry run sniper scan -t https://example.com --tools zap

# Run an active scan against a target
poetry run sniper scan -t https://example.com --tools zap --options zap:scan_type=active

# Use the AJAX spider
poetry run sniper scan -t https://example.com --tools zap --options zap:use_ajax_spider=true

# Configure scan depth
poetry run sniper scan -t https://example.com --tools zap --options zap:scan_type=active,zap:recursion=true --depth 3

# Output results to JSON file
poetry run sniper scan -t https://example.com --tools zap -o zap_results.json
```

### Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_type` | Type of scan to perform: `passive` or `active` | `passive` |
| `use_ajax_spider` | Use AJAX spider instead of traditional spider | `false` |
| `daemon_start_timeout` | Timeout in seconds for starting the ZAP daemon | `60` |
| `daemon_options` | Additional command-line options for ZAP daemon | `[]` |
| `context_name` | ZAP context name for the scan | `Sniper` |
| `attack_strength` | Attack strength for active scan (LOW, MEDIUM, HIGH) | `MEDIUM` |
| `alert_threshold` | Alert threshold (LOW, MEDIUM, HIGH) | `MEDIUM` |

## Integration Details

The ZAP integration works by:

1. Starting ZAP in daemon mode (if not using an existing instance)
2. Connecting to the ZAP API
3. Creating a new session
4. Crawling the target website using either the standard spider or AJAX spider
5. Optionally running an active scan to detect vulnerabilities
6. Collecting and parsing alerts
7. Converting ZAP alerts into standardized `WebFinding` objects
8. Shutting down ZAP (if it was started by the integration)

## API Usage Example

```python
from src.integrations.owasp_zap import ZapIntegration

# Initialize the ZAP integration
zap = ZapIntegration(
    target="https://example.com",
    options={
        "scan_type": "active",
        "use_ajax_spider": True,
        "recursion": True
    }
)

# Run the scan
zap.scan()

# Get the results
results = zap.output_scan_results()
for finding in results:
    print(f"Title: {finding.title}")
    print(f"Severity: {finding.severity}")
    print(f"URL: {finding.url}")
    print(f"Description: {finding.description}")
    print("---")

# Clean up
zap.cleanup()
```

## Result Parsing

ZAP alerts are converted to standardized `WebFinding` objects with the following structure:

- `title`: "ZAP: [Alert Name]"
- `severity`: Mapped from ZAP risk levels to Sniper severity levels:
  - ZAP High → Sniper Critical
  - ZAP Medium → Sniper High
  - ZAP Low → Sniper Medium
  - ZAP Informational → Sniper Low
- `url`: The specific URL where the issue was found
- `method`: HTTP method (GET, POST, etc.)
- `parameter`: Affected parameter if applicable
- `description`: Alert description from ZAP
- `raw_evidence`: Complete alert data from ZAP

## Troubleshooting

Common issues:

1. **ZAP API not found**: Ensure `python-owasp-zap-v2.4` or `zaproxy` is installed
2. **ZAP executable not found**: Ensure ZAP is installed and in your PATH
3. **Connection failure**: Check if the configured host and port are correct
4. **API key issues**: Verify the API key matches the one configured in ZAP
5. **Scan timeout**: Increase the `scan_timeout` value for large targets
6. **Memory issues**: Add `-Xmx2048m` to `daemon_options` to increase Java heap size

## Limitations and Known Issues

- The integration requires more memory for large targets or complex web applications
- Some JavaScript-heavy applications may not be fully crawled without the AJAX spider
- Certain authentication mechanisms may require manual configuration
- Proxy settings may need to be configured for targets behind corporate networks

## Future Enhancements

- Support for authentication during scanning
- Integration with ZAP's automation framework
- Enhanced result filtering options
- Support for context-specific scan policies
- Integration with CI/CD pipelines

## Reference

- [OWASP ZAP Official Documentation](https://www.zaproxy.org/docs/)
- [ZAP Python API Documentation](https://github.com/zaproxy/zap-api-python)
- [ZAP Scanning Best Practices](https://www.zaproxy.org/docs/desktop/start/features/scan/) 