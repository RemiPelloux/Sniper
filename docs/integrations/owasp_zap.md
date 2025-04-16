# OWASP ZAP Integration

This document explains the integration between Sniper and OWASP ZAP (Zed Attack Proxy), an open-source web application security scanner.

## Features

- Passive scanning for information gathering
- Active scanning for vulnerability detection
- Support for both standard and AJAX spider modes
- Headless operation through the Python API
- Comprehensive parsing of security alerts

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

The ZAP integration can be configured using environment variables or a `.env` file:

```
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

## Usage Examples

### Basic Command Line Usage

```bash
# Run a passive scan against a target
sniper scan -t https://example.com --tools zap

# Run an active scan against a target
sniper scan -t https://example.com --tools zap --options zap:scan_type=active

# Use the AJAX spider
sniper scan -t https://example.com --tools zap --options zap:use_ajax_spider=true
```

### Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `scan_type` | Type of scan to perform: `passive` or `active` | `passive` |
| `use_ajax_spider` | Use AJAX spider instead of traditional spider | `false` |
| `daemon_start_timeout` | Timeout in seconds for starting the ZAP daemon | `60` |
| `daemon_options` | Additional command-line options for ZAP daemon | `[]` |

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

## Result Parsing

ZAP alerts are converted to the following finding structure:

- `title`: "ZAP: [Alert Name]"
- `severity`: Mapped from ZAP risk levels to Sniper severity levels
- `url`: The specific URL where the issue was found
- `method`: HTTP method (GET, POST, etc.)
- `parameter`: Affected parameter if applicable
- `description`: Alert description from ZAP
- `raw_evidence`: Complete alert data from ZAP

## Troubleshooting

Common issues:

1. **ZAP API not found**: Ensure `python-owasp-zap-v2.4` is installed
2. **ZAP executable not found**: Ensure ZAP is installed and in your PATH
3. **Connection failure**: Check if the configured host and port are correct
4. **API key issues**: Verify the API key matches the one configured in ZAP

## Reference

- [OWASP ZAP Official Documentation](https://www.zaproxy.org/docs/)
- [ZAP Python API Documentation](https://github.com/zaproxy/zap-api-python) 