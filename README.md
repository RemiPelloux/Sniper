# Sniper CLI

Penetration Testing CLI Tool with Machine Learning Enhancement.

*This project is under active development.*

## Overview

Sniper CLI is a powerful, modular penetration testing tool that integrates various security scanning tools into a single command-line interface. It enhances traditional security scanning with machine learning to prioritize testing vectors and identify potential vulnerabilities.

## Features

- Unified command-line interface for multiple security tools
- Standardized output format for easier analysis
- Integration with popular security tools:
  - Nmap for port scanning
  - OWASP ZAP for web vulnerability scanning
  - Dirsearch for directory discovery
  - Sublist3r for subdomain enumeration
  - Wappalyzer for technology detection (coming soon)
- Machine learning capabilities for smart scanning (coming soon)

## Installation

Requires Python 3.11+ and Poetry for dependency management.

```bash
# Install the basic package
poetry install

# Install with optional dependencies (e.g., for ZAP and Wappalyzer)
poetry install --extras "zap wappalyzer"
```

## Tool Dependencies

Some integrations require external tools to be installed:

- **OWASP ZAP**: Install from [zaproxy.org](https://www.zaproxy.org/download/) and ensure it's in your PATH.
- **Wappalyzer**: Requires Firefox and geckodriver. See [Wappalyzer Docs](docs/integrations/wappalyzer.md#prerequisites).
- **Nmap**: Install using your system's package manager.
- **Dirsearch**: Requires Python 3 and installation from GitHub.
- **Sublist3r**: Requires manual installation from GitHub. See [Sublist3r Docs](docs/integrations/sublist3r.md#prerequisites).

## Usage

```bash
# Get help
poetry run sniper --help

# Scan a target with Nmap
poetry run sniper scan -t example.com --tools nmap

# Perform web scanning with OWASP ZAP
poetry run sniper scan -t https://example.com --tools zap

# Run an active ZAP scan
poetry run sniper scan -t https://example.com --tools zap --options zap:scan_type=active

# Detect technologies with Wappalyzer
poetry run sniper scan -t https://example.com --tools wappalyzer

# Find subdomains with Sublist3r
poetry run sniper scan -t example.com --tools sublist3r
```

## Project Structure

-   `src/`: Main application source code.
    - `src/cli/`: Command-line interface components
    - `src/core/`: Core functionality (configuration, logging, etc.)
    - `src/integrations/`: Tool integrations
    - `src/results/`: Result models and processing
-   `tests/`: Unit and integration tests.
-   `docs/`: Project documentation (roadmap, specifications, etc.).
-   `models/`: (Planned) Machine learning models.
-   `data/`: (Planned) Training and reference data.

## Documentation

For more detailed information about specific integrations, see:

- [OWASP ZAP Integration](docs/integrations/owasp_zap.md)
- [Wappalyzer Integration](docs/integrations/wappalyzer.md)
- [Sublist3r Integration](docs/integrations/sublist3r.md)
- More documentation coming soon...

## Contributing

(To be filled in)

## License

MIT License (See `pyproject.toml`) 