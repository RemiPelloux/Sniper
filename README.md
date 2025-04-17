# Sniper CLI

Penetration Testing CLI Tool with Machine Learning Enhancement.

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
  - Wappalyzer for technology detection
- Machine learning capabilities for smart vulnerability prediction and risk scoring
  - Custom ML models for vulnerability classification
  - Risk scoring based on historical CVE data
  - Predictive analysis of potential attack vectors
  - Feature extraction from scan results
- Comprehensive reporting with consolidated findings
  - HTML, JSON, and PDF report formats
  - Executive summaries and detailed technical reports
  - Customizable templates and branding options
- Configurable scan depth and target specification
- JSON output support for integration with other tools
- Containerized deployment with Docker and docker-compose
- Interactive CLI mode with visualization options
- Authentication support for web scanning with OWASP ZAP
- Scheduled scanning capabilities with result comparison
- Advanced API for integration with other security tools
- Web dashboard for visualizing scan results (coming in Sprint 4)

## Installation

Requires Python 3.11+ and Poetry for dependency management.

```bash
# Clone the repository
git clone https://github.com/yourusername/sniper-cli.git
cd sniper-cli

# Install the basic package
poetry install

# Install with optional dependencies (e.g., for ZAP and Wappalyzer)
poetry install --extras "zap wappalyzer"
```

### Docker Installation

For containerized deployment, use Docker:

```bash
# Build and run using docker-compose
docker-compose up -d

# Run a scan using the container
docker exec sniper poetry run sniper scan -t example.com

# Or use the container in interactive mode
docker exec -it sniper bash
```

## Tool Dependencies

Some integrations require external tools to be installed:

- **OWASP ZAP**: Install from [zaproxy.org](https://www.zaproxy.org/download/) and ensure it's in your PATH.
- **Wappalyzer**: Requires Firefox and geckodriver. See [Wappalyzer Setup](#wappalyzer-setup) below.
- **Nmap**: Install using your system's package manager (`apt install nmap`, `brew install nmap`, etc.).
- **Dirsearch**: Clone from GitHub: `git clone https://github.com/maurosoria/dirsearch.git`.
- **Sublist3r**: Clone from GitHub: `git clone https://github.com/aboul3la/Sublist3r.git`.

### Wappalyzer Setup

For the Wappalyzer integration:

1. Install Firefox browser
2. Download geckodriver from [GitHub Releases](https://github.com/mozilla/geckodriver/releases)
3. Add geckodriver to your PATH
4. Install required Python packages: `poetry install --extras "wappalyzer"`

## Configuration

Create a `config.yaml` file in your project directory or use the default configuration:

```yaml
tools:
  zap:
    api_key: "your-zap-api-key"
    host: "localhost"
    port: 8080
    auth_config:
      username_field: "username"
      password_field: "password"
      login_url: "https://example.com/login"
      username: "test_user"
      password: "test_password"
    context_config:
      name: "example_context"
      include_urls: ["https://example.com/*"]
      exclude_urls: ["https://example.com/logout"]
    scan_policy: "Default Policy"
  nmap:
    sudo: false
    arguments: "-sV -sC"
  wappalyzer:
    headless: true
  sublist3r:
    threads: 5
  dirsearch:
    wordlist: "path/to/wordlist.txt"
    extensions: "php,html,js"
ml:
  feature_extraction:
    enabled: true
    methods: ["severity_based", "technology_context", "attack_vector"]
  risk_scoring:
    algorithm: "weighted_ensemble"
    factors: ["severity", "exploitability", "impact", "context"]
  model_path: "models/vulnerability_classifier.pkl"
  training_data: "data/training_set.json"
api:
  host: "0.0.0.0"
  port: 5000
  authentication:
    enabled: true
    method: "token"
  rate_limiting:
    enabled: true
    requests_per_minute: 60
scheduled_scans:
  enabled: true
  storage_path: "data/scheduled_scans/"
  comparison:
    enabled: true
    highlight_changes: true
```

## Usage

```bash
# Get help
poetry run sniper --help

# Basic scan of a target with all available tools
poetry run sniper scan -t example.com

# Scan a target with specific tools
poetry run sniper scan -t example.com --tools nmap,zap

# Perform web scanning with OWASP ZAP
poetry run sniper scan -t https://example.com --tools zap

# Run an active ZAP scan with custom options
poetry run sniper scan -t https://example.com --tools zap --options zap:scan_type=active,zap:recursion=true

# Run ZAP scan with authentication
poetry run sniper scan -t https://example.com --tools zap --options zap:auth=true

# Detect technologies with Wappalyzer
poetry run sniper scan -t https://example.com --tools wappalyzer

# Find subdomains with Sublist3r
poetry run sniper scan -t example.com --tools sublist3r

# Generate a detailed report after scanning
poetry run sniper report -t example.com -o report.html --format html

# Export findings to JSON for integration with other tools
poetry run sniper report -t example.com -o findings.json --format json

# Start interactive scan mode
poetry run sniper scan -t example.com --interactive

# Analyze scan results with ML model
poetry run sniper ml analyze -i report.json -o risk_assessment.json

# Train custom ML model with your own data
poetry run sniper ml train -i custom_data.json -o models/custom_model.pkl

# Schedule a recurring scan
poetry run sniper schedule -t example.com --frequency daily --time "02:00"

# Run the configuration wizard
poetry run sniper config --wizard

# Start the REST API server
poetry run sniper api --port 5000
```

## Project Structure

-   `src/`: Main application source code.
    - `src/cli/`: Command-line interface components
    - `src/core/`: Core functionality (configuration, logging, etc.)
    - `src/integrations/`: Tool integrations
    - `src/results/`: Result models and processing
    - `src/ml/`: Machine learning components for risk assessment
    - `src/api/`: REST API components
    - `src/web/`: Web dashboard components (Sprint 4)
    - `src/scheduler/`: Scheduled scanning components
-   `tests/`: Unit and integration tests.
-   `docs/`: Project documentation (roadmap, specifications, integration guides).
-   `models/`: Machine learning models and training data.
-   `data/`: Training and reference data for ML models.
-   `docker/`: Docker configuration files and containerization scripts.
-   `kubernetes/`: Kubernetes deployment configurations (Sprint 4).

## Documentation

For more detailed information about specific integrations, see:

- [OWASP ZAP Integration](docs/integrations/owasp_zap.md)
- [Wappalyzer Integration](docs/integrations/wappalyzer.md)
- [Sublist3r Integration](docs/integrations/sublist3r.md)
- [Nmap Integration](docs/integrations/nmap.md)
- [Dirsearch Integration](docs/integrations/dirsearch.md)

For user and developer documentation:

- [User Guide](docs/user/guide.md)
- [Developer Documentation](docs/developer/guide.md)
- [API Documentation](docs/api/reference.md)
- [ML Model Documentation](docs/ml/overview.md)
- [Docker Deployment Guide](docs/deployment/docker.md)
- [Kubernetes Deployment Guide](docs/deployment/kubernetes.md) (Coming in Sprint 4)

## Development Roadmap

- Sprint 1-3: ✅ Complete - Core functionality, tool integrations, ML capabilities
- Sprint 4: REST API, Web Dashboard, Enhanced ML features, Kubernetes deployment
- Sprint 5: Distributed scanning, cloud deployment, mobile app, advanced reporting

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure they pass (`poetry run pytest`)
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Follow the modular architecture pattern established in the codebase
- Write comprehensive tests for all new features (aim for >85% coverage)
- Document all public interfaces
- Keep dependencies minimal and explicit
- Follow PEP 8 style guidelines (`poetry run black .` and `poetry run isort .`)

## License

MIT License 