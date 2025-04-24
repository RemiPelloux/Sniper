# Sniper Security Tool - Quick Start Guide

This guide will help you quickly get started with the Sniper Security Tool, covering installation, basic configuration, and essential operations.

## 1. Installation

### Prerequisites

Before installing Sniper, ensure you have:

- Python 3.10 or higher
- [Poetry](https://python-poetry.org/docs/#installation) for dependency management
- Docker (optional, but recommended for tool containerization)
- Git

### Option 1: Standard Installation

```bash
# Clone the repository
git clone https://github.com/your-username/sniper.git
cd sniper

# Install dependencies with Poetry
poetry install

# Verify installation
poetry run sniper --version
```

### Option 2: Docker Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/sniper.git
cd sniper

# Build and run using Docker Compose
docker compose up -d

# Run commands using Docker
docker compose run --rm sniper --version
```

## 2. Basic Scanning

### Running Your First Scan

```bash
# Standard scan against a target
poetry run sniper scan run --target example.com

# If using Docker
docker compose run --rm sniper scan run --target example.com
```

### Specifying Output Format

```bash
# Save results to a JSON file
poetry run sniper scan run --target example.com --output results.json

# Generate output in multiple formats
poetry run sniper scan run --target example.com --output results.json --json --html
```

### Selecting Scan Modules

```bash
# List available modules
poetry run sniper scan modules

# Use specific modules
poetry run sniper scan run --target example.com --module ports,web,subdomains

# Exclude certain modules
poetry run sniper scan run --target example.com --exclude web
```

## 3. Using Scan Modes

Sniper provides predefined scan modes for different scenarios:

```bash
# List available scan modes
poetry run sniper scan modes

# Run a scan using a specific mode
poetry run sniper scan run --target example.com --mode stealth
poetry run sniper scan run --target example.com --mode comprehensive
```

Available modes include:
- **quick**: Fast reconnaissance with minimal footprint
- **standard**: Balanced scan for routine assessments
- **comprehensive**: In-depth assessment with thorough testing
- **stealth**: Low-profile scan to avoid detection
- **api**: Specialized scan for API endpoints

## 4. Generating Reports

After performing a scan, you can generate detailed reports:

```bash
# Generate an HTML report from scan results
poetry run sniper report results.json --format html

# Generate multiple format reports
poetry run sniper report results.json --format html,json,markdown

# Specify output location
poetry run sniper report results.json --format html --output /path/to/reports/
```

## 5. Managing Security Tools

Sniper can manage the security tools it uses:

```bash
# List available tools
poetry run sniper tools list

# Show detailed information about a tool
poetry run sniper tools show nmap

# Install a tool
poetry run sniper tools install zap

# Update installed tools
poetry run sniper tools update
```

## 6. Using Sandbox Environments

Test against deliberately vulnerable applications:

```bash
# List available sandbox environments
poetry run sniper sandbox list

# Start a sandbox environment
poetry run sniper sandbox start dvwa

# Check sandbox status
poetry run sniper sandbox status

# Stop a sandbox environment
poetry run sniper sandbox stop dvwa
```

## 7. Distributed Scanning

For large-scale scanning, use the distributed architecture:

```bash
# Start a master node
poetry run sniper distributed master start --host 0.0.0.0 --port 5000

# Start a worker node
poetry run sniper distributed worker start --master example.com:5000 --capabilities web,ports,subdomains

# Submit a task to the distributed system
poetry run sniper distributed tasks submit --target example.com --type scan --priority high

# Check task status
poetry run sniper distributed tasks list
```

## 8. Machine Learning Features

Leverage Sniper's ML capabilities:

```bash
# Predict vulnerabilities based on scan results
poetry run sniper ml predict --input scan-results.json

# Calculate risk scores
poetry run sniper ml risk --input scan-results.json
```

## 9. Advanced Configuration

Create a custom configuration file in the `config` directory:

```yaml
# config/config.yaml
modules:
  nmap:
    enabled: true
    arguments: "-sV -p 1-1000"
  
  sublist3r:
    enabled: true
    
  wappalyzer:
    enabled: true
    
  zap:
    enabled: true
    api_key: "changeme"
    api_url: "http://localhost:8080"
    
  dirsearch:
    enabled: true
    wordlist: "common.txt"

output:
  report_dir: "./data/reports"
  formats:
    - json
    - html
```

Specify a custom configuration file:

```bash
poetry run sniper scan run --target example.com --config my_custom_config.yaml
```

## 10. Next Steps

- Learn about creating [custom scan modes](docs/custom_scan_modes.md)
- Explore the [distributed scanning architecture](docs/distributed.md)
- Learn how to [extend Sniper](docs/extensions.md) with your own modules
- View [example workflows](docs/examples.md) for common security testing scenarios

For complete documentation, visit the [full documentation](docs/README.md). 