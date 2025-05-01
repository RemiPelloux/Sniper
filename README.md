# Sniper Security Tool

<p align="center">
  <img src="docs/assets/sniper-logo.png" alt="Sniper Logo" width="200"/>
</p>

<div align="center">
  <strong>Advanced Security Testing with AI-Powered Intelligence</strong>
</div>
<div align="center">
  A comprehensive security scanning platform with distributed architecture, machine learning capabilities, and intelligent orchestration
</div>

<div align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License" />
  <img src="https://img.shields.io/badge/version-0.1.0-orange.svg" alt="Version 0.1.0" />
  <img src="https://img.shields.io/badge/tests-414%20passing-brightgreen.svg" alt="414 Tests Passing" />
</div>

<hr>

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Using Docker](#using-docker-recommended)
  - [Manual Installation](#manual-installation)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
  - [Scan Modes](#scan-modes)
  - [Distributed Scanning](#distributed-scanning)
  - [Machine Learning](#machine-learning)
  - [Sandbox Environments](#sandbox-environments)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

## Overview

Sniper is a comprehensive security scanning platform designed for professional penetration testers, security researchers, and DevSecOps teams. It combines the power of multiple security tools, distributed computing, and machine learning to deliver advanced security testing capabilities with unprecedented speed and intelligence.

Built with a modular architecture, Sniper orchestrates specialized security tools, analyzes their results using AI, and provides actionable security insights through a unified interface.

## Key Features

### Core Capabilities

- **Unified Interface**: Interact with 40+ security tools through a single CLI or API
- **Modular Design**: Easily extend with plugins and custom integrations
- **Flexible Configuration**: Configure each tool with custom parameters
- **Comprehensive Reporting**: Generate reports in multiple formats (JSON, HTML, Markdown)

### Advanced Features

- **Distributed Scanning Architecture**:
  - Master-worker model for parallel scanning across multiple nodes
  - Auto-scaling capability based on workload and resource availability
  - Task distribution with intelligent prioritization
  - Fault tolerance and recovery mechanisms

- **AI-Powered Intelligence**:
  - ML-based vulnerability prediction and risk scoring
  - Smart scan optimization based on target characteristics
  - Pattern learning for identifying complex vulnerabilities
  - Autonomous vulnerability testing and verification

- **Integrated Security Modules**:
  - Port scanning and service detection (Nmap)
  - Subdomain enumeration (Sublist3r)
  - Technology detection (Wappalyzer)
  - Web vulnerability scanning (OWASP ZAP)
  - Directory discovery (Dirsearch)
  - And many more...

- **Sandbox Environments**:
  - Built-in vulnerable application sandbox for training and testing
  - Docker-based isolation for safe exploitation attempts
  - Pre-configured environments (DVWA, OWASP Juice Shop)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/security-labs/sniper.git
cd sniper

# Install with Poetry
poetry install

# Run a basic scan
poetry run sniper scan run --target https://example.org

# Generate a report
poetry run sniper report data/results/example.org_*.json --format html
```

## Installation

### Using Docker (Recommended)

```bash
# Build and run using Docker Compose
docker compose up -d

# Run a scan
docker compose run --rm sniper scan run --target https://example.org
```

### Manual Installation

#### Prerequisites

- Python 3.10 or higher
- Poetry (dependency management)
- Docker (optional, for tool containerization)

#### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/security-labs/sniper.git
   cd sniper
   ```

2. **Install dependencies**:
   ```bash
   poetry install
   ```

3. **Verify installation**:
   ```bash
   poetry run sniper --version
   ```

#### Security Tool Dependencies

Sniper can use many external security tools. You have three options:

1. **Install tools manually** on your system
2. **Let Sniper use Docker containers** automatically (recommended)
3. **Use the distributed architecture** to delegate tool execution to worker nodes

## Basic Usage

### Running a Basic Scan

```bash
# Run a basic scan against a target
poetry run sniper scan run --target https://example.org

# Specify output file
poetry run sniper scan run --target https://example.org --output my-scan-results.json

# Use specific modules
poetry run sniper scan run --target https://example.org --module ports,web,subdomains
```

### Viewing Results

```bash
# Generate an HTML report
poetry run sniper report my-scan-results.json --format html

# Generate multiple format reports
poetry run sniper report my-scan-results.json --format html,json,markdown
```

### Managing Tools

```bash
# List available tools
poetry run sniper tools list

# Show detailed information about a tool
poetry run sniper tools show nmap

# Install a tool
poetry run sniper tools install zap

# Update a tool
poetry run sniper tools update nmap
```

## Advanced Usage

### Scan Modes

Sniper supports predefined scan modes for different scenarios:

```bash
# List available scan modes
poetry run sniper scan modes

# Use a specific scan mode
poetry run sniper scan run --target https://example.org --mode stealth
poetry run sniper scan run --target https://example.org --mode comprehensive
```

Available modes include:
- **quick**: Fast reconnaissance with minimal footprint
- **standard**: Balanced scan for routine assessments
- **comprehensive**: In-depth assessment with thorough testing
- **stealth**: Low-profile scan to avoid detection
- **api**: Specialized scan for API endpoints

### Distributed Scanning

Sniper's distributed architecture allows you to scale your scanning capabilities across multiple nodes:

```bash
# Start a master node
poetry run sniper distributed master start --host 0.0.0.0 --port 5000

# Start a worker node
poetry run sniper distributed worker start --master scanner.example.org:5000 --capabilities web,ports,subdomains

# Submit a task to the distributed system
poetry run sniper distributed tasks submit --target https://example.org --type scan --priority high

# List workers connected to the master
poetry run sniper distributed workers list

# Check task status
poetry run sniper distributed tasks list
```

### Machine Learning

Leverage Sniper's ML capabilities:

```bash
# Predict vulnerabilities based on scan results
poetry run sniper ml predict --input scan-results.json

# Calculate risk scores
poetry run sniper ml risk --input scan-results.json

# Train a custom model (requires training data)
poetry run sniper ml train --data training-data/ --output my-model.pkl
```

### Sandbox Environments

Sniper includes a sandbox plugin for managing vulnerable testing environments:

```bash
# List available sandbox environments
poetry run sniper sandbox list

# Start a sandbox environment
poetry run sniper sandbox start dvwa

# Check status of sandbox environments
poetry run sniper sandbox status

# Stop a sandbox environment
poetry run sniper sandbox stop dvwa
```

## Architecture

Sniper is built with a modular, microservices-inspired architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                       Sniper Core                           │
├─────────────┬─────────────┬─────────────┬─────────────┬─────┘
│ Scan Engine │ Config Mgmt │ Plugin Mgmt │ Tool Mgmt   │
└─────────────┴─────────────┴─────────────┴─────────────┘
        │              │              │            │
┌───────▼──────┐ ┌─────▼───────┐ ┌────▼─────┐ ┌────▼────────┐
│   Security   │ │ Distributed │ │ Reporting│ │ Machine      │
│    Tools     │ │   System    │ │  Engine  │ │ Learning     │
└──────────────┘ └─────────────┘ └──────────┘ └─────────────┘
```

### Distributed Architecture

```
┌─────────────────┐                 ┌─────────────────┐
│   Master Node   │◄───Network─────►│   Worker Node   │
│                 │    Protocol     │                 │
└──────┬──────────┘                 └────────┬────────┘
       │                                     │
       │                                     │
┌──────▼──────────┐                 ┌────────▼────────┐
│ Task Scheduler  │                 │   Task Runner   │
│ Load Balancer   │                 │  Tool Executor  │
│ Result Aggregator│                 │ Result Reporter │
└─────────────────┘                 └─────────────────┘
```

### Plugin System

Sniper features a robust plugin system that allows for easy extension of its capabilities:

- **Tool Integrations**: Add support for new security tools
- **Reporting Plugins**: Create custom report formats
- **Custom Scanners**: Implement specialized scanning logic
- **Sandbox Environments**: Add new vulnerable application setups

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- [User Guide](docs/user_guide.md): Complete usage documentation
- [Developer Guide](docs/dev_guide.md): How to extend Sniper
- [API Reference](docs/api_reference.md): REST API documentation
- [Architecture](docs/architecture.md): Detailed system design
- [Tool Integrations](docs/tools.md): Available security tool integrations

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
poetry install --with dev

# Run tests
poetry run pytest

# Format code
poetry run black .
poetry run isort .

# Type checking
poetry run mypy .
```

### Project Structure

```
sniper/
├── src/                 # Source code
│   ├── cli/             # CLI commands and interfaces
│   ├── core/            # Core functionality
│   ├── distributed/     # Distributed scanning architecture
│   ├── integrations/    # Security tool integrations
│   ├── ml/              # Machine learning components
│   ├── payloads/        # Vulnerability testing payloads
│   ├── reporting/       # Report generation
│   ├── results/         # Result processing and normalization
│   └── sniper/          # Plugin system and extensions
├── tests/               # Test suite
├── docs/                # Documentation
├── config/              # Configuration files
└── examples/            # Example scripts and usage
```

## Roadmap

See our [Roadmap](docs/roadmap.md) for planned features and future development.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ by the Sniper Security Tool Team</sub>
</div>