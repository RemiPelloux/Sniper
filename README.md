# Sniper

A comprehensive security scanning tool that integrates multiple security tools for reconnaissance, vulnerability scanning, and reporting.

## Features

- Integrated security modules:
  - Port scanning (Nmap)
  - Subdomain enumeration (Sublist3r)
  - Technology detection (Wappalyzer)
  - Web vulnerability scanning (OWASP ZAP)
  - Directory brute-forcing (Dirsearch)
- ML-powered vulnerability prediction and risk scoring
- Unified reporting system with multiple output formats
- Flexible configuration management
- Modular architecture for easy extension
- Distributed scanning architecture:
  - Master-worker model for parallel scanning
  - Auto-scaling capabilities based on workload
  - Fault tolerance and recovery mechanisms
  - Support for multiple deployment environments (local, Docker, Kubernetes)

## Installation

### Using Docker (Recommended)

1. Clone the repository:
   ```
   git clone https://github.com/your-username/sniper.git
   cd sniper
   ```

2. Build and run using Docker Compose:
   ```
   docker compose up -d
   ```

3. Run a scan:
   ```
   docker compose run --rm sniper scan --target example.com
   ```

### Manual Installation

1. Install dependencies:
   - Python 3.10+
   - Poetry
   - Nmap
   - OWASP ZAP (for web scanning)

2. Clone the repository:
   ```
   git clone https://github.com/your-username/sniper.git
   cd sniper
   ```

3. Install Python dependencies:
   ```
   poetry install
   ```

4. Run a scan:
   ```
   poetry run python -m src.cli.scan --target example.com
   ```

## Configuration

Create a `config.yaml` file in the `config` directory:

```yaml
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
    - console
```

## Usage

### Basic Scan

```bash
docker compose run --rm sniper scan --target example.com
```

### Advanced Usage

Scan with specific modules:
```bash
docker compose run --rm sniper scan --target example.com --modules nmap,wappalyzer,zap
```

Scan with specific depth:
```bash
docker compose run --rm sniper scan --target example.com --depth deep
```

Generate an HTML report:
```bash
docker compose run --rm sniper scan --target example.com --output html,json
```

### Distributed Scanning

Start a master node:
```bash
docker compose run --rm sniper distributed master --auto-scaling --min-nodes 2 --max-nodes 5
```

Start a worker node:
```bash
docker compose run --rm sniper distributed worker --master-host <master-ip> --master-port 5000
```

Check distributed system status:
```bash
docker compose run --rm sniper distributed status
```

## Development

### Running Tests

```bash
poetry run pytest
```

### Adding New Modules

1. Create a new integration file in `src/integrations/`
2. Implement the required interface methods
3. Register the module in `src/modules/registry.py`

## License

This project is licensed under the MIT License - see the LICENSE file for details. 