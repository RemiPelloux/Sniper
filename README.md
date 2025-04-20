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
- Predefined scan modes for different scanning scenarios
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
   docker compose run --rm sniper scan run --target example.com
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
   poetry run sniper scan run --target example.com
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
poetry run sniper scan run --target example.com
```

### Using Scan Modes

Sniper supports predefined scan modes, each tailored for specific scanning scenarios:

List available scan modes:
```bash
poetry run sniper scan modes
```

Run a scan using a specific mode:
```bash
poetry run sniper scan run --target example.com --mode quick
poetry run sniper scan run --target example.com --mode comprehensive
poetry run sniper scan run --target example.com --mode stealth
```

Available scan modes:
- **quick**: Fast reconnaissance with minimal footprint
- **standard**: Balanced scan for routine security assessments
- **comprehensive**: In-depth security assessment with thorough testing
- **stealth**: Low-profile scan to avoid detection
- **api**: Specialized scan for API endpoints and services

### Advanced Usage

Scan with specific modules:
```bash
poetry run sniper scan run --target example.com --module technologies --module ports
```

Scan with comma-separated modules:
```bash
poetry run sniper scan run --target example.com --module technologies,ports,web
```

Scan with specific depth:
```bash
poetry run sniper scan run --target example.com --depth COMPREHENSIVE
```

Generate a report:
```bash
poetry run sniper scan run --target example.com --output report.json --json
```

### Docker Container Fallbacks

Sniper automatically detects if required security tools (like Nmap, OWASP ZAP, etc.) are installed on your system. If a tool is missing, Sniper will:

1. Check if Docker is available on your system
2. Pull the appropriate Docker image for the missing tool
3. Create a wrapper script to use the tool via Docker
4. Use this wrapper for scanning operations

This ensures that you can run scans even if you haven't installed all the required security tools locally. The Docker container fallback is completely transparent - you don't need to modify your commands or configuration.

To use this feature, simply make sure Docker is installed on your system. Everything else happens automatically when needed.

### Distributed Scanning

Start a master node:
```bash
poetry run sniper distributed master --auto-scaling --min-nodes 2 --max-nodes 5
```

Start a worker node:
```bash
poetry run sniper distributed worker --master-host <master-ip> --master-port 5000
```

Check distributed system status:
```bash
poetry run sniper distributed status
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

### Adding Custom Scan Modes

Custom scan modes can be added by creating or modifying the `config/scan_modes.yaml` file:

```yaml
custom_mode:
  name: custom_mode
  description: "Your custom scan mode description"
  target_types: ["domain", "url"]
  modules:
    - technologies
    - ports
  settings:
    max_threads: 10
    timeout: 1800
    scan_depth: standard
  tools:
    nmap:
      enabled: true
      options:
        ports: "80,443,8080"
    wappalyzer:
      enabled: true
      options: {}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.