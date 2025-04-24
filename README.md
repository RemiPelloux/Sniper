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

### Specialized Target Scanning

Sniper includes dedicated commands for specific targets:

#### DVWA (Damn Vulnerable Web Application)

```bash
# Scan a DVWA instance with defaults
poetry run sniper scan dvwa http://localhost

# Scan with options
poetry run sniper scan dvwa http://localhost --security-level medium --output dvwa-report.json
```

#### OWASP Juice Shop

```bash
# Scan a Juice Shop instance with defaults
poetry run sniper scan juiceshop http://localhost:3000

# Scan with options
poetry run sniper scan juiceshop http://localhost:3000 --output juice-report.json
```

These specialized scan commands are optimized for testing these deliberately vulnerable applications, making them ideal for security training and testing environments.

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

## Distributed Scanning Architecture

Sniper includes a powerful distributed scanning architecture that allows you to scale your security testing across multiple machines. This is useful for large-scale assessments, high-performance scanning, and specialized worker nodes.

### Automatic Worker Management (New!)

The latest version includes automatic worker management, eliminating the need to manually start and manage worker nodes:

```bash
# Start master node with auto-scaling (workers are managed automatically)
python run_master.py --min-workers 3 --max-workers 10

# Submit tasks directly (no need to manage workers)
python submit_task.py https://example.com --wait
```

### Using Docker Compose with Auto-Scaling

The Docker Compose configuration now supports automatic worker management:

```bash
# Start the entire distributed system with auto-scaling
docker compose -f docker-compose.distributed.yml up

# Scale workers explicitly if needed
docker compose -f docker-compose.distributed.yml up --scale worker=5
```

### Task Submission API

For integrating with other applications, use the task submitter API:

```bash
# Start the task submitter API server
python -m src.cli.task_submitter --master localhost:5000 --port 8080

# Now you can submit tasks via HTTP API
curl -X POST http://localhost:8080/scan/vulnerability \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "priority": "high"}'
```

### Manual Mode (Legacy)

If you prefer to manually manage master and worker nodes:

```bash
# Start a master node
python -m src.cli.distributed_typer master start --host 0.0.0.0 --port 5000

# Start worker nodes manually
python -m src.cli.distributed_typer worker start --master localhost:5000 --capabilities vulnerability_scan,recon
```

For more details about the distributed scanning architecture, see the [Distributed Scanning Documentation](docs/distributed.md).

## Testing

This project uses pytest for testing. The test configuration has been fixed to ensure proper test discovery:

```bash
# Run all tests
python -m pytest

# Run specific test modules
python -m pytest tests/distributed/

# Run with coverage
python -m pytest --cov=src tests/
```

If you encounter issues with pytest, run the fix script:

```bash
python fix_pytest.py
```

## Current Sprint Status

### Sprint 3: Distributed Architecture Implementation ✅

- ✅ Implement master node functionality with task distribution
- ✅ Implement worker node with task execution capabilities
- ✅ Create command-line interface for distributed operations
- ✅ Add Docker Compose configuration for easy deployment
- ✅ Document distributed architecture usage and workflows

### Sprint 4: Advanced Scanning Features ✅

- ✅ Implement advanced vulnerability scanning techniques
- ✅ Add support for custom scanning rules and profiles
- ✅ Integrate with external security tools and databases
- ✅ Enhance reporting with detailed vulnerability information
- ✅ Optimize scanning performance for large targets

### Sprint 5: Worker Auto-Management & API Integration 🔄

- ✅ Implement automatic worker scaling based on workload
- ✅ Create task submission API for external integrations
- ✅ Fix pytest configuration and test frameworks
- ✅ Add worker health monitoring and recovery
- 🔄 Expand ML capabilities for vulnerability detection