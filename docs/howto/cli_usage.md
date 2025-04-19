# Sniper CLI Usage Guide

This guide provides detailed instructions on how to use the Sniper command-line interface for security testing.

## Basic Commands

Sniper offers several core commands for different types of security testing:

```bash
# Display help information
sniper --help

# Display version information
sniper --version

# Run a basic scan against a target
sniper scan -t example.com

# Specify scan mode (fast, normal, thorough)
sniper scan -t example.com -m thorough

# Specify output format (json, html, markdown)
sniper scan -t example.com --output-format json

# Save results to a file
sniper scan -t example.com --output-file report.json
```

## Scan Types

Sniper supports different types of scans:

```bash
# Run a full scan (all modules)
sniper scan -t example.com --type full

# Run a web application scan
sniper scan -t example.com --type webapp

# Run a network scan
sniper scan -t 192.168.1.1 --type network

# Run a reconnaissance scan
sniper scan -t example.com --type recon

# Run a vulnerability scan
sniper scan -t example.com --type vuln
```

## Advanced Options

For more fine-grained control:

```bash
# Specify custom ports to scan
sniper scan -t example.com --ports 80,443,8080,8443

# Set scan depth (1-5)
sniper scan -t example.com --depth 3

# Enable verbose output
sniper scan -t example.com -v

# Use quiet mode (minimal output)
sniper scan -t example.com -q

# Include specific tools
sniper scan -t example.com --tools nmap,zap,sqlmap

# Exclude specific tools
sniper scan -t example.com --exclude-tools nikto,wpscan

# Set timeout for the entire scan (in minutes)
sniper scan -t example.com --timeout 60

# Set rate limiting (requests per second)
sniper scan -t example.com --rate-limit 10
```

## Target Specification

Specify targets in different ways:

```bash
# Scan a single domain
sniper scan -t example.com

# Scan multiple domains
sniper scan -t example.com,example.org

# Scan from a file containing targets
sniper scan -t targets.txt

# Scan a CIDR range
sniper scan -t 192.168.1.0/24

# Scan with specific URL path
sniper scan -t https://example.com/webapp/
```

## Authentication Options

For authenticated scanning:

```bash
# Specify username and password
sniper scan -t https://example.com --username admin --password secret

# Use a session cookie
sniper scan -t https://example.com --cookie "session=abc123"

# Use bearer token authorization
sniper scan -t https://example.com --header "Authorization: Bearer token123"

# Use API key
sniper scan -t https://example.com --header "X-API-Key: key123"
```

## Machine Learning Features

Control ML-enhanced scanning:

```bash
# Enable ML-based tool selection
sniper scan -t example.com --ml-tool-selection

# Enable ML-based vulnerability prediction
sniper scan -t example.com --ml-vuln-prediction

# Train the ML model with new data
sniper ml train --data-file new_findings.json

# Evaluate ML model performance
sniper ml evaluate
```

## Distributed Scanning

For distributed scanning:

```bash
# Start a master node
sniper distributed start-master --host 0.0.0.0 --port 8080

# Start a worker node
sniper distributed start-worker --master-host 192.168.1.100 --master-port 8080

# Submit a task to the distributed system
sniper distributed submit-task -t example.com --type full

# Check task status
sniper distributed status --task-id abc123

# List all workers
sniper distributed list-workers
```

## Configuration Management

Manage Sniper configuration:

```bash
# Generate a default configuration file
sniper config init

# Specify a custom configuration file
sniper scan -t example.com --config my_config.yaml

# View current configuration
sniper config show

# Set a configuration value
sniper config set scan.default_depth 3

# Reset configuration to defaults
sniper config reset
```

## Report Management

Manage and manipulate reports:

```bash
# List available reports
sniper report list

# View a specific report
sniper report view --id abc123

# Compare two reports
sniper report compare --id1 abc123 --id2 def456

# Export a report to different format
sniper report export --id abc123 --format pdf

# Generate an executive summary
sniper report summary --id abc123
```

## Tool Management

Manage the integrated security tools:

```bash
# List all available tools
sniper tools list

# Show details about a specific tool
sniper tools info --name nmap

# Check if tools are installed
sniper tools check

# Install missing tools
sniper tools install

# Update tools
sniper tools update
```

## Examples

Here are some complete examples for common use cases:

### Basic Web Application Scan

```bash
sniper scan -t https://example.com -m normal --type webapp --output-file webapp_scan.html --output-format html
```

### Network Security Scan with Custom Ports

```bash
sniper scan -t 192.168.1.0/24 --type network --ports 22,80,443,3389,8080 --output-file network_scan.json
```

### Full Authenticated Scan with Rate Limiting

```bash
sniper scan -t https://example.com --type full --username admin --password secret --rate-limit 5 --output-file full_scan.html
```

### Reconnaissance with ML Enhancement

```bash
sniper scan -t example.com --type recon --ml-tool-selection --depth 4 --output-file recon_results.json
```

## Troubleshooting

If you encounter issues with the CLI:

```bash
# Run with debug logging
sniper scan -t example.com --log-level debug

# Check Sniper status
sniper status

# Verify tool integrations
sniper tools check

# Clean temporary files
sniper clean

# Get system information for bug reports
sniper system-info
```

## Next Steps

After learning the basics of the CLI, you may want to explore:

- [Configuration Guide](configuration.md) for customizing Sniper
- [Tool Integration](tool_integration.md) for details on available security tools
- [ML Capabilities](ml_capabilities.md) for leveraging machine learning features 