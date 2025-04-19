# Running Security Scans with Sniper

This guide provides detailed instructions on how to perform security scans using Sniper.

## Basic Scanning

### Quick Start

Run a basic scan against a target:

```bash
# Basic scan with default settings
sniper scan -t example.com

# Specify scan mode (fast, normal, thorough)
sniper scan -t example.com -m thorough

# Run a specific type of scan
sniper scan -t example.com --type webapp
```

### Scan Modes

Sniper supports different scan modes that control scan intensity:

- **Fast**: Quick surface-level scan (useful for initial reconnaissance)
- **Normal**: Standard depth scan (balanced between speed and coverage)
- **Thorough**: In-depth comprehensive scan (slower but more thorough)

```bash
# Fast scan mode
sniper scan -t example.com -m fast

# Normal scan mode (default)
sniper scan -t example.com -m normal

# Thorough scan mode
sniper scan -t example.com -m thorough
```

### Scan Types

Choose from different scan types based on your needs:

```bash
# Full scan (runs all scan modules)
sniper scan -t example.com --type full

# Web application scanning
sniper scan -t example.com --type webapp

# Network infrastructure scanning
sniper scan -t 192.168.1.0/24 --type network

# Reconnaissance only
sniper scan -t example.com --type recon

# Vulnerability scanning
sniper scan -t example.com --type vuln
```

## Target Specification

### Multiple Targets

Scan multiple targets at once:

```bash
# Comma-separated list of targets
sniper scan -t example.com,example.org,example.net

# Using a file containing targets (one per line)
sniper scan -t targets.txt
```

### IP Ranges and CIDR Notation

Network scanning with IP ranges:

```bash
# Scan a subnet
sniper scan -t 192.168.1.0/24 --type network

# Scan an IP range
sniper scan -t 192.168.1.1-192.168.1.254 --type network

# Scan specific IPs
sniper scan -t 192.168.1.1,192.168.1.10,192.168.1.15 --type network
```

### URL Path Targets

Specify URL paths for web application scans:

```bash
# Scan a specific application path
sniper scan -t https://example.com/webapp/

# Include multiple paths
sniper scan -t https://example.com/app1/,https://example.com/app2/
```

## Scan Customization

### Controlling Scan Depth

Adjust how deeply Sniper scans:

```bash
# Set scan depth (1-5, where 5 is deepest)
sniper scan -t example.com --depth 3

# For web apps, control crawling depth
sniper scan -t example.com --type webapp --crawl-depth 2
```

### Port Specification

Control which ports are scanned:

```bash
# Scan specific ports
sniper scan -t example.com --ports 80,443,8080,8443

# Scan port ranges
sniper scan -t example.com --ports 1-1000

# Scan common web ports
sniper scan -t example.com --common-web-ports

# Scan all ports
sniper scan -t example.com --all-ports
```

### Tool Selection

Choose which security tools to use:

```bash
# Specify tools to include
sniper scan -t example.com --tools nmap,zap,sqlmap

# Exclude specific tools
sniper scan -t example.com --exclude-tools nikto,wpscan

# Let ML select the most effective tools
sniper scan -t example.com --ml-tool-selection
```

## Authentication Options

### Basic Authentication

Authenticate with websites during scanning:

```bash
# Use username and password
sniper scan -t https://example.com --username admin --password secret

# Specify authentication method
sniper scan -t https://example.com --auth-method basic --username admin --password secret
```

### Session-Based Authentication

Use cookies or session tokens:

```bash
# Provide session cookie
sniper scan -t https://example.com --cookie "session=abc123"

# Using a cookie file
sniper scan -t https://example.com --cookie-file cookies.txt

# Provide custom headers for authentication
sniper scan -t https://example.com --header "Authorization: Bearer token123"
```

### Authentication Scripting

For complex authentication flows:

```bash
# Use an authentication script
sniper scan -t https://example.com --auth-script login_script.js

# Record an authentication sequence
sniper auth record -t https://example.com --output-script login_script.js
```

## Rate Limiting and Performance

### Controlling Scan Speed

Adjust scanning intensity to avoid overloading targets:

```bash
# Set rate limiting (requests per second)
sniper scan -t example.com --rate-limit 10

# Adjust concurrent requests
sniper scan -t example.com --concurrent-requests 5

# Add delay between requests (in milliseconds)
sniper scan -t example.com --request-delay 200
```

### Resource Management

Control Sniper's resource usage:

```bash
# Limit CPU usage (percentage)
sniper scan -t example.com --max-cpu 75

# Limit memory usage (MB)
sniper scan -t example.com --max-memory 2048

# Set thread count
sniper scan -t example.com --threads 4
```

## Scan Output and Reporting

### Output Formats

Specify report formats:

```bash
# Generate HTML report
sniper scan -t example.com --output-format html --output-file report.html

# Generate JSON output
sniper scan -t example.com --output-format json --output-file results.json

# Generate markdown report
sniper scan -t example.com --output-format markdown --output-file report.md

# Generate multiple formats
sniper scan -t example.com --output-format html,json,markdown
```

### Report Customization

Customize the appearance and content of reports:

```bash
# Use a specific report template
sniper scan -t example.com --report-template executive

# Include evidence details
sniper scan -t example.com --include-evidence

# Set report title
sniper scan -t example.com --report-title "Security Assessment Report"

# Include executive summary
sniper scan -t example.com --executive-summary
```

### Finding Filtering

Filter out findings in reports:

```bash
# Filter by severity (critical, high, medium, low, info)
sniper scan -t example.com --min-severity high

# Filter by confidence level
sniper scan -t example.com --min-confidence medium

# Filter by finding type
sniper scan -t example.com --finding-types xss,sqli,csrf
```

## Advanced Features

### ML-Enhanced Scanning

Leverage machine learning capabilities:

```bash
# Enable ML-based tool selection
sniper scan -t example.com --ml-tool-selection

# Enable ML-based vulnerability prediction
sniper scan -t example.com --ml-vuln-prediction

# Enable pattern recognition
sniper scan -t example.com --ml-pattern-learning

# Enable all ML features
sniper scan -t example.com --ml-all
```

### Autonomous Testing

Use autonomous testing capabilities:

```bash
# Run autonomous testing for XSS
sniper autonomous-test -t example.com --vulnerability-type xss

# Run autonomous testing with custom payloads
sniper autonomous-test -t example.com --vulnerability-type sqli --custom-payloads payloads.txt

# Comprehensive autonomous scan
sniper autonomous-test -t example.com --comprehensive
```

### Integration with Other Tools

Customize how Sniper integrates with external tools:

```bash
# Specify ZAP API URL
sniper scan -t example.com --zap-api-url http://localhost:8080

# Use custom Nmap parameters
sniper scan -t example.com --nmap-params "-sS -T4 -A"

# Specify SQLMap options
sniper scan -t example.com --sqlmap-options "--risk=3 --level=5"
```

## Scheduled and Recurring Scans

### Scheduling Scans

Set up scans to run at specific times:

```bash
# Schedule a one-time scan
sniper schedule-scan -t example.com --time "2023-12-31 23:59:59"

# Schedule a recurring scan (daily at 2 AM)
sniper schedule-scan -t example.com --cron "0 2 * * *"

# List scheduled scans
sniper schedule-list

# Remove a scheduled scan
sniper schedule-remove --id abc123
```

### Scan Templates

Save scan configurations for reuse:

```bash
# Save current scan settings as a template
sniper scan -t example.com --type webapp --save-template webapp-scan

# List available templates
sniper templates list

# Run a scan using a template
sniper scan --template webapp-scan -t example.com

# Delete a template
sniper templates delete webapp-scan
```

## Distributed Scanning

### Running Distributed Scans

Execute scans across multiple worker nodes:

```bash
# Submit a distributed scan
sniper distributed submit-task -t example.com --type full

# Submit with specific worker assignment
sniper distributed submit-task -t example.com --worker worker-1

# Set task priority
sniper distributed submit-task -t example.com --priority high
```

### Monitoring Distributed Scans

Track scan progress:

```bash
# Check task status
sniper distributed task-status --task-id abc123

# Get task results
sniper distributed get-results --task-id abc123

# View task logs
sniper distributed task-logs --task-id abc123
```

## Example Scanning Scenarios

### Web Application Security Assessment

```bash
# Comprehensive web application scan
sniper scan -t https://example.com/webapp/ \
  --type webapp \
  --username admin --password secret \
  --crawl-depth 3 \
  --output-format html,json \
  --output-file webapp_security_assessment.html \
  --include-evidence \
  --ml-vuln-prediction
```

### Network Infrastructure Audit

```bash
# Network security scan
sniper scan -t 192.168.1.0/24 \
  --type network \
  --ports 1-1000,3389,5900-5910 \
  --rate-limit 100 \
  --output-format html \
  --output-file network_audit.html
```

### Reconnaissance-Only Assessment

```bash
# Information gathering only
sniper scan -t example.com \
  --type recon \
  --depth 4 \
  --include-tools amass,subfinder,httpx \
  --output-format json \
  --output-file recon_results.json
```

### DevSecOps Pipeline Integration

```bash
# CI/CD friendly scan
sniper scan -t https://staging.example.com \
  --type webapp \
  --ci-mode \
  --min-severity high \
  --fail-on-critical \
  --output-format json,junit \
  --output-file ci_results.json
```

### API Security Testing

```bash
# API security scan
sniper scan -t https://api.example.com \
  --type api \
  --auth-header "Authorization: Bearer token123" \
  --api-spec openapi.yaml \
  --output-format html \
  --output-file api_security_report.html
```

## Troubleshooting

### Common Scan Issues

1. **Scan taking too long**:
   ```bash
   # Reduce scan depth
   sniper scan -t example.com --depth 2
   
   # Limit the scope
   sniper scan -t example.com --exclude-paths /blog,/forum
   
   # Use fast mode
   sniper scan -t example.com -m fast
   ```

2. **Target connection issues**:
   ```bash
   # Check connectivity
   sniper check-connectivity -t example.com
   
   # Increase timeout values
   sniper scan -t example.com --timeout 120
   
   # Use proxy
   sniper scan -t example.com --proxy http://proxy.example.com:8080
   ```

3. **Authentication failures**:
   ```bash
   # Test authentication separately
   sniper test-auth -t https://example.com --username admin --password secret
   
   # Debug authentication process
   sniper scan -t example.com --auth-debug
   ```

### Scan Logs and Monitoring

```bash
# Enable verbose logging
sniper scan -t example.com -v

# Set specific log level
sniper scan -t example.com --log-level debug

# Save logs to file
sniper scan -t example.com --log-file scan_log.txt

# View current scan status
sniper status
```

## Next Steps

After running scans, you may want to explore:

- [Report Generation](report_generation.md) for customizing and analyzing reports
- [Finding Analysis](finding_analysis.md) for understanding and triaging findings
- [ML Capabilities](ml_capabilities.md) for enhancing scan effectiveness with machine learning 