# Autonomous Testing with Sniper

This guide explains how to use Sniper's autonomous testing capabilities to discover and validate security vulnerabilities with minimal human intervention.

## Overview

Sniper's autonomous testing module can:

- Self-discover and test for various vulnerability types
- Generate and mutate payloads based on context
- Learn from previous testing results
- Perform comprehensive security assessments with minimal configuration

## Basic Autonomous Testing

### Testing for Specific Vulnerabilities

Test for individual vulnerability types:

```bash
# Test for XSS vulnerabilities
sniper autonomous-test -t https://example.com --vulnerability-type xss

# Test for SQL injection
sniper autonomous-test -t https://example.com --vulnerability-type sqli

# Test for command injection
sniper autonomous-test -t https://example.com --vulnerability-type cmdi
```

### Supported Vulnerability Types

Sniper can autonomously test for these vulnerability types:

- `xss` - Cross-Site Scripting
- `sqli` - SQL Injection
- `cmdi` - Command Injection
- `ssrf` - Server-Side Request Forgery
- `open-redirect` - Open Redirects
- `path-traversal` - Path Traversal
- `jwt` - JWT Vulnerabilities
- `xml` - XML Injection
- `nosqli` - NoSQL Injection
- `csrf` - Cross-Site Request Forgery
- `cookie` - Cookie Security Issues
- `cors` - CORS Misconfiguration

### Comprehensive Testing

Test for multiple vulnerability types at once:

```bash
# Test for all supported vulnerability types
sniper autonomous-test -t https://example.com --comprehensive

# Test for specific vulnerability categories
sniper autonomous-test -t https://example.com --vuln-categories injection,authentication
```

## Testing Configuration

### Controlling Test Intensity

Adjust the depth and breadth of testing:

```bash
# Set the number of payloads to test per vulnerability type
sniper autonomous-test -t https://example.com --payload-count 20

# Set the maximum depth for crawling/testing
sniper autonomous-test -t https://example.com --max-depth 3

# Control test intensity (1-5, where 5 is most intense)
sniper autonomous-test -t https://example.com --intensity 4
```

### Authentication for Testing

Authenticate with the target before testing:

```bash
# Using username and password
sniper autonomous-test -t https://example.com --username admin --password secret

# Using session cookie
sniper autonomous-test -t https://example.com --cookie "session=abc123"

# Using a bearer token
sniper autonomous-test -t https://example.com --header "Authorization: Bearer token123"
```

### Specifying Test Targets

Test specific parts of the application:

```bash
# Test a specific URL path
sniper autonomous-test -t https://example.com/path/

# Test specific parameters
sniper autonomous-test -t https://example.com --parameters "id,user,search"

# Test specific forms
sniper autonomous-test -t https://example.com --forms "/login,/search"

# Test API endpoints
sniper autonomous-test -t https://example.com/api/ --api-mode
```

## Advanced Features

### Custom Payload Generation

Control how payloads are generated and used:

```bash
# Use custom payloads from a file
sniper autonomous-test -t https://example.com --vulnerability-type xss --custom-payloads xss_payloads.txt

# Enable payload mutation
sniper autonomous-test -t https://example.com --enable-mutations

# Set mutation complexity (1-5)
sniper autonomous-test -t https://example.com --mutation-complexity 3

# Generate context-aware payloads
sniper autonomous-test -t https://example.com --context-aware
```

### Rate Limiting

Control test speed to avoid overwhelming the target:

```bash
# Set requests per second
sniper autonomous-test -t https://example.com --rate-limit 10

# Add delay between requests (milliseconds)
sniper autonomous-test -t https://example.com --request-delay 500

# Set connection timeout (seconds)
sniper autonomous-test -t https://example.com --timeout 30
```

### Machine Learning Integration

Enhance testing with machine learning:

```bash
# Use ML to prioritize test paths
sniper autonomous-test -t https://example.com --ml-path-prioritization

# Use ML to generate more effective payloads
sniper autonomous-test -t https://example.com --ml-enhanced-payloads

# Use ML to predict vulnerability likelihood
sniper autonomous-test -t https://example.com --ml-prediction
```

## Output and Reporting

### Basic Output Control

Configure how results are reported:

```bash
# Specify output format
sniper autonomous-test -t https://example.com --output-format json

# Save results to a file
sniper autonomous-test -t https://example.com --output-file results.json

# Control verbosity
sniper autonomous-test -t https://example.com --verbosity detailed
```

### Evidence Collection

Control how vulnerability evidence is collected:

```bash
# Include detailed evidence
sniper autonomous-test -t https://example.com --include-evidence

# Capture screenshots of vulnerabilities (where applicable)
sniper autonomous-test -t https://example.com --capture-screenshots

# Include HTTP request/response details
sniper autonomous-test -t https://example.com --include-http-details
```

### Result Filtering

Filter which results are included in output:

```bash
# Filter by minimum severity
sniper autonomous-test -t https://example.com --min-severity high

# Filter by minimum confidence
sniper autonomous-test -t https://example.com --min-confidence medium

# Only report confirmed vulnerabilities
sniper autonomous-test -t https://example.com --confirmed-only
```

## Distributed Autonomous Testing

Leverage distributed architecture for larger tests:

```bash
# Submit an autonomous test to the distributed system
sniper distributed submit-task -t example.com --type autonomous --vulnerability-type xss

# Run comprehensive autonomous testing across distributed workers
sniper distributed submit-task -t example.com --type autonomous --comprehensive

# Allocate specific resources for intensive testing
sniper distributed submit-task -t example.com --type autonomous --resource-profile high-memory
```

## Safe Exploitation

Configure how far testing goes:

```bash
# Enable/disable safe exploitation (proof of concept)
sniper autonomous-test -t https://example.com --safe-exploitation

# Set exploitation depth (1-3)
sniper autonomous-test -t https://example.com --exploitation-depth 2

# Generate exploitation chains
sniper autonomous-test -t https://example.com --chain-exploits
```

## Example Use Cases

### Comprehensive Web Application Assessment

```bash
# Full autonomous testing of a web application
sniper autonomous-test -t https://example.com \
  --comprehensive \
  --username admin --password secret \
  --max-depth 3 \
  --include-evidence \
  --output-format html \
  --output-file autonomous_assessment.html \
  --ml-enhanced-payloads
```

### API Security Testing

```bash
# Autonomous testing of a REST API
sniper autonomous-test -t https://api.example.com \
  --api-mode \
  --header "Authorization: Bearer token123" \
  --vulnerability-type sqli,cmdi,nosqli \
  --payload-count 30 \
  --output-format json \
  --output-file api_security_test.json
```

### Targeted Testing with Custom Payloads

```bash
# Targeted XSS testing with custom payloads
sniper autonomous-test -t https://example.com/search \
  --vulnerability-type xss \
  --parameters "q,filter" \
  --custom-payloads xss_advanced_payloads.txt \
  --enable-mutations \
  --include-evidence \
  --capture-screenshots \
  --output-file xss_results.html
```

### Integration with DevSecOps Pipeline

```bash
# CI/CD friendly autonomous testing
sniper autonomous-test -t https://staging.example.com \
  --vulnerability-type xss,sqli,cmdi \
  --ci-mode \
  --min-severity high \
  --confirmed-only \
  --output-format json,junit \
  --output-file ci_security_results.json
```

## Tool Discovery

Discover and evaluate new security testing tools:

```bash
# Discover new security tools
sniper tool-discovery search --max-tools 5

# Get recommended tools for a specific vulnerability type
sniper tool-discovery recommend --vulnerability-type xss

# Evaluate a specific tool
sniper tool-discovery evaluate --tool-name xsshunter
```

## Payload Generation

Generate security testing payloads:

```bash
# Generate XSS payloads
sniper generate-payloads --vulnerability-type xss --count 20

# Generate SQL injection payloads
sniper generate-payloads --vulnerability-type sqli --count 15 --output-file sqli_payloads.txt

# Generate context-aware payloads
sniper generate-payloads --vulnerability-type xss --context form --count 10
```

## Training and Model Management

Manage the autonomous testing learning capabilities:

```bash
# Train on previous scan results
sniper autonomous-train --from-results previous_results.json

# View training status
sniper autonomous-status

# Reset learning models
sniper autonomous-reset

# Import trained models
sniper autonomous-import --file trained_models.zip
```

## Troubleshooting

### Common Issues

1. **Testing too aggressive**:
   ```bash
   # Reduce intensity
   sniper autonomous-test -t example.com --intensity 2
   
   # Add more rate limiting
   sniper autonomous-test -t example.com --rate-limit 5 --request-delay 1000
   ```

2. **False positives**:
   ```bash
   # Increase confidence threshold
   sniper autonomous-test -t example.com --min-confidence high
   
   # Enable verification mode
   sniper autonomous-test -t example.com --verify-findings
   ```

3. **Authentication issues**:
   ```bash
   # Test authentication separately
   sniper test-auth -t https://example.com --username admin --password secret
   
   # Increase authentication timeout
   sniper autonomous-test -t example.com --auth-timeout 60
   ```

### Logging and Debugging

```bash
# Enable debug logging
sniper autonomous-test -t example.com --log-level debug

# Save debug logs to file
sniper autonomous-test -t example.com --log-file autonomous_debug.log

# Enable step-by-step mode
sniper autonomous-test -t example.com --step-by-step
```

## Best Practices

- Always get proper authorization before testing
- Start with low intensity and increase gradually
- Use rate limiting to avoid overwhelming the target
- Begin with specific vulnerability types before comprehensive testing
- Enable evidence collection for better understanding of findings
- Use ML-enhanced testing for more effective payload generation
- Review and verify findings to eliminate false positives

## Next Steps

After running autonomous tests, you may want to explore:

- [Report Generation](report_generation.md) to create detailed reports
- [ML Capabilities](ml_capabilities.md) to enhance testing with machine learning
- [Finding Analysis](finding_analysis.md) to analyze and understand results 