## Subfinder

Subfinder is a fast passive subdomain enumeration tool that can discover valid subdomains for websites. It uses passive sources, search engines, pastebins, internet archives, and more to find subdomains without sending traffic to the target server.

### Features

- Fast passive subdomain enumeration
- Supports multiple passive sources
- Ability to filter and sort results
- Configurable output formats

### Usage

#### Command Line

```bash
sniper recon subdomain --tool subfinder example.com
```

#### Python API

```python
from src.integrations import SubfinderIntegration

# Create an instance
subfinder = SubfinderIntegration()

# Run a scan
findings = await subfinder.scan("example.com")

# Process findings
for finding in findings:
    print(f"Found subdomain: {finding.subdomain}")
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| silent | Run silently, show only subdomains | False |
| sources | Comma-separated list of sources to use | All sources |
| resolvers | Path to a file containing DNS resolvers | System default |
| all | Use all sources including slow ones | False |
| max_time | Maximum time to run in seconds | 300 |
| rate_limit | Maximum number of HTTP requests per second | 150 |
| timeout_seconds | Timeout for the entire scan in seconds | 600 |

### Example

```bash
# Advanced usage with options
sniper recon subdomain --tool subfinder example.com --options '{"sources": "crtsh,dnsdumpster,bufferover", "all": true, "timeout_seconds": 900}'
```

### Integration with Other Tools

Subfinder results can be used as input for other tools in the Sniper toolkit by piping the discovered subdomains:

```bash
# Find subdomains then scan for open ports
sniper recon subdomain --tool subfinder example.com --pipe-to "scan ports"
```

This creates a powerful reconnaissance workflow where the output of Subfinder can be directly fed into other tools. 