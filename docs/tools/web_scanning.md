## Dirsearch

Dirsearch is an advanced web path scanner for directory enumeration. It's designed to discover hidden files and directories on web servers, helping identify potential security issues and administrative interfaces that might be exposed.

### Features

- Fast directory/file enumeration with multithreading
- Support for multiple file extensions
- Smart recursion capabilities for deeper scanning
- Customizable wordlists and fine-grained parameter control
- Automatic filtering of certain response codes

### Usage

#### Command Line

```bash
sniper scan directories --tool dirsearch https://example.com
```

#### Python API

```python
from src.integrations import DirsearchIntegration

# Create an instance
dirsearch = DirsearchIntegration()

# Run a scan
findings = await dirsearch.scan("https://example.com")

# Process findings
for finding in findings:
    print(f"Found URL: {finding.url} - Status: {finding.status_code}")
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| extensions | File extensions to search for | php,html,js,txt,bak,config,json,xml |
| recursive | Enable recursive scanning | true |
| exclude_status | Status codes to ignore | 400,404,500-599 |
| threads | Number of threads to use | 30 |
| wordlist | Wordlist to use for discovery | default |
| timeout_seconds | Timeout for the entire scan in seconds | 1800 |

### Example

```bash
# Advanced usage with options
sniper scan directories --tool dirsearch https://example.com --options '{"extensions": "php,asp,aspx,jsp", "threads": 50, "wordlist": "large"}'
```

### Integration with Other Tools

Dirsearch results can be used as input for other tools in the Sniper toolkit by piping the discovered paths:

```bash
# Find directories then scan for vulnerabilities
sniper scan directories --tool dirsearch https://example.com --pipe-to "scan vulnerabilities"
```

This creates a powerful workflow where directories discovered by Dirsearch are automatically scanned for vulnerabilities. 