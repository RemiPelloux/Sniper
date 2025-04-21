# Scan Modes in Sniper

Scan modes are preconfigured scanning profiles that provide a balance of speed, thoroughness, and stealth for different scanning scenarios. They allow users to quickly select an appropriate scanning strategy without needing to manually configure individual modules and settings.

## Available Scan Modes

Sniper includes the following predefined scan modes:

### Quick Mode

**Purpose:** Fast reconnaissance with minimal footprint, suitable for initial target assessment.

**Configuration:**
- **Modules:** Technologies detection, basic port scanning
- **Performance:** 5 threads, 10-minute timeout, minimal retries
- **Tools:** 
  - Wappalyzer for technology fingerprinting
  - Nmap with limited port range (80, 443, 8080, 8443)

**Ideal for:**
- Initial reconnaissance
- Time-constrained assessments
- Getting a quick overview of a target

**Example usage:**
```bash
poetry run sniper scan run example.com --mode quick
```

### Standard Mode

**Purpose:** Balanced scan suitable for routine security assessments.

**Configuration:**
- **Modules:** Technologies, subdomains, ports, web vulnerabilities, directory discovery
- **Performance:** 10 threads, 1-hour timeout, moderate retries
- **Tools:**
  - Wappalyzer for technology fingerprinting
  - Sublist3r for subdomain enumeration
  - Nmap with top 1000 ports
  - OWASP ZAP for active vulnerability scanning (without AJAX spider)
  - Dirsearch with common wordlist

**Ideal for:**
- Regular security assessments
- Routine security checks
- Vulnerability scanning with reasonable depth

**Example usage:**
```bash
poetry run sniper scan run example.com --mode standard
```

### Comprehensive Mode

**Purpose:** In-depth security assessment with thorough testing and vulnerability scanning.

**Configuration:**
- **Modules:** Technologies, subdomains, ports, web vulnerabilities, directory discovery
- **Performance:** 15 threads, 2-hour timeout, maximum retries
- **Tools:**
  - Multiple subdomain enumeration tools (Amass, Subfinder)
  - Nmap with all ports (1-65535) and vulnerability scripts
  - OWASP ZAP with active scanning and AJAX spider
  - Dirsearch with extensive wordlist
  - Nuclei for known vulnerability checks
  - SQLMap for SQL injection testing

**Ideal for:**
- Penetration testing
- Full security audits
- Thorough vulnerability assessments

**Example usage:**
```bash
poetry run sniper scan run example.com --mode comprehensive
```

### Stealth Mode

**Purpose:** Low-profile scan designed to minimize detection chance.

**Configuration:**
- **Modules:** Technologies, limited port scanning, passive web assessment
- **Performance:** 2 threads, longer timeouts, deliberate delays between requests
- **Tools:**
  - Httpx with silent mode
  - Nmap with timing template 1 (slowest)
  - ZAP in passive mode only

**Ideal for:**
- Situations where avoiding detection is critical
- Sensitive targets
- Initial reconnaissance in red team exercises

**Example usage:**
```bash
poetry run sniper scan run example.com --mode stealth
```

### API Mode

**Purpose:** Specialized scan for API endpoints and services.

**Configuration:**
- **Modules:** Technologies, web vulnerabilities
- **Performance:** 8 threads, 40-minute timeout
- **Tools:**
  - Wappalyzer for technology fingerprinting
  - Httpx for API endpoint discovery
  - Nuclei with API-specific templates
  - Ffuf for API endpoint fuzzing

**Ideal for:**
- API security testing
- REST/GraphQL endpoints assessment
- Microservice architecture scanning

**Example usage:**
```bash
poetry run sniper scan run https://api.example.com --mode api
```

## DVWA (Damn Vulnerable Web Application) Scanning

In addition to the existing scan modes, Sniper now provides specialized scanning capabilities for DVWA (Damn Vulnerable Web Application), which is a deliberately vulnerable web application used for security training and testing.

### Using the DVWA Scan Command

The dedicated DVWA scan command provides an optimized scanning experience specifically for DVWA instances:

```bash
sniper scan dvwa [URL] [OPTIONS]
```

**Example Usage:**
```bash
# Scan a local DVWA instance
sniper scan dvwa http://localhost

# Scan with a custom output file
sniper scan dvwa http://example.com:80 --output dvwa-findings.txt

# Scan with JSON output format
sniper scan dvwa http://localhost --json

# Scan with a specific security level
sniper scan dvwa http://localhost --security-level medium

# Scan without automatic login
sniper scan dvwa http://localhost --no-login
```

**Available Options:**
- `--output`, `-o`: Output file for detailed findings
- `--json`, `-j`: Output in JSON format
- `--max-urls`: Maximum number of URLs to crawl (default: 100)
- `--wait`: Wait time in seconds for JavaScript to load (default: 3)
- `--login/--no-login`: Automatically login to DVWA before scanning (default: login enabled)
- `--security-level`: DVWA security level to set before scanning (low, medium, high, impossible) (default: low)

### Using the DVWA Scan Mode

You can also use the DVWA scan mode with the general scan command:

```bash
sniper scan run [URL] --mode dvwa
```

The DVWA scan mode is optimized with the following configurations:
- Focuses on technologies, web scanning, and directory discovery
- Optimized for testing PHP-based vulnerabilities
- Tests for XSS, SQL injection, command injection, path traversal, and file inclusion vulnerabilities
- Uses specific tools and settings optimized for DVWA's architecture

## Usage

### Listing Available Scan Modes

To see all available scan modes with descriptions:

```bash
poetry run sniper scan modes
```

### Running a Scan with a Specific Mode

```bash
poetry run sniper scan run <target> --mode <mode_name>
```

### Overriding Mode Settings

You can override specific settings from a scan mode:

```bash
# Use quick mode but with a different depth
poetry run sniper scan run example.com --mode quick --depth COMPREHENSIVE

# Use stealth mode but add an additional module
poetry run sniper scan run example.com --mode stealth --module directories
```

## Creating Custom Scan Modes

Custom scan modes can be defined by creating or modifying the `config/scan_modes.yaml` file.

### Scan Mode Configuration Schema

```yaml
mode_name:
  name: mode_name                         # Name of the scan mode
  description: "Mode description"         # Human-readable description
  target_types: ["domain", "url", "ip"]   # Supported target types
  modules:                                # List of modules to enable
    - technologies
    - subdomains
    - ports
    - web
    - directories
  settings:                               # General scan settings
    max_threads: 10                       # Maximum parallel operations
    timeout: 3600                         # Overall timeout in seconds
    retries: 2                            # Number of retries for failed operations
    scan_depth: standard                  # Scan depth (quick, standard, comprehensive)
    delay: 0                              # Delay between requests in seconds (0 for none)
  tools:                                  # Tool-specific configurations
    tool_name:
      enabled: true                       # Whether the tool is enabled
      options:                            # Tool-specific options
        option1: value1
        option2: value2
```

### Example Custom Scan Mode

```yaml
webservice:
  name: webservice
  description: "Focused scan for web services and applications"
  target_types: ["url", "webapp"]
  modules:
    - technologies
    - web
    - directories
  settings:
    max_threads: 8
    timeout: 1800
    retries: 2
    scan_depth: standard
  tools:
    wappalyzer:
      enabled: true
      options: {}
    zap:
      enabled: true
      options:
        active_scan: true
        ajax_spider: true
        scan_policy: "Web App Scan"
    dirsearch:
      enabled: true
      options:
        wordlist: "webapp.txt"
        extensions: "php,asp,aspx,jsp,html,js"
    nuclei:
      enabled: true
      options:
        templates: "cves,vulnerabilities,exposures,technologies"
```

## Scan Mode Implementation Details

Scan modes are loaded from the `config/scan_modes.yaml` file and managed by the `ScanModeManager` class in `src/core/scan_mode_manager.py`. The manager provides methods to retrieve and filter scan modes based on various criteria.

When a scan is executed with a specific mode, the scan runner:

1. Retrieves the scan mode configuration from the `ScanModeManager`
2. Applies the mode's module list, replacing the default list
3. Sets the depth and other scan parameters based on the mode settings
4. Configures each tool with the options specified in the mode
5. Executes the scan using the mode's configuration

This allows for a flexible and extensible system where users can easily create and share scan profiles for specific use cases and targets. 