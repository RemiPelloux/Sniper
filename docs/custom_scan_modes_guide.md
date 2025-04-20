# Custom Scan Modes Guide

This guide explains how to create, configure, and use custom scan modes in the Sniper Security Tool.

## What are Scan Modes?

Scan modes are predefined configurations that control how Sniper executes security scans. They define which modules are enabled, which tools are used, and with what settings. Using scan modes allows you to:

- Create specialized scan configurations for different target types
- Save and reuse common scanning patterns
- Share standardized scan configurations with your team
- Balance between speed, comprehensiveness, and stealth

## Available Built-in Scan Modes

Sniper comes with several built-in scan modes:

- **quick**: Fast reconnaissance with minimal footprint
- **standard**: Balanced scan for routine security assessments
- **comprehensive**: In-depth security assessment
- **stealth**: Low-profile scan designed to minimize detection
- **api**: Specialized scan for API endpoints and services

To list all available scan modes:

```bash
poetry run sniper scan modes
```

## Creating Custom Scan Modes

To create a custom scan mode, you need to add a new entry to the `config/scan_modes.yaml` file. Each scan mode follows this structure:

```yaml
mode_name:
  name: mode_name                         # The mode's name
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

### Available Modules

The following modules can be included in your custom scan mode:

- `technologies`: Detection of technologies, frameworks, and languages
- `subdomains`: Subdomain enumeration
- `ports`: Port scanning and service detection
- `web`: Web vulnerability scanning
- `directories`: Directory and file discovery

### Scan Depth

Scan depth controls the intensity and thoroughness of the scan:

- `quick`: Fast scan with minimal probing (suitable for initial reconnaissance)
- `standard`: Balanced scan (good for routine assessments)
- `comprehensive`: Thorough scan with extensive testing (slower but more comprehensive)

### Tool Configuration

Each tool can have its own set of options. Refer to the tool's documentation for available options.

## Example: Creating a Custom Scan Mode

Here's an example of a custom scan mode for WordPress websites:

```yaml
wordpress:
  name: wordpress
  description: "Specialized scan for WordPress sites with focus on known CMS vulnerabilities"
  target_types: ["url", "webapp"]
  modules:
    - technologies
    - web
    - directories
  settings:
    max_threads: 8
    timeout: 3600
    retries: 2
    scan_depth: standard
  tools:
    wappalyzer:
      enabled: true
      options: {}
    nmap:
      enabled: true
      options:
        ports: "80,443,8080,8443"
    zap:
      enabled: true
      options:
        active_scan: true
        scan_policy: "WordPress"
    dirsearch:
      enabled: true
      options:
        wordlist: "wordpress.txt"
        extensions: "php,txt,bak"
    wpscan:
      enabled: true
      options:
        enumerate: "vp,vt,tt,cb,dbe,u,m"
        random_user_agent: true
```

## Example: Supply Chain Security Assessment Mode

For analyzing dependencies, package security, and code vulnerabilities:

```yaml
supply_chain:
  name: supply_chain
  description: "Specialized scan for software supply chain security assessment"
  target_types: ["domain", "url", "repository", "package"]
  modules:
    - technologies
    - web
    - ports
  settings:
    max_threads: 8
    timeout: 4800
    retries: 2
    scan_depth: comprehensive
  tools:
    # Tool configuration for dependency and package analysis
    wappalyzer:
      enabled: true
      options:
        dependencies: true
    nmap:
      enabled: true
      options:
        ports: "21,22,80,443,3000,5000,8080,8443,9000"
    nuclei:
      enabled: true
      options:
        templates: "cves,vulnerabilities,exposed-panels"
        tag: "supply-chain,package-manager,ci"
    # Additional tool configurations...
```

## Using Custom Scan Modes

Once you've added your custom scan mode to `config/scan_modes.yaml`, you can use it with the scan command:

```bash
poetry run sniper scan run example.com --mode wordpress
```

You can still override specific parameters from your scan mode:

```bash
# Use wordpress mode but with comprehensive depth
poetry run sniper scan run example.com --mode wordpress --depth COMPREHENSIVE

# Use wordpress mode but add the subdomains module
poetry run sniper scan run example.com --mode wordpress --module subdomains
```

## Best Practices for Custom Scan Modes

1. **Start with an existing mode**: Base your custom modes on the built-in ones, making targeted changes.
2. **Test your scan modes**: Validate your custom scan modes on test targets before using them in production.
3. **Be specific with target types**: Define appropriate target types to ensure your scan mode is used correctly.
4. **Choose tool options carefully**: Only override the tool options that need customization; let default values work otherwise.
5. **Balance resources**: Set reasonable thread counts and timeouts based on your scanning needs.
6. **Document your scan modes**: Include clear descriptions explaining the purpose and suitable targets.
7. **Consider specialization**: Create specialized modes for specific target types (WordPress, APIs, etc.) rather than generic catch-all modes.

## Troubleshooting

If your custom scan mode isn't working as expected:

1. **Verify the YAML syntax**: Ensure your YAML is valid (use a YAML validator if needed).
2. **Check module names**: Ensure module names match exactly (case-sensitive).
3. **Tool availability**: Make sure all tools referenced in your scan mode are installed.
4. **Log level**: Run with increased verbosity to see detailed logs: `--log-level DEBUG`.

## Advanced: Tool-Specific Configurations

Each security tool supports different configuration options. Refer to the documentation for each tool to understand the available options. Here are some common options for popular tools:

### Nmap
- `ports`: Range of ports to scan (e.g., "80,443", "1-1000", "top1000")
- `timing_template`: Speed/aggressiveness (1-5, with 5 being most aggressive)
- `scripts`: Nmap scripts to run (e.g., "default", "vuln", "discovery")

### OWASP ZAP
- `active_scan`: Whether to perform active scanning (boolean)
- `ajax_spider`: Whether to use the AJAX spider (boolean)
- `scan_policy`: Scan policy to use (e.g., "Default Policy", "API-Minimal")

### Nuclei
- `templates`: Categories of templates to use (e.g., "cves,vulnerabilities,exposures")
- `severity`: Severity levels to scan for (e.g., "critical,high,medium")
- `rate_limit`: Maximum requests per second 