# Sublist3r Integration

This document explains the integration between Sniper and Sublist3r, a popular tool for enumerating subdomains of websites using OSINT.

## Features

- Leverages multiple search engines (Google, Bing, Yahoo, etc.) and third-party services (VirusTotal, Netcraft, etc.) to find subdomains.
- Simple integration that runs the Sublist3r script and parses its output file.

## Prerequisites

Sublist3r requires **manual installation** as it's typically cloned from GitHub.

1.  **Clone the Sublist3r repository:**
    ```bash
    git clone https://github.com/aboul3la/Sublist3r.git /path/to/install/Sublist3r
    ```
    *(Replace `/path/to/install/Sublist3r` with your desired installation directory)*

2.  **Install Sublist3r's dependencies:**
    ```bash
    cd /path/to/install/Sublist3r
    pip install -r requirements.txt 
    ```

3.  **Ensure `sublist3r.py` is in your system PATH:**
    -   You can add the installation directory to your PATH environment variable.
    -   Alternatively, create a symbolic link from a directory already in your PATH (like `/usr/local/bin`) to `/path/to/install/Sublist3r/sublist3r.py`.

Sniper will look for `sublist3r.py` or `sublist3r` in the PATH.

## Configuration

No specific configuration is required in `.env` or environment variables for this integration.

## Usage Examples

### Basic Command Line Usage

```bash
# Run Sublist3r against a target domain
sniper scan -t example.com --tools sublist3r

# Increase the timeout (Sublist3r can sometimes be slow)
sniper scan -t example.com --tools sublist3r --options sublist3r:timeout_seconds=1200
```

### Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `timeout_seconds` | Timeout for the command execution | `600` |
| *Other Sublist3r options (e.g., threads `-t`, specific engines `-e`) are not currently exposed via Sniper options but could be added.* |

## Integration Details

The integration works by:

1. Checking if `sublist3r.py` or `sublist3r` is available in the PATH.
2. Creating a temporary file to store the output.
3. Running the Sublist3r script/executable with the target domain (`-d`) and output file (`-o`) arguments.
4. Waiting for the command to complete or timeout.
5. Reading the subdomains listed in the temporary output file.
6. Converting each found subdomain into a standardized `SubdomainFinding` object.
7. Deleting the temporary output file.

## Result Parsing

Sublist3r results are converted to the following finding structure:

- `title`: "Subdomain Found: [subdomain]"
- `severity`: `INFO` (Subdomain discovery is informational)
- `target`: The base domain that was scanned.
- `subdomain`: The specific subdomain discovered.
- `description`: Auto-generated description: "Discovered subdomain: [subdomain]"
- `raw_evidence`: The subdomain string itself.

## Troubleshooting

Common issues:

1. **`sublist3r.py` or `sublist3r` not found**: Ensure Sublist3r is correctly installed manually and that its location (or a symlink) is in your PATH.
2. **Dependency errors**: Make sure you installed the requirements for Sublist3r (`pip install -r requirements.txt` in its directory).
3. **Tool timeouts**: Sublist3r queries many external services and can be slow. Increase the `timeout_seconds` option if scans consistently time out.
4. **API key issues (for some engines)**: Some search engines used by Sublist3r might require API keys for extensive use, which Sublist3r manages internally. Frequent use might hit rate limits.

## Reference

- [Sublist3r GitHub Repository](https://github.com/aboul3la/Sublist3r) 