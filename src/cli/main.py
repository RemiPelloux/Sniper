import typer
import logging
import asyncio # Import asyncio
from typing import Optional
from typing_extensions import Annotated

# Absolute imports according to rules
from src.core.validation import validate_url
from src.core.logging_config import setup_logging
# Reconnaissance modules
from src.recon.dns_enum import enumerate_dns, get_domain_from_url
from src.recon.subdomain_finder import find_subdomains
from src.recon.whois_info import get_whois_info
from src.recon.ssl_analyzer import get_ssl_info
from src.recon.tech_fingerprint import fingerprint_technology
from src.recon.port_scanner import scan_ports

# Setup a logger for this module
logger = logging.getLogger(__name__)

# --- CLI Definition ---

# Use async version of Typer if commands are async
app = typer.Typer(
    name="pentest-cli",
    help="A CLI tool for penetration testing with ML capabilities.",
    add_completion=False, # Disable shell completion for now
)

# Make the command async to await fingerprint_technology
@app.command()
async def scan(
    target_url: Annotated[
        str,
        typer.Argument(
            ..., # Ellipsis makes it a required argument
            help="The target URL to scan (e.g., https://example.com).",
            metavar="URL",
        ),
    ],
    # TODO: Add flags to enable/disable specific recon/scan modules
) -> None:
    """
    Initiates a penetration test scan on the specified target URL.
    """
    logger.info(f"Received scan command for target: {target_url}")
    # Validate the URL first
    validated_url = validate_url(target_url)
    logger.debug(f"URL validation successful: {validated_url}")

    print(f"\n--- Starting Scan on: {validated_url} ---")
    logger.info(f"Initiating scan phases for: {validated_url}")

    # --- Reconnaissance Phase --- 
    print("\n--- Phase: Reconnaissance ---")
    domain = "<unknown>"
    try:
        domain = get_domain_from_url(validated_url)
        logger.info(f"Extracted domain for reconnaissance: {domain}")
        print(f"Target Domain: {domain}")

        # Run reconnaissance tasks (basic integration)
        # Note: Running sync tasks like nmap within async requires care (e.g., run_in_executor)
        # For simplicity now, we call them directly, but this will block the event loop.
        
        # DNS Enumeration
        dns_results = enumerate_dns(domain)
        print(f"\n[Recon] DNS Results:")
        print(f"  A Records: {dns_results.a_records}")
        print(f"  AAAA Records: {dns_results.aaaa_records}")
        print(f"  MX Records: {dns_results.mx_records}")
        print(f"  NS Records: {dns_results.ns_records}")
        print(f"  TXT Records: {dns_results.txt_records}")

        # Subdomain Discovery (Placeholder)
        subdomains = find_subdomains(domain)
        print(f"\n[Recon] Found Subdomains (Placeholder): {[s.name for s in subdomains]}")

        # WHOIS Info
        whois_info = get_whois_info(domain)
        print(f"\n[Recon] WHOIS Info:")
        if whois_info:
            print(f"  Registrar: {whois_info.registrar}")
            print(f"  Created: {whois_info.creation_date}")
            print(f"  Expires: {whois_info.expiration_date}")
            print(f"  Nameservers: {whois_info.name_servers}")
        else:
            print("  (Could not retrieve WHOIS info)")

        # SSL/TLS Info
        ssl_info = get_ssl_info(domain) # Uses default port 443
        print(f"\n[Recon] SSL/TLS Info (Port 443):")
        if ssl_info:
            print(f"  Issuer: {ssl_info.issuer}")
            print(f"  Subject: {ssl_info.subject}")
            print(f"  Valid From: {ssl_info.valid_from}")
            print(f"  Valid Until: {ssl_info.valid_until}")
            print(f"  SANs: {ssl_info.sans}")
        else:
            print("  (Could not retrieve SSL/TLS info)")

        # Technology Fingerprinting (Async)
        tech_info = await fingerprint_technology(validated_url)
        print(f"\n[Recon] Technology Info:")
        if tech_info:
            print(f"  Server Header: {tech_info.server_header}")
            print(f"  Powered By: {tech_info.powered_by_header}")
            print(f"  Detected Tech: {tech_info.detected_technologies}")
        else:
             print("  (Could not retrieve tech info)")

        # Port Scanning (Sync - potential blocker)
        # TODO: Run synchronous nmap scan in a separate thread/process executor
        # loop = asyncio.get_running_loop()
        # port_scan_results = await loop.run_in_executor(None, scan_ports, domain)
        port_scan_results = scan_ports(domain)
        print(f"\n[Recon] Port Scan Results (Top 1000 TCP):")
        if port_scan_results:
             print(f"  Host Status: {port_scan_results.status}")
             print(f"  Open Ports:")
             if port_scan_results.open_ports:
                 for port in port_scan_results.open_ports:
                    version = f' ({port.service_version})' if port.service_version else ''
                    print(f"    - {port.port_number}/tcp: {port.service_name}{version}")
             else:
                 print("    (No open TCP ports found)")
        else:
             print("  (Port scan failed or nmap not found)")

    except ValueError as e:
        logger.error(f"Failed to get domain from URL: {e}")
        print(f"Error: Could not determine domain from {validated_url}")
        # Exit or handle error appropriately
        return
    except Exception as e:
        logger.error(f"An unexpected error occurred during reconnaissance: {e}", exc_info=True)
        print(f"An unexpected error occurred during reconnaissance.")
        # Optionally continue to next phases or exit

    # --- Scanning Phase --- 
    print("\n--- Phase: Vulnerability Scanning ---")
    # TODO: Implement core scanning logic using scanner modules
    print("(Vulnerability scanning not yet implemented)")
    logger.warning("Vulnerability scanning phase not implemented.")

    # --- Reporting Phase --- 
    print("\n--- Phase: Reporting ---")
    # TODO: Implement reporting based on collected data
    print("(Report generation not yet implemented)")
    logger.warning("Reporting phase not implemented.")

    print("\n--- Scan Complete ---")


# State dictionary remains the same
state = {"verbose": False, "log_level": "INFO", "log_file": None}

@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output (DEBUG level)."),
    ] = False,
    log_file: Annotated[
        Optional[str],
        typer.Option("--log-file", help="Path to save log output."),
    ] = None,
) -> None:
    """
    PenTest CLI Tool with Machine Learning Augmentation.

    Use -v or --verbose for detailed debug logging.
    Use --log-file PATH to save logs to a file.
    """
    state["verbose"] = verbose
    state["log_file"] = log_file
    log_level = "DEBUG" if verbose else "INFO"
    state["log_level"] = log_level

    setup_logging(log_level=log_level, log_file=log_file)
    logger.debug("Logging initialized.")
    # Config loading could also happen here
    # logger.debug("Configuration loaded.")

def run_app():
    # Wrapper to handle the async nature if needed by entry point
    app()

if __name__ == "__main__":
    # If running the script directly, use asyncio.run for async commands
    # Note: Typer handles this automatically when run via the entry point
    # but direct execution of an async command needs an event loop.
    # However, Typer's default runner might handle this. Let's keep the standard call.
    app() 