import logging
import typer
from enum import Enum
from typing import List, Optional

# Import core modules
from src.core.validation import validate_target_url
from src.results import ResultNormalizer

# Import tool integrations
from src.integrations import (
    NmapIntegration,
    ZapIntegration,
    Sublist3rIntegration,
    WappalyzerIntegration,
    DirsearchIntegration,
)

app = typer.Typer(name="scan", help="Perform security scans on targets.")
log = logging.getLogger(__name__)


class ScanDepth(str, Enum):
    """Scan depth options for controlling scan intensity."""
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class ScanModule(str, Enum):
    """Available scan modules that can be enabled or disabled."""
    PORTS = "ports"
    WEB = "web"
    SUBDOMAINS = "subdomains"
    TECHNOLOGIES = "technologies"
    DIRECTORIES = "directories"
    ALL = "all"


@app.command("run")
def run_scan(
    target: str = typer.Argument(
        ...,
        help="Target URL to scan (must include scheme, e.g., https://example.com).",
        callback=validate_target_url,
    ),
    depth: ScanDepth = typer.Option(
        ScanDepth.STANDARD,
        "--depth", "-d",
        help="Scan depth/intensity level.",
    ),
    modules: List[ScanModule] = typer.Option(
        [ScanModule.ALL],
        "--modules", "-m",
        help="Specific modules to run (default is all).",
    ),
    timeout: int = typer.Option(
        3600,
        "--timeout", "-t",
        help="Scan timeout in seconds (default: 1 hour).",
    ),
    threads: int = typer.Option(
        5,
        "--threads",
        help="Number of threads to use for parallel scanning (default: 5).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for scan results (without extension).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results in JSON format in addition to human-readable format.",
    ),
    ignore_ssl: bool = typer.Option(
        False,
        "--ignore-ssl",
        help="Ignore SSL certificate errors during scanning.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output.",
    ),
) -> None:
    """Run a security scan on the specified target.
    
    This command orchestrates multiple security tools to perform comprehensive scanning
    on the provided target. The scan can be customized with different depth levels,
    specific modules, and other parameters.
    """
    log.info(f"Initiating {depth.value} scan on target: {target}")
    
    # Configure scan based on depth
    configure_scan_parameters(depth, threads, timeout)
    
    # Determine which modules to run
    scan_modules = resolve_scan_modules(modules)
    log.info(f"Enabled modules: {', '.join(scan_modules)}")
    
    # Initialize the result normalizer for processing findings
    normalizer = ResultNormalizer()
    all_findings = []
    
    try:
        # Step 1: Run passive reconnaissance first (technologies, subdomains)
        if ScanModule.TECHNOLOGIES.value in scan_modules:
            typer.echo("Detecting technologies...")
            findings = run_technology_scan(target, ignore_ssl)
            all_findings.extend(findings)
            
        if ScanModule.SUBDOMAINS.value in scan_modules:
            typer.echo("Discovering subdomains...")
            findings = run_subdomain_scan(target)
            all_findings.extend(findings)
            
        # Step 2: Run active reconnaissance (ports, web vulnerabilities, directories)
        if ScanModule.PORTS.value in scan_modules:
            typer.echo("Scanning ports...")
            findings = run_port_scan(target, depth)
            all_findings.extend(findings)
            
        if ScanModule.WEB.value in scan_modules:
            typer.echo("Scanning for web vulnerabilities...")
            findings = run_web_scan(target, depth, ignore_ssl)
            all_findings.extend(findings)
            
        if ScanModule.DIRECTORIES.value in scan_modules:
            typer.echo("Discovering directories...")
            findings = run_directory_scan(target, depth, ignore_ssl)
            all_findings.extend(findings)
        
        # Process and normalize all findings
        typer.echo("Processing and normalizing findings...")
        normalized_findings = normalizer.normalize_findings(all_findings)
        deduplicated_findings = normalizer.deduplicate_findings(normalized_findings)
        correlated_findings = normalizer.correlate_findings(deduplicated_findings)
        
        # Output results
        typer.echo(f"Scan completed. Found {len(deduplicated_findings)} unique findings.")
        output_scan_results(correlated_findings, output, json_output)
        
    except Exception as e:
        typer.echo(f"Error during scan: {str(e)}", err=True)
        log.error(f"Scan failed: {str(e)}", exc_info=True)
        raise typer.Exit(code=1)


def configure_scan_parameters(depth: ScanDepth, threads: int, timeout: int) -> None:
    """Configure scan parameters based on scan depth."""
    # This would adjust parameters for each tool based on the selected depth
    # For now, we'll just log the configuration
    log.debug(f"Configuring scan with depth={depth.value}, threads={threads}, timeout={timeout}")


def resolve_scan_modules(modules: List[ScanModule]) -> List[str]:
    """Resolve the list of modules to run based on user input."""
    if ScanModule.ALL in modules:
        return [m.value for m in ScanModule if m != ScanModule.ALL]
    return [m.value for m in modules]


def run_technology_scan(target: str, ignore_ssl: bool) -> List:
    """Run technology detection scan using Wappalyzer."""
    log.debug(f"Running technology scan against {target}")
    scanner = WappalyzerIntegration()
    return scanner.scan(target, verify_ssl=not ignore_ssl)


def run_subdomain_scan(target: str) -> List:
    """Run subdomain discovery using Sublist3r."""
    log.debug(f"Running subdomain scan against {target}")
    scanner = Sublist3rIntegration()
    return scanner.scan(target)


def run_port_scan(target: str, depth: ScanDepth) -> List:
    """Run port scan using Nmap."""
    log.debug(f"Running port scan against {target} with depth {depth.value}")
    scanner = NmapIntegration()
    
    # Configure scan parameters based on depth
    ports = None
    if depth == ScanDepth.QUICK:
        ports = "22,80,443,8080,8443"
    elif depth == ScanDepth.STANDARD:
        ports = "top1000"
    # Comprehensive uses default (all ports)
    
    return scanner.scan(target, ports=ports)


def run_web_scan(target: str, depth: ScanDepth, ignore_ssl: bool) -> List:
    """Run web vulnerability scan using OWASP ZAP."""
    log.debug(f"Running web scan against {target} with depth {depth.value}")
    scanner = ZapIntegration()
    
    # Configure scan parameters based on depth
    active_scan = depth != ScanDepth.QUICK
    ajax_spider = depth == ScanDepth.COMPREHENSIVE
    
    return scanner.scan(target, active_scan=active_scan, ajax_spider=ajax_spider, verify_ssl=not ignore_ssl)


def run_directory_scan(target: str, depth: ScanDepth, ignore_ssl: bool) -> List:
    """Run directory discovery using Dirsearch."""
    log.debug(f"Running directory scan against {target} with depth {depth.value}")
    scanner = DirsearchIntegration()
    
    # Configure scan parameters based on depth
    wordlist_size = "small"
    if depth == ScanDepth.STANDARD:
        wordlist_size = "medium"
    elif depth == ScanDepth.COMPREHENSIVE:
        wordlist_size = "large"
    
    return scanner.scan(target, wordlist_size=wordlist_size, verify_ssl=not ignore_ssl)


def output_scan_results(correlated_findings, output_file: Optional[str], json_format: bool) -> None:
    """Output scan results to console and/or file."""
    # For now, just print a summary to the console
    # In the actual implementation, this would generate detailed reports
    for target, findings in correlated_findings.items():
        typer.echo(f"\nFindings for {target}:")
        
        # Group findings by severity
        by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        for finding in findings:
            by_severity[finding.severity.name].append(finding)
        
        # Display summary counts
        typer.echo(f"  Critical: {len(by_severity['CRITICAL'])}")
        typer.echo(f"  High: {len(by_severity['HIGH'])}")
        typer.echo(f"  Medium: {len(by_severity['MEDIUM'])}")
        typer.echo(f"  Low: {len(by_severity['LOW'])}")
        typer.echo(f"  Info: {len(by_severity['INFO'])}")
    
    typer.echo("\nTo generate a detailed report, use the 'report' command.")
