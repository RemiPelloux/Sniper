import asyncio
import logging
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.results.types import BaseFinding
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.nmap import NmapIntegration
from src.integrations.owasp_zap import ZapIntegration
from src.integrations.sublist3r import Sublist3rIntegration
from src.integrations.wappalyzer import WappalyzerIntegration
from src.results.normalizer import ResultNormalizer

# Define enums for scan functionality
class ScanModule(str, Enum):
    """Scan modules that can be enabled or disabled."""
    TECHNOLOGIES = "technologies"
    SUBDOMAINS = "subdomains"
    PORTS = "ports"
    WEB = "web"
    DIRECTORIES = "directories"
    ALL = "all"

class ScanDepth(str, Enum):
    """Depth/intensity levels for scanning."""
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"

log = logging.getLogger(__name__)
console = Console()
app = typer.Typer()


def validate_target_url(target: str) -> str:
    """Validate and normalize the target URL.
    
    Args:
        target: The target URL, domain, or IP to validate
        
    Returns:
        The normalized target URL
        
    Raises:
        ValueError: If the target is invalid
    """
    # Simple validation for now - in a real implementation, this would do more
    if not target:
        raise ValueError("Target URL cannot be empty")
    
    # Add http:// prefix if no protocol specified
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
        
    return target


def configure_scan_parameters(depth: ScanDepth, threads: int = 10, timeout: int = 3600) -> None:
    """Configure scan parameters based on depth.
    
    Args:
        depth: The depth level of the scan
        threads: Number of threads to use
        timeout: Timeout for scan operations in seconds
    """
    log.info(f"Configuring scan with depth={depth.value}, threads={threads}, timeout={timeout}sec")
    # This function could modify global scan parameters or return a config object
    # For now it just logs the configuration


@app.command("run")
def scan(
    target: str = typer.Argument(..., help="Target to scan (URL, domain, or IP)"),
    modules: List[ScanModule] = typer.Option(
        [ScanModule.ALL],
        "--module",
        "-m",
        help="Modules to run (can specify multiple)",
    ),
    depth: ScanDepth = typer.Option(
        ScanDepth.STANDARD, "--depth", "-d", help="Scan depth"
    ),
    ignore_ssl: bool = typer.Option(
        False, "--ignore-ssl", help="Ignore SSL certificate errors"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for detailed findings"
    ),
    json_format: bool = typer.Option(
        False, "--json", "-j", help="Output in JSON format"
    ),
) -> None:
    """
    Run security scans against a target.

    The scan command automates multiple security scanning techniques:
    - Technology detection
    - Subdomain discovery
    - Port scanning
    - Web vulnerability assessment
    - Directory discovery

    Examples:
        sniper scan example.com
        sniper scan https://example.com -m TECHNOLOGY -m PORT
        sniper scan example.com -d COMPREHENSIVE --output results.txt
    """
    # Validate target
    if not target:
        typer.echo("Error: Target is required", err=True)
        raise typer.Exit(code=1)

    # Resolve full list of modules to run
    module_list = resolve_scan_modules(modules)
    typer.echo(f"Target: {target}")
    typer.echo(f"Scan depth: {depth.name}")
    typer.echo(f"Modules: {', '.join(module_list)}")

    # Create output file path if specified
    output_file = None
    if output:
        output_file = str(output.resolve())
        typer.echo(f"Output will be written to: {output_file}")

    # Run scans based on selected modules
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(description="Running scans...", total=None)

        # The main dictionary to collect all findings
        all_findings: List[BaseFinding] = []

        try:
            # Run each selected module
            if ScanModule.TECHNOLOGIES.value in module_list:
                technology_findings = asyncio.run(run_technology_scan(target, ignore_ssl))
                all_findings.extend(technology_findings)

            if ScanModule.SUBDOMAINS.value in module_list:
                subdomain_findings = asyncio.run(run_subdomain_scan(target))
                all_findings.extend(subdomain_findings)

            if ScanModule.PORTS.value in module_list:
                port_findings = asyncio.run(run_port_scan(target, depth))
                all_findings.extend(port_findings)

            if ScanModule.WEB.value in module_list:
                web_findings = asyncio.run(run_web_scan(target, depth, ignore_ssl))
                all_findings.extend(web_findings)

            if ScanModule.DIRECTORIES.value in module_list:
                directory_findings = asyncio.run(run_directory_scan(target, depth, ignore_ssl))
                all_findings.extend(directory_findings)

        except Exception as e:
            typer.echo(f"Error during scan: {e}", err=True)
            raise typer.Exit(code=1)

    # Correlate findings
    typer.echo("\nCorrelating findings...")
    normalizer = ResultNormalizer()
    correlated_findings = normalizer.correlate_findings(all_findings)

    # Output results
    output_scan_results(correlated_findings, output_file, json_format)
    typer.echo("Scan completed successfully.")


def resolve_scan_modules(modules: List[ScanModule]) -> List[str]:
    """Resolve the list of modules to run based on user input."""
    if ScanModule.ALL in modules:
        return [m.value for m in ScanModule if m != ScanModule.ALL]
    return [m.value for m in modules]


async def run_technology_scan(target: str, ignore_ssl: bool) -> List:
    """Run technology detection scan using Wappalyzer."""
    log.debug(f"Running technology scan against {target}")
    scanner = WappalyzerIntegration()
    execution_result = await scanner.run(target, options={"verify_ssl": not ignore_ssl})
    return scanner.parse_output(execution_result) or []


async def run_subdomain_scan(target: str) -> List:
    """Run subdomain discovery using Sublist3r."""
    log.debug(f"Running subdomain scan against {target}")
    scanner = Sublist3rIntegration()
    execution_result = await scanner.run(target)
    return scanner.parse_output(execution_result) or []


async def run_port_scan(target: str, depth: ScanDepth) -> List:
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
    
    execution_result = await scanner.run(target, options={"ports": ports})
    return scanner.parse_output(execution_result) or []


async def run_web_scan(target: str, depth: ScanDepth, ignore_ssl: bool) -> List:
    """Run web vulnerability scan using OWASP ZAP."""
    log.debug(f"Running web scan against {target} with depth {depth.value}")
    scanner = ZapIntegration()
    
    # Configure scan parameters based on depth
    active_scan = depth != ScanDepth.QUICK
    ajax_spider = depth == ScanDepth.COMPREHENSIVE
    
    execution_result = await scanner.run(target, options={
        "active_scan": active_scan, 
        "ajax_spider": ajax_spider, 
        "verify_ssl": not ignore_ssl
    })
    return scanner.parse_output(execution_result) or []


async def run_directory_scan(target: str, depth: ScanDepth, ignore_ssl: bool) -> List:
    """Run directory discovery using Dirsearch."""
    log.debug(f"Running directory scan against {target} with depth {depth.value}")
    scanner = DirsearchIntegration()
    
    # Configure scan parameters based on depth
    wordlist_size = "small"
    if depth == ScanDepth.STANDARD:
        wordlist_size = "medium"
    elif depth == ScanDepth.COMPREHENSIVE:
        wordlist_size = "large"
    
    execution_result = await scanner.run(target, options={
        "wordlist_size": wordlist_size, 
        "verify_ssl": not ignore_ssl
    })
    return scanner.parse_output(execution_result) or []


def output_scan_results(
    correlated_findings, output_file: Optional[str], json_format: bool
) -> None:
    """Output scan results to console and/or file."""
    # For now, just print a summary to the console
    # In the actual implementation, this would generate detailed reports
    for target, findings in correlated_findings.items():
        typer.echo(f"\nFindings for {target}:")

        # Group findings by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}

        for finding in findings:
            by_severity[finding.severity.name].append(finding)

        # Display summary counts
        typer.echo(f"  Critical: {len(by_severity['CRITICAL'])}")
        typer.echo(f"  High: {len(by_severity['HIGH'])}")
        typer.echo(f"  Medium: {len(by_severity['MEDIUM'])}")
        typer.echo(f"  Low: {len(by_severity['LOW'])}")
        typer.echo(f"  Info: {len(by_severity['INFO'])}")

    typer.echo("\nTo generate a detailed report, use the 'report' command.")
