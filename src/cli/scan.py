"""
Command-line interface for scan functionality.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Union
import re

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.core.scan_mode_manager import ScanModeManager
from src.integrations import (
    DirsearchIntegration,
    NmapIntegration,
    Sublist3rIntegration,
    WappalyzerIntegration,
    ZapIntegration,
    check_and_ensure_tools,
)
from src.results.normalizer import ResultNormalizer
from src.integrations.vulnerability_scanner import VulnerabilityScanner
from src.ml.url_prioritizer import URLPrioritizer, create_structured_report

# Create the typer app
app = typer.Typer(help="Security scanning commands")

# Create console for rich output
console = Console()

# Set up logger
log = logging.getLogger("sniper.cli.scan")


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


def configure_scan_parameters(
    depth: ScanDepth, threads: int = 10, timeout: int = 3600
) -> None:
    """Configure scan parameters based on depth."""
    if depth == ScanDepth.QUICK:
        threads = 5
        timeout = 600  # 10 minutes
    elif depth == ScanDepth.STANDARD:
        threads = 10
        timeout = 3600  # 1 hour
    elif depth == ScanDepth.COMPREHENSIVE:
        threads = 15
        timeout = 7200  # 2 hours
    
    log.info(f"Scan parameters: Depth={depth.name}, Threads={threads}, Timeout={timeout}s")
    return threads, timeout


def str_to_scan_depth(depth_str: str) -> ScanDepth:
    """Convert string to ScanDepth enum."""
    try:
        return ScanDepth(depth_str.lower())
    except (ValueError, KeyError):
        # Default to STANDARD if invalid
        log.warning(f"Invalid scan depth: {depth_str}, using STANDARD")
        return ScanDepth.STANDARD


def str_list_to_scan_modules(module_strs: List[str]) -> List[ScanModule]:
    """Convert list of string module names to ScanModule enums."""
    result = []
    for module_str in module_strs:
        # Split by comma to support formats like "-m technologies,ports,web"
        if "," in module_str:
            for single_module in module_str.split(","):
                try:
                    module = ScanModule(single_module.lower().strip())
                    result.append(module)
                except ValueError:
                    log.warning(f"Invalid module string: {single_module}, skipping")
        else:
            try:
                module = ScanModule(module_str.lower())
                result.append(module)
            except ValueError:
                log.warning(f"Invalid module string: {module_str}, skipping")

    return result if result else [ScanModule.ALL]


def parse_modules_callback(value: List[str]) -> List[str]:
    """
    Parse comma-separated module lists into separate module values.
    
    This callback is called by Typer to process module option values.
    It handles both multiple -m flags and comma-separated lists.
    
    Args:
        value: List of module option values
        
    Returns:
        Expanded list of modules with comma-separated values split
    """
    result = []
    for item in value:
        if "," in item:
            # Split by comma and add each module
            result.extend([m.strip() for m in item.split(",") if m.strip()])
        else:
            # Add single module
            result.append(item)
    return result


@app.command("run")
def scan(
    target: str = typer.Argument(..., help="Target to scan (URL, domain, or IP)"),
    modules: List[str] = typer.Option(
        ["all"],
        "--module",
        "-m",
        help="Modules to run (can specify multiple or comma-separated list)",
        callback=parse_modules_callback,
    ),
    depth: ScanDepth = typer.Option(
        ScanDepth.STANDARD, "--depth", "-d", help="Scan depth"
    ),
    scan_mode: str = typer.Option(
        None,
        "--mode",
        help="Predefined scan mode to use (e.g., quick, comprehensive, stealth)",
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
        sniper scan https://example.com -m technologies,ports,web
        sniper scan example.com -d COMPREHENSIVE --output results.txt
        sniper scan example.com --mode stealth
    """
    # Validate target
    try:
        target = validate_target_url(target)
    except ValueError as e:
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)

    # Initialize scan mode manager
    scan_mode_manager = ScanModeManager()

    # Get scan mode configuration if specified
    if scan_mode:
        mode_config = scan_mode_manager.get_scan_mode(scan_mode)
        if not mode_config:
            console.print(
                f"Error: Scan mode '{scan_mode}' not found. Run 'sniper scan modes' to list available modes.",
                style="red",
            )
            sys.exit(1)
        
        # Apply scan mode settings
        scan_depth_str = mode_config.get("settings", {}).get("scan_depth", depth.name)
        scan_depth = str_to_scan_depth(scan_depth_str) if isinstance(scan_depth_str, str) else depth
        max_threads = mode_config.get("settings", {}).get("max_threads", 10)
        timeout_value = mode_config.get("settings", {}).get("timeout", 3600)
        retries = mode_config.get("settings", {}).get("retries", 2)
        max_pages = mode_config.get("settings", {}).get("max_pages", None)
        structured_reporting = mode_config.get("settings", {}).get("structured_reporting", False)
        prioritize_endpoints = mode_config.get("settings", {}).get("prioritize_endpoints", False)
        
        # Override modules with the ones from the scan mode
        if "modules" in mode_config:
            modules = [ScanModule(module) for module in mode_config["modules"] if module in ScanModule._value2member_map_]
        
        console.print(
            f"Using scan mode: {scan_mode} - {mode_config.get('description', '')}",
            style="blue",
        )

    # Resolve full list of modules to run
    module_list = resolve_scan_modules(modules)
    typer.echo(f"Target: {target}")
    typer.echo(f"Scan depth: {scan_depth.name}")
    typer.echo(f"Modules: {', '.join(module_list)}")

    # Check for required tools based on selected modules
    required_tools = []
    if ScanModule.TECHNOLOGIES.value in module_list:
        required_tools.append("wappalyzer")
    if ScanModule.PORTS.value in module_list:
        required_tools.append("nmap")
    if ScanModule.WEB.value in module_list:
        required_tools.append("zap")
    if ScanModule.DIRECTORIES.value in module_list:
        required_tools.append("dirsearch")
    if ScanModule.SUBDOMAINS.value in module_list:
        required_tools.extend(["sublist3r", "amass", "subfinder"])

    # Ensure all required tools are available
    typer.echo("Checking required tools...")
    tool_availability = check_and_ensure_tools(required_tools)
    
    # Report on tool availability
    unavailable_tools = [tool for tool, (available, _) in tool_availability.items() if not available]
    if unavailable_tools:
        typer.echo(f"Warning: Some tools are not available: {', '.join(unavailable_tools)}")
        typer.echo("Continuing with available tools only.")
    
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
        crawled_urls = []

        try:
            # Run each selected module with appropriate tools and configurations
            if ScanModule.TECHNOLOGIES.value in module_list:
                if tool_availability.get("wappalyzer", (False, ""))[0]:
                    tech_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "wappalyzer" in mode_tools and mode_tools["wappalyzer"].get(
                            "enabled", True
                        ):
                            tech_tools["wappalyzer"] = mode_tools["wappalyzer"].get(
                                "options", {}
                            )

                    technology_findings = asyncio.run(
                        run_technology_scan(target, ignore_ssl, tech_tools)
                    )
                    all_findings.extend(technology_findings)
                else:
                    log.warning("Skipping technologies module: Wappalyzer not available")

            if ScanModule.SUBDOMAINS.value in module_list:
                available_subdomain_tools = {
                    tool: tool_availability.get(tool, (False, ""))[0]
                    for tool in ["sublist3r", "amass", "subfinder"]
                }
                
                if any(available_subdomain_tools.values()):
                    subdomain_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        for tool in ["sublist3r", "amass", "subfinder"]:
                            if (
                                available_subdomain_tools.get(tool, False) and
                                tool in mode_tools and 
                                mode_tools[tool].get("enabled", True)
                            ):
                                subdomain_tools[tool] = mode_tools[tool].get("options", {})

                    subdomain_findings = asyncio.run(
                        run_subdomain_scan(target, subdomain_tools)
                    )
                    all_findings.extend(subdomain_findings)
                else:
                    log.warning("Skipping subdomains module: No subdomain tools available")

            if ScanModule.PORTS.value in module_list:
                if tool_availability.get("nmap", (False, ""))[0]:
                    port_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "nmap" in mode_tools and mode_tools["nmap"].get("enabled", True):
                            port_tools["nmap"] = mode_tools["nmap"].get("options", {})

                    port_findings = asyncio.run(run_port_scan(target, scan_depth, port_tools))
                    all_findings.extend(port_findings)
                else:
                    log.warning("Skipping ports module: Nmap not available")

            if ScanModule.WEB.value in module_list:
                if tool_availability.get("zap", (False, ""))[0]:
                    web_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "zap" in mode_tools and mode_tools["zap"].get("enabled", True):
                            web_tools["zap"] = mode_tools["zap"].get("options", {})

                    web_findings = asyncio.run(
                        run_web_scan(target, scan_depth, ignore_ssl, web_tools)
                    )
                    all_findings.extend(web_findings)
                else:
                    log.warning("Skipping web module: ZAP not available")

            if ScanModule.DIRECTORIES.value in module_list:
                if tool_availability.get("dirsearch", (False, ""))[0]:
                    dir_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "dirsearch" in mode_tools and mode_tools["dirsearch"].get(
                            "enabled", True
                        ):
                            dir_tools["dirsearch"] = mode_tools["dirsearch"].get(
                                "options", {}
                            )

                    directory_findings = asyncio.run(
                        run_directory_scan(target, scan_depth, ignore_ssl, dir_tools)
                    )
                    all_findings.extend(directory_findings)
                else:
                    log.warning("Skipping directories module: Dirsearch not available")

            # Store all results
            scan_results = {}
            for tool_name, result in tool_availability.items():
                if result[0]:
                    scan_results[tool_name] = result[1]

            # If using AI Smart scan mode with prioritization and structured reporting
            if scan_mode == "ai_smart" and prioritize_endpoints:
                try:
                    # Get all crawled URLs from scan results
                    for tool_name, result in scan_results.items():
                        if isinstance(result, dict) and "crawled_urls" in result:
                            crawled_urls.extend(result["crawled_urls"])
                        elif isinstance(result, dict) and "urls" in result:
                            crawled_urls.extend(result["urls"])
                    
                    # Deduplicate URLs
                    crawled_urls = list(set(crawled_urls))
                    
                    if crawled_urls:
                        # Initialize URL prioritizer
                        prioritizer = URLPrioritizer(
                            max_urls=max_pages or 150,
                            confidence_threshold=0.6,
                            use_historical_data=True
                        )
                        
                        console.print(f"Prioritizing {len(crawled_urls)} discovered URLs...", style="blue")
                        prioritized_urls = prioritizer.prioritize(crawled_urls, target)
                        
                        # Create structured report
                        console.print("Generating structured report...", style="blue")
                        html_report_path = create_structured_report(
                            target=target,
                            output_dir=output_file.parent if output_file else ".", 
                            findings=all_findings,
                            prioritized_urls=prioritized_urls
                        )
                        
                        console.print(f"\nAI Smart report generated at: {html_report_path}", style="green")
                    else:
                        console.print("No URLs were crawled during the scan for prioritization", style="yellow")
                
                except ImportError as e:
                    console.print(f"Warning: Could not import URL prioritizer: {str(e)}", style="yellow")
                    console.print("AI Smart structured reporting will be skipped", style="yellow")
                    structured_reporting = False

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


@app.command("modes")
def list_scan_modes() -> None:
    """
    List available scan modes with their descriptions.

    Displays all predefined scan modes that can be used with the 'scan run' command.
    """
    scan_mode_manager = ScanModeManager()
    all_modes = scan_mode_manager.get_all_scan_modes()

    if not all_modes:
        typer.echo("No scan modes are currently defined.")
        return

    # Create a rich table for displaying scan modes
    table = Table(title="Available Scan Modes")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="green")
    table.add_column("Modules", style="yellow")
    table.add_column("Target Types", style="magenta")

    for name, config in all_modes.items():
        description = config.get("description", "")
        modules = ", ".join(config.get("modules", []))
        target_types = ", ".join(config.get("target_types", []))

        table.add_row(name, description, modules, target_types)

    console.print(table)


def resolve_scan_modules(modules: List[ScanModule]) -> List[str]:
    """Resolve the list of modules to run based on user input."""
    if isinstance(modules, list) and len(modules) > 0 and isinstance(modules[0], str):
        # If we received strings, convert them to ScanModule
        modules = str_list_to_scan_modules(modules)

    if ScanModule.ALL in modules:
        return [m.value for m in ScanModule if m != ScanModule.ALL]
    return [m.value for m in modules]


async def run_technology_scan(
    target: str, ignore_ssl: bool, tool_options: Dict = None
) -> List:
    """Run technology detection scan using Wappalyzer."""
    log.debug(f"Running technology scan against {target}")
    scanner = WappalyzerIntegration()

    # Default options
    options = {"verify_ssl": not ignore_ssl}

    # Update with tool-specific options if available
    if tool_options and "wappalyzer" in tool_options:
        options.update(tool_options["wappalyzer"])

    execution_result = await scanner.run(target, options=options)
    findings = await scanner.parse_output(execution_result)
    return findings or []


async def run_subdomain_scan(target: str, tool_options: Dict = None) -> List:
    """Run subdomain discovery using Sublist3r or other tools based on configuration."""
    log.debug(f"Running subdomain scan against {target}")
    findings = []

    # Determine which subdomain tools to use based on configuration
    use_sublist3r = True
    use_amass = False
    use_subfinder = False

    sublist3r_options = {}
    amass_options = {}
    subfinder_options = {}

    if tool_options:
        # Override default tool selection based on provided options
        if "sublist3r" in tool_options:
            sublist3r_options = tool_options["sublist3r"]
        else:
            use_sublist3r = False

        if "amass" in tool_options:
            use_amass = True
            amass_options = tool_options["amass"]

        if "subfinder" in tool_options:
            use_subfinder = True
            subfinder_options = tool_options["subfinder"]

    # Run tools based on configuration
    if use_sublist3r:
        scanner = Sublist3rIntegration()
        execution_result = await scanner.run(target, options=sublist3r_options)
        findings.extend(scanner.parse_output(execution_result) or [])

    # Additional tools would be implemented similarly
    # For now, we'll log that they would run but not implement them fully
    if use_amass:
        log.info(f"Would run Amass with options: {amass_options}")
        # Integration would be implemented here

    if use_subfinder:
        log.info(f"Would run Subfinder with options: {subfinder_options}")
        # Integration would be implemented here

    return findings


async def run_port_scan(
    target: str, depth: ScanDepth, tool_options: Dict = None
) -> List:
    """Run port scan using Nmap with configured options."""
    log.debug(f"Running port scan against {target} with depth {depth.value}")
    scanner = NmapIntegration()

    # Configure scan parameters based on depth
    options = {}
    if depth == ScanDepth.QUICK:
        options["ports"] = "22,80,443,8080,8443"
    elif depth == ScanDepth.STANDARD:
        options["ports"] = "top1000"
    # Comprehensive uses default (all ports)

    # Override with tool-specific options if available
    if tool_options and "nmap" in tool_options:
        options.update(tool_options["nmap"])

    execution_result = await scanner.run(target, options=options)
    return scanner.parse_output(execution_result) or []


async def run_web_scan(
    target: str, depth: ScanDepth, ignore_ssl: bool, tool_options: Dict = None
) -> List:
    """Run web vulnerability scan using OWASP ZAP with configured options."""
    log.debug(f"Running web scan against {target} with depth {depth.value}")
    scanner = ZapIntegration()

    # Configure scan parameters based on depth
    options = {
        "active_scan": depth != ScanDepth.QUICK,
        "ajax_spider": depth == ScanDepth.COMPREHENSIVE,
        "verify_ssl": not ignore_ssl,
    }

    # Override with tool-specific options if available
    if tool_options and "zap" in tool_options:
        options.update(tool_options["zap"])

    execution_result = await scanner.run(target, options=options)
    return scanner.parse_output(execution_result) or []


async def run_directory_scan(
    target: str, depth: ScanDepth, ignore_ssl: bool, tool_options: Dict = None
) -> List:
    """Run directory/file discovery scan using Dirsearch with configured options."""
    log.debug(f"Running directory scan against {target} with depth {depth.value}")
    scanner = DirsearchIntegration()

    # Configure scan parameters based on depth
    options = {"verify_ssl": not ignore_ssl}

    if depth == ScanDepth.QUICK:
        options["wordlist"] = "common.txt"
        options["extensions"] = "php,html"
    elif depth == ScanDepth.STANDARD:
        options["wordlist"] = "medium.txt"
        options["extensions"] = "php,html,js,txt"
    else:  # COMPREHENSIVE
        options["wordlist"] = "big.txt"
        options["extensions"] = "php,html,js,txt,bak,old,sql,zip"

    # Override with tool-specific options if available
    if tool_options and "dirsearch" in tool_options:
        options.update(tool_options["dirsearch"])

    execution_result = await scanner.run(target, options=options)
    return scanner.parse_output(execution_result) or []


def output_scan_results(
    correlated_findings, output_file: Optional[str], json_format: bool
) -> None:
    """Output scan results to console and/or file in the specified format."""
    # Output to console
    if correlated_findings:
        # Count total findings across all targets
        total_findings = sum(len(findings) for findings in correlated_findings.values())
        typer.echo(f"\nFound {total_findings} issues:")
        
        # Process each target and its findings
        for target_url, findings in correlated_findings.items():
            typer.echo(f"\nTarget: {target_url}")
            for i, finding in enumerate(findings, 1):
                # Get severity as string and convert to uppercase
                severity_str = str(finding.severity).split('.')[-1]
                severity_color = {
                    "CRITICAL": typer.colors.BRIGHT_RED,
                    "HIGH": typer.colors.RED,
                    "MEDIUM": typer.colors.YELLOW,
                    "LOW": typer.colors.GREEN,
                    "INFO": typer.colors.BLUE,
                }.get(severity_str, "")
                
                if severity_color:
                    typer.echo(
                        f"{i}. [{severity_color}]{severity_str}[/] - {finding.title}"
                    )
                else:
                    typer.echo(f"{i}. {severity_str} - {finding.title}")
    else:
        typer.echo("No security issues found.")
    
    # Output to file if specified
    if output_file:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        if not correlated_findings:
            with open(output_file, "w") as f:
                if json_format:
                    json.dump({"findings": {}}, f)
                else:
                    f.write("# Scan Results\n\nNo security issues found.\n")
            typer.echo(f"Results written to {output_file}")
            return
        
        serializable_findings = {}
        import json
        
        try:
            with open(output_file, "w") as f:
                if json_format:
                    # Convert findings to serializable format
                    for target, findings in correlated_findings.items():
                        serializable_findings[target] = [finding.dict() for finding in findings]
                    json.dump(serializable_findings, f, indent=2)
                else:
                    f.write("# Scan Results\n\n")
                    for target_url, findings in correlated_findings.items():
                        f.write(f"## Target: {target_url}\n\n")
                        for i, finding in enumerate(findings, 1):
                            severity_str = str(finding.severity).split('.')[-1]
                            f.write(f"### {i}. {severity_str} - {finding.title}\n\n")
                            f.write(f"**Description:** {finding.description}\n\n")
                            f.write(f"**Tool:** {finding.tool}\n\n")
                            f.write(f"**Severity:** {severity_str}\n\n")
                            f.write(f"{finding.description}\n\n")
                            f.write("---\n\n")
            typer.echo(f"Results written to {output_file}")
        except Exception as e:
            typer.echo(f"Error writing results to file: {e}", err=True)


def validate_target_url(target: str) -> str:
    """Validate and normalize the target URL.

    Args:
        target: The target URL, domain, or IP to validate

    Returns:
        Normalized target URL

    Raises:
        ValueError: If the target is invalid
    """
    # Simplistic validation for demonstration purposes
    if not target:
        raise ValueError("Target URL cannot be empty")
    
    # If no protocol specified, assume HTTP
    if not target.startswith(("http://", "https://")):
        # Check if it looks like an IP address
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split(".") if part):
            target = f"http://{target}"
        else:
            target = f"http://{target}"
    
    return target 


@app.command("juiceshop")
def scan_juiceshop(
    target: str = typer.Argument("http://localhost:3000", help="JuiceShop URL (default: http://localhost:3000)"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for detailed findings"
    ),
    json_format: bool = typer.Option(
        False, "--json", "-j", help="Output in JSON format"
    ),
    max_urls: int = typer.Option(
        100, "--max-urls", help="Maximum number of URLs to crawl"
    ),
    wait_time: int = typer.Option(
        3, "--wait", help="Wait time in seconds for JavaScript to load"
    ),
) -> None:
    """
    Run a specialized security scan against OWASP Juice Shop.
    
    This command runs a comprehensive vulnerability scan against a Juice Shop instance,
    focusing on finding common web vulnerabilities like XSS, SQL injection, and more.
    
    Examples:
        sniper scan juiceshop
        sniper scan juiceshop http://192.168.1.100:3000
        sniper scan juiceshop --output juiceshop-findings.txt
        sniper scan juiceshop --json
        sniper scan juiceshop --max-urls 200 --wait 5
    """
    # Validate target
    try:
        target = validate_target_url(target)
    except ValueError as e:
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)
    
    console.print(f"[bold green]Starting specialized Juice Shop scan against:[/] {target}")
    console.print("[bold yellow]This scan will test for: XSS, SQLi, Open Redirect, Path Traversal[/]")
    console.print(f"[bold blue]Crawl settings:[/] Max URLs: {max_urls}, Wait time: {wait_time}s")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Running vulnerability scan...", total=None)
        
        # Create and initialize scanner
        scanner = VulnerabilityScanner()
        
        # Check prerequisites
        if not scanner.check_prerequisites():
            console.print("[bold red]Error:[/] Vulnerability scanner prerequisites not met.")
            raise typer.Exit(code=1)
        
        try:
            # Common paths to check for JuiceShop
            common_paths = [
                "/", 
                "/login", 
                "/register",
                "/search",
                "/rest/products",
                "/rest/user/login",
                "/rest/user/registration",
                "/api/products",
                "/ftp",
                "/score-board",
                "/administration",
                "/profile",
                "/contact",
                "/about",
                "/#/login",
                "/#/register",
                "/#/search",
                "/#/basket",
                "/#/contact",
                "/#/about"
            ]
            
            # Add these paths to our target for scanning
            urls_to_scan = [f"{target}{path}" for path in common_paths]
            
            # Run the scanner
            loop = asyncio.get_event_loop()
            scan_options = {
                "verify_ssl": False,
                "scan_types": ["xss", "sqli", "open_redirect", "path_traversal"],
                "scan_depth": "comprehensive",
                "max_urls": max_urls,
                "initial_urls": urls_to_scan,
                "wait_time": wait_time
            }
            
            # Inform about scan approach
            console.print(f"[bold]Testing {len(urls_to_scan)} known JuiceShop paths[/]")
            
            scan_result = loop.run_until_complete(scanner.run(target, options=scan_options))
            
            # Parse results
            findings = scanner.parse_output(scan_result)
            
            progress.update(task, completed=True)
            
            # Output findings
            if findings:
                console.print(f"\n[bold green]Found {len(findings)} potential vulnerabilities:[/]")
                
                # Create a table for findings
                table = Table(show_header=True)
                table.add_column("Vulnerability", style="bold red")
                table.add_column("URL", style="blue")
                table.add_column("Severity", style="yellow")
                table.add_column("Evidence", style="green", no_wrap=False)
                
                for finding in findings:
                    evidence = getattr(finding, "evidence", "")
                    if not evidence and hasattr(finding, "raw_evidence"):
                        evidence = str(finding.raw_evidence)[:80] + "..." if finding.raw_evidence and len(str(finding.raw_evidence)) > 80 else str(finding.raw_evidence or "")
                    
                    table.add_row(
                        finding.title,
                        finding.url,
                        str(finding.severity),
                        evidence[:80] + "..." if evidence and len(evidence) > 80 else evidence or ""
                    )
                
                console.print(table)
                
                # Save detailed findings if output file specified
                if output:
                    save_findings = []
                    for finding in findings:
                        save_findings.append(finding.dict())
                    
                    with open(output, "w") as f:
                        if json_format:
                            json.dump(save_findings, f, indent=2)
                        else:
                            f.write(f"# OWASP Juice Shop Scan Results\n")
                            f.write(f"Target: {target}\n\n")
                            for i, finding in enumerate(findings, 1):
                                f.write(f"## Finding {i}: {finding.title}\n")
                                f.write(f"- Severity: {finding.severity}\n")
                                f.write(f"- URL: {finding.url}\n")
                                f.write(f"- Request Method: {finding.request_method}\n")
                                f.write(f"- Evidence:\n```\n{finding.evidence}\n```\n\n")
                    
                    console.print(f"\nDetailed findings saved to: {output}")
            else:
                console.print("\n[bold green]No vulnerabilities found.[/]")
                
                # Provide some suggestions for manual testing
                console.print("\n[bold yellow]Suggestions for manual testing:[/]")
                console.print("1. Try SQL injection on the login form (admin' --)")
                console.print("2. Try XSS in the search field (<script>alert('xss')</script>)")
                console.print("3. Check for path traversal in the FTP server (%2e%2e/%2e%2e/etc/passwd)")
                console.print("4. Try to access /score-board directly for vulnerability tracking")
                
        except Exception as e:
            console.print(f"[bold red]Error during scan:[/] {str(e)}")
            raise typer.Exit(code=1)


@app.command("dvwa")
def scan_dvwa(
    target: str = typer.Argument("http://localhost:80", help="DVWA URL (default: http://localhost:80)"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for detailed findings"
    ),
    json_format: bool = typer.Option(
        False, "--json", "-j", help="Output in JSON format"
    ),
    max_urls: int = typer.Option(
        100, "--max-urls", help="Maximum number of URLs to crawl"
    ),
    wait_time: int = typer.Option(
        3, "--wait", help="Wait time in seconds for JavaScript to load"
    ),
    login: bool = typer.Option(
        True, "--login/--no-login", help="Automatically login to DVWA before scanning"
    ),
    security_level: str = typer.Option(
        "low", "--security-level", help="DVWA security level to set before scanning (low, medium, high, impossible)"
    ),
) -> None:
    """
    Run a specialized security scan against Damn Vulnerable Web Application (DVWA).
    
    This command runs a comprehensive vulnerability scan against a DVWA instance,
    focusing on finding common web vulnerabilities like XSS, SQL injection, and more.
    
    Examples:
        sniper scan dvwa
        sniper scan dvwa http://192.168.1.100
        sniper scan dvwa --output dvwa-findings.txt
        sniper scan dvwa --json
        sniper scan dvwa --max-urls 200 --wait 5
        sniper scan dvwa --security-level medium
        sniper scan dvwa --no-login
    """
    # Validate target
    try:
        target = validate_target_url(target)
    except ValueError as e:
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(code=1)
    
    console.print(f"[bold green]Starting specialized DVWA scan against:[/] {target}")
    console.print("[bold yellow]This scan will test for: XSS, SQLi, Command Injection, Path Traversal, File Inclusion[/]")
    console.print(f"[bold blue]Crawl settings:[/] Max URLs: {max_urls}, Wait time: {wait_time}s")
    
    if login:
        console.print(f"[bold blue]Login:[/] Will attempt to login with default credentials")
        console.print(f"[bold blue]Security Level:[/] Will set to {security_level}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Running vulnerability scan...", total=None)
        
        # Create and initialize scanner
        scanner = VulnerabilityScanner()
        
        # Check prerequisites
        if not scanner.check_prerequisites():
            console.print("[bold red]Error:[/] Vulnerability scanner prerequisites not met.")
            raise typer.Exit(code=1)
        
        try:
            # Handle DVWA login if requested
            if login:
                progress.update(task, description="Logging into DVWA...")
                login_successful = try_dvwa_login(scanner, target, security_level)
                
                if not login_successful:
                    console.print("[bold red]Warning:[/] Failed to login to DVWA. Continuing with unauthenticated scan.")
            
            # Common paths to check for DVWA
            common_paths = [
                "/", 
                "/login.php", 
                "/setup.php",
                "/security.php",
                "/vulnerabilities/xss_r/",
                "/vulnerabilities/xss_s/",
                "/vulnerabilities/sqli/",
                "/vulnerabilities/sqli_blind/",
                "/vulnerabilities/exec/",
                "/vulnerabilities/upload/",
                "/vulnerabilities/captcha/",
                "/vulnerabilities/csrf/",
                "/vulnerabilities/fi/",
                "/vulnerabilities/brute/",
                "/vulnerabilities/weak_id/",
                "/instructions.php",
                "/about.php",
                "/security.php",
                "/phpinfo.php"
            ]
            
            # Add these paths to our target for scanning
            urls_to_scan = [f"{target}{path}" for path in common_paths]
            
            # Run the scanner
            loop = asyncio.get_event_loop()
            scan_options = {
                "verify_ssl": False,
                "scan_types": ["xss", "sqli", "command_injection", "path_traversal", "file_inclusion"],
                "scan_depth": "comprehensive",
                "max_urls": max_urls,
                "initial_urls": urls_to_scan,
                "wait_time": wait_time
            }
            
            # Inform about scan approach
            console.print(f"[bold]Testing {len(urls_to_scan)} known DVWA paths[/]")
            
            scan_result = loop.run_until_complete(scanner.run(target, options=scan_options))
            
            # Parse results
            findings = scanner.parse_output(scan_result)
            
            progress.update(task, completed=True)
            
            # Output findings
            if findings:
                console.print(f"\n[bold green]Found {len(findings)} potential vulnerabilities:[/]")
                
                # Create a table for findings
                table = Table(show_header=True)
                table.add_column("Vulnerability", style="bold red")
                table.add_column("URL", style="blue")
                table.add_column("Severity", style="yellow")
                table.add_column("Evidence", style="green", no_wrap=False)
                
                for finding in findings:
                    evidence = getattr(finding, "evidence", "")
                    if not evidence and hasattr(finding, "raw_evidence"):
                        evidence = str(finding.raw_evidence)[:80] + "..." if finding.raw_evidence and len(str(finding.raw_evidence)) > 80 else str(finding.raw_evidence or "")
                    
                    table.add_row(
                        finding.title,
                        finding.url,
                        str(finding.severity),
                        evidence[:80] + "..." if evidence and len(evidence) > 80 else evidence or ""
                    )
                
                console.print(table)
                
                # Save detailed findings if output file specified
                if output:
                    save_findings = []
                    for finding in findings:
                        save_findings.append(finding.dict())
                    
                    with open(output, "w") as f:
                        if json_format:
                            json.dump(save_findings, f, indent=2)
                        else:
                            f.write(f"# DVWA Scan Results\n")
                            f.write(f"Target: {target}\n\n")
                            for i, finding in enumerate(findings, 1):
                                f.write(f"## Finding {i}: {finding.title}\n")
                                f.write(f"- Severity: {finding.severity}\n")
                                f.write(f"- URL: {finding.url}\n")
                                f.write(f"- Request Method: {finding.request_method}\n")
                                f.write(f"- Evidence:\n```\n{finding.evidence}\n```\n\n")
                    
                    console.print(f"\nDetailed findings saved to: {output}")
            else:
                console.print("\n[bold green]No vulnerabilities found.[/]")
                
                # Provide some suggestions for manual testing
                console.print("\n[bold yellow]Suggestions for manual testing:[/]")
                console.print("1. Try SQL injection on the login form (admin' --)")
                console.print("2. Try XSS in the user input fields (<script>alert('xss')</script>)")
                console.print("3. Try command injection in the ping tool (127.0.0.1 && cat /etc/passwd)")
                console.print("4. Try path traversal and file inclusion (../../etc/passwd)")
                
        except Exception as e:
            console.print(f"[bold red]Error during scan:[/] {str(e)}")
            raise typer.Exit(code=1)


def try_dvwa_login(scanner, target, security_level):
    """
    Attempt to login to DVWA with default credentials and set security level
    
    Args:
        scanner: The vulnerability scanner instance
        target: The base URL of the DVWA instance
        security_level: The security level to set (low, medium, high, impossible)
        
    Returns:
        bool: True if login was successful, False otherwise
    """
    try:
        # Step 1: Get login page to retrieve CSRF token
        login_url = f"{target}/login.php"
        response = scanner.session.get(login_url, timeout=10)
        
        # Check if we can access the login page
        if response.status_code != 200:
            log.warning(f"Failed to access DVWA login page: {response.status_code}")
            return False
            
        # Extract CSRF token (if present)
        csrf_token = None
        match = re.search(r'<input type="hidden" name="user_token" value="([a-zA-Z0-9]+)"', response.text)
        if match:
            csrf_token = match.group(1)
            log.debug(f"Found CSRF token: {csrf_token}")
        
        # Step 2: Login with default credentials
        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }
        
        # Add CSRF token if found
        if csrf_token:
            login_data["user_token"] = csrf_token
        
        login_response = scanner.session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
        
        # Check if login was successful (look for logout link or welcome message)
        if "logout" in login_response.text.lower() or "welcome to damn vulnerable web application" in login_response.text.lower():
            log.info("Successfully logged into DVWA")
            
            # Step 3: Set security level
            if security_level in ["low", "medium", "high", "impossible"]:
                security_url = f"{target}/security.php"
                
                # Get security page to retrieve CSRF token
                security_response = scanner.session.get(security_url, timeout=10)
                
                # Extract CSRF token (if present)
                security_csrf_token = None
                match = re.search(r'<input type="hidden" name="user_token" value="([a-zA-Z0-9]+)"', security_response.text)
                if match:
                    security_csrf_token = match.group(1)
                
                # Set security level
                security_data = {
                    "security": security_level,
                    "seclev_submit": "Submit"
                }
                
                # Add CSRF token if found
                if security_csrf_token:
                    security_data["user_token"] = security_csrf_token
                
                security_set_response = scanner.session.post(security_url, data=security_data, timeout=10)
                
                if "security level set to" in security_set_response.text.lower():
                    log.info(f"Successfully set DVWA security level to {security_level}")
                else:
                    log.warning(f"Failed to set DVWA security level to {security_level}")
            
            return True
        else:
            log.warning("Failed to login to DVWA with default credentials")
            return False
            
    except Exception as e:
        log.error(f"Error during DVWA login: {str(e)}")
        return False 