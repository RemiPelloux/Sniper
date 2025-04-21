"""
Scan Command for Sniper Security Tool

This module defines the scan command-line interface for Sniper, which automates
multiple security scanning techniques for a target.
"""

import os
import asyncio
import json
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
import logging
import typer
from rich.console import Console
from rich.table import Table
from colorama import Fore, Style
from src.core.validation import validate_target_url

from src.core.scan_mode_manager import ScanModeManager
from src.integrations.wappalyzer import WappalyzerIntegration
from src.results.normalizer import ResultNormalizer
from src.integrations.docker_utils import check_and_ensure_tools

# Initialize logger
log = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

# Define app command group
app = typer.Typer(help="Scanning commands for Sniper Security Tool")


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
    """
    Configure scan parameters based on scan depth.

    This function sets up various parameters used across different scan modules
    based on the scan depth selected by the user.

    Args:
        depth: The scan depth/intensity
        threads: Base number of threads
        timeout: Base timeout in seconds
    """
    # Configure parameters based on depth
    if depth == ScanDepth.QUICK:
        threads = max(5, threads // 2)
        timeout = timeout // 2
    elif depth == ScanDepth.COMPREHENSIVE:
        threads = threads * 2
        timeout = timeout * 2


def str_to_scan_depth(depth_str: str) -> ScanDepth:
    """Convert a string to ScanDepth enum."""
    try:
        return ScanDepth(depth_str.lower())
    except ValueError:
        typer.echo(f"Invalid scan depth: {depth_str}")
        raise typer.Exit(code=1)


def str_list_to_scan_modules(module_strs: List[str]) -> List[ScanModule]:
    """
    Convert a list of strings to ScanModule enums.

    Args:
        module_strs: List of module names as strings

    Returns:
        List of ScanModule enums
    """
    modules = []
    for module_str in module_strs:
        try:
            modules.append(ScanModule(module_str.lower()))
        except ValueError:
            typer.echo(f"Invalid scan module: {module_str}")
            typer.echo(f"Available modules: {', '.join([m.value for m in ScanModule])}")
            raise typer.Exit(code=1)
    return modules


def parse_modules_callback(value: List[str]) -> List[str]:
    """
    Parse module options which may include comma-separated values.

    This callback handles both multiple --module options and comma-separated
    lists within a single --module option.

    Args:
        value: List of module values from command line

    Returns:
        Expanded list of modules
    """
    expanded_modules = []

    for item in value:
        # Split by comma if it contains one
        if "," in item:
            expanded_modules.extend([m.strip() for m in item.split(",") if m.strip()])
        else:
            expanded_modules.append(item.strip())

    # Remove duplicates while preserving order
    unique_modules = []
    for module in expanded_modules:
        if module not in unique_modules:
            unique_modules.append(module)

    return unique_modules


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
    prioritize_endpoints: bool = typer.Option(
        False, "--prioritize", help="Prioritize discovered endpoints (for AI Smart mode only)"
    ),
    max_pages: Optional[int] = typer.Option(
        None, "--max-pages", help="Maximum number of pages to analyze (for AI Smart mode only)"
    ),
) -> None:
    """
    Automated multiple security scanning techniques for a target.

    This command performs a comprehensive security scan on the provided target, 
    which can be a URL, domain, or IP address. It combines various scanning 
    modules including technology detection, subdomain enumeration, port scanning,
    web vulnerability scanning, and directory brute forcing.

    The scan depth and modules can be customized to suit your needs.
    """
    try:
        from src.ml.url_prioritizer import URLPrioritizer
        from src.reporting.structured_reports import create_structured_report
    except ImportError as e:
        typer.echo(f"Error importing required modules: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Starting scan on target: {target}")

    # Check if a specific scan mode is requested
    if scan_mode:
        scan_mode_manager = ScanModeManager()
        try:
            # Get the scan mode configuration
            scan_mode_config = scan_mode_manager.get_scan_mode(scan_mode)
            
            if not scan_mode_config:
                typer.echo(f"Scan mode '{scan_mode}' not found", err=True)
                available_modes = scan_mode_manager.get_all_scan_modes().keys()
                if available_modes:
                    typer.echo(f"Available modes: {', '.join(available_modes)}")
                raise typer.Exit(code=1)
                
            typer.echo(f"Using scan mode: {scan_mode}")
            
            # Apply scan mode settings
            if "depth" in scan_mode_config and not depth:
                depth = str_to_scan_depth(scan_mode_config["depth"])
                typer.echo(f"Setting scan depth to: {depth.value}")
                
            if "modules" in scan_mode_config and (not modules or modules == ["all"]):
                modules = scan_mode_config["modules"]
                typer.echo(f"Using modules from scan mode: {', '.join(modules)}")
        except Exception as e:
            typer.echo(f"Error applying scan mode: {e}", err=True)
            raise typer.Exit(code=1)

    # Configure scan parameters based on depth
    configure_scan_parameters(depth)

    # Parse modules
    module_list = resolve_scan_modules(modules)
    typer.echo(f"Modules enabled: {', '.join(module_list)}")

    # Create output file path if specified
    output_file = None
    if output:
        output_file = Path(output)
        os.makedirs(output_file.parent, exist_ok=True)

    # Validate target URL
    target = validate_target_url(target)
    if not target:
        typer.echo("Invalid target URL", err=True)
        raise typer.Exit(code=1)

    # Initialize findings list
    all_findings = []
    crawled_urls = []
    structured_reporting = prioritize_endpoints and scan_mode == "ai_smart"

    try:
        # Check for required tools based on selected modules
        required_tools = []
        
        if ScanModule.TECHNOLOGIES.value in module_list:
            required_tools.append("wappalyzer")
            
        if ScanModule.SUBDOMAINS.value in module_list:
            required_tools.extend(["sublist3r", "amass", "subfinder"])
            
        if ScanModule.PORTS.value in module_list:
            required_tools.append("nmap")
            
        if ScanModule.WEB.value in module_list:
            required_tools.append("zap")
            
        if ScanModule.DIRECTORIES.value in module_list:
            required_tools.append("dirsearch")

        # Check tool availability
        tool_availability = check_and_ensure_tools(required_tools)
        
        # Check for unavailable tools and log warnings
        unavailable_tools = [name for name, (available, _) in tool_availability.items() if not available]
        if unavailable_tools:
            warning_msg = f"Warning: Some tools are not available: {', '.join(unavailable_tools)}"
            typer.echo(warning_msg)
            log.warning(warning_msg)
            
            # Special warning for AI smart mode if smart_recon is unavailable
            if scan_mode == "ai_smart" and "smart_recon" in unavailable_tools:
                ai_warning = "Smart Recon is not available - AI prioritization will be limited"
                typer.echo(ai_warning)
                log.warning(ai_warning)
        
        with console.status("[bold green]Running security scan..."):
            # Run technology scan if enabled
            if ScanModule.TECHNOLOGIES.value in module_list:
                if tool_availability.get("wappalyzer", (False, ""))[0]:
                    tech_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "wappalyzer" in mode_tools and mode_tools["wappalyzer"].get("enabled", True):
                            tech_tools["wappalyzer"] = mode_tools["wappalyzer"].get(
                                "options", {})

                    technology_findings = asyncio.run(
                        run_technology_scan(target, ignore_ssl, tech_tools)
                    )
                    all_findings.extend(technology_findings)
                else:
                    log.warning(
                        "Skipping technologies module: Wappalyzer not available")

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
                    log.warning(
                        "Skipping subdomains module: No subdomain tools available")

            if ScanModule.PORTS.value in module_list:
                if tool_availability.get("nmap", (False, ""))[0]:
                    port_tools = {}
                    if scan_mode:
                        # Get tool configurations for this module from the scan mode
                        mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                        if "nmap" in mode_tools and mode_tools["nmap"].get("enabled", True):
                            port_tools["nmap"] = mode_tools["nmap"].get("options", {})

                    port_findings = asyncio.run(
                        run_port_scan(target, scan_depth, port_tools)
                    )
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
                        if "dirsearch" in mode_tools and mode_tools["dirsearch"].get("enabled", True):
                            dir_tools["dirsearch"] = mode_tools["dirsearch"].get("options", {})

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

                        console.print(
                            f"Prioritizing {len(crawled_urls)} discovered URLs...",
                            style="blue"
                        )
                        prioritized_urls = prioritizer.prioritize(crawled_urls, target)

                        # Create structured report
                        console.print("Generating structured report...", style="blue")
                        html_report_path = create_structured_report(
                            target=target,
                            output_dir=output_file.parent if output_file else ".",
                            findings=all_findings,
                            prioritized_urls=prioritized_urls
                        )

                        console.print(
                            f"\nAI Smart report generated at: {html_report_path}",
                            style="green"
                        )
                    else:
                        console.print(
                            "No URLs were crawled during the scan for prioritization",
                            style="yellow"
                        )

                except ImportError as e:
                    console.print(
                        f"Warning: Could not import URL prioritizer: {str(e)}", 
                        style="yellow"
                    )
                    console.print(
                        "AI Smart structured reporting will be skipped",
                        style="yellow"
                    )
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


def resolve_scan_modules(modules: List[str]) -> List[str]:
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
    findings = scanner.parse_output(execution_result)
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
        from src.integrations.sublist3r import Sublist3rIntegration
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
    from src.integrations.nmap import NmapIntegration
    scanner = NmapIntegration()

    # Configure scan parameters based on depth
    options = {}
    if depth == ScanDepth.QUICK:
        options["ports"] = "22,80,443,8080,8443"
    elif depth == ScanDepth.STANDARD:
        options["ports"] = "1-1000"  # Replace 'top1000' with actual port range
    else:  # COMPREHENSIVE
        options["ports"] = "1-65535"  # All ports

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
    from src.integrations.owasp_zap import ZapIntegration
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
    from src.integrations.dirsearch import DirsearchIntegration
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
    correlated_findings, output_file: Optional[Path], json_format: bool
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
                    json.dump([], f)
                else:
                    f.write("# Scan Results\n\nNo security issues found.\n")
            typer.echo(f"Results written to {output_file}")
            return

        serializable_findings = {}

        try:
            with open(output_file, "w") as f:
                if json_format:
                    # Convert findings to serializable format
                    if isinstance(correlated_findings, dict):
                        # Handle dict format (target -> findings)
                        for target, findings in correlated_findings.items():
                            serializable_findings[target] = [
                                finding.dict() for finding in findings
                            ]
                        json.dump(serializable_findings, f, indent=2)
                    else:
                        # Handle list format (flat list of findings)
                        serializable_list = [finding.dict() for finding in correlated_findings]
                        json.dump(serializable_list, f, indent=2)
                else:
                    # Write markdown format
                    f.write("# Scan Results\n\n")
                    if isinstance(correlated_findings, dict):
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
                    else:
                        # Handle list format
                        for i, finding in enumerate(correlated_findings, 1):
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
