import asyncio
import logging
import tempfile
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Union

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.core.scan_mode_manager import ScanModeManager
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.nmap import NmapIntegration
from src.integrations.owasp_zap import ZapIntegration
from src.integrations.sublist3r import Sublist3rIntegration
from src.integrations.wappalyzer import WappalyzerIntegration
from src.results.normalizer import ResultNormalizer
from src.results.types import BaseFinding
from src.tools.manager import ToolManager


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


def configure_scan_parameters(
    depth: ScanDepth, threads: int = 10, timeout: int = 3600
) -> None:
    """Configure scan parameters based on depth.

    Args:
        depth: The depth level of the scan
        threads: Number of threads to use
        timeout: Timeout for scan operations in seconds
    """
    log.info(
        f"Configuring scan with depth={depth.value}, threads={threads}, timeout={timeout}sec"
    )
    # This function could modify global scan parameters or return a config object
    # For now it just logs the configuration


# Helper function to convert string to ScanDepth enum
def str_to_scan_depth(depth_str: str) -> ScanDepth:
    """Convert a string to a ScanDepth enum value.
    
    Args:
        depth_str: String representation of the scan depth
    
    Returns:
        ScanDepth enum value
    """
    try:
        return ScanDepth(depth_str.lower())
    except ValueError:
        log.warning(f"Invalid scan depth string: {depth_str}, using STANDARD")
        return ScanDepth.STANDARD


# Helper function to convert strings to ScanModule list
def str_list_to_scan_modules(module_strs: List[str]) -> List[ScanModule]:
    """Convert a list of string module names to ScanModule enum values.
    
    Args:
        module_strs: List of module names as strings
    
    Returns:
        List of ScanModule enum values
    """
    result = []
    for module_str in module_strs:
        try:
            module = ScanModule(module_str.lower())
            result.append(module)
        except ValueError:
            log.warning(f"Invalid module string: {module_str}, skipping")
    
    return result if result else [ScanModule.ALL]


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
    scan_mode: str = typer.Option(
        None, "--mode", help="Predefined scan mode to use (e.g., quick, comprehensive, stealth)"
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
    tool_manager = ToolManager()
    
    # If a scan mode was specified, use its configuration
    if scan_mode:
        mode_config = scan_mode_manager.get_scan_mode(scan_mode)
        if not mode_config:
            typer.echo(f"Error: Scan mode '{scan_mode}' not found. Run 'sniper scan modes' to list available modes.", err=True)
            raise typer.Exit(code=1)
        
        # Apply the scan mode configuration
        typer.echo(f"Using scan mode: {scan_mode} - {mode_config.get('description', '')}")
        
        # Override modules and depth if specified by scan mode
        if "modules" in mode_config:
            # Convert string module names to ScanModule enum values
            modules = str_list_to_scan_modules(mode_config["modules"])
        
        # Get settings from the scan mode
        settings = mode_config.get("settings", {})
        if "scan_depth" in settings:
            # Convert string depth to ScanDepth enum
            depth = str_to_scan_depth(settings["scan_depth"])
        
        # Log the scan configuration from the scan mode
        max_threads = settings.get("max_threads", 10)
        timeout_value = settings.get("timeout", 3600)
        retries = settings.get("retries", 2)
        log.info(f"Scan configuration from mode '{scan_mode}': threads={max_threads}, timeout={timeout_value}s, retries={retries}")
    
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
            # Run each selected module with appropriate tools and configurations
            if ScanModule.TECHNOLOGIES.value in module_list:
                tech_tools = {}
                if scan_mode:
                    # Get tool configurations for this module from the scan mode
                    mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                    if "wappalyzer" in mode_tools and mode_tools["wappalyzer"].get("enabled", True):
                        tech_tools["wappalyzer"] = mode_tools["wappalyzer"].get("options", {})
                
                technology_findings = asyncio.run(
                    run_technology_scan(target, ignore_ssl, tech_tools)
                )
                all_findings.extend(technology_findings)

            if ScanModule.SUBDOMAINS.value in module_list:
                subdomain_tools = {}
                if scan_mode:
                    # Get tool configurations for this module from the scan mode
                    mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                    for tool in ["sublist3r", "amass", "subfinder"]:
                        if tool in mode_tools and mode_tools[tool].get("enabled", True):
                            subdomain_tools[tool] = mode_tools[tool].get("options", {})
                
                subdomain_findings = asyncio.run(run_subdomain_scan(target, subdomain_tools))
                all_findings.extend(subdomain_findings)

            if ScanModule.PORTS.value in module_list:
                port_tools = {}
                if scan_mode:
                    # Get tool configurations for this module from the scan mode
                    mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                    if "nmap" in mode_tools and mode_tools["nmap"].get("enabled", True):
                        port_tools["nmap"] = mode_tools["nmap"].get("options", {})
                
                port_findings = asyncio.run(run_port_scan(target, depth, port_tools))
                all_findings.extend(port_findings)

            if ScanModule.WEB.value in module_list:
                web_tools = {}
                if scan_mode:
                    # Get tool configurations for this module from the scan mode
                    mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                    if "zap" in mode_tools and mode_tools["zap"].get("enabled", True):
                        web_tools["zap"] = mode_tools["zap"].get("options", {})
                
                web_findings = asyncio.run(run_web_scan(target, depth, ignore_ssl, web_tools))
                all_findings.extend(web_findings)

            if ScanModule.DIRECTORIES.value in module_list:
                dir_tools = {}
                if scan_mode:
                    # Get tool configurations for this module from the scan mode
                    mode_tools = scan_mode_manager.get_tools_for_scan_mode(scan_mode)
                    if "dirsearch" in mode_tools and mode_tools["dirsearch"].get("enabled", True):
                        dir_tools["dirsearch"] = mode_tools["dirsearch"].get("options", {})
                
                directory_findings = asyncio.run(
                    run_directory_scan(target, depth, ignore_ssl, dir_tools)
                )
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


async def run_technology_scan(target: str, ignore_ssl: bool, tool_options: Dict = None) -> List:
    """Run technology detection scan using Wappalyzer."""
    log.debug(f"Running technology scan against {target}")
    scanner = WappalyzerIntegration()
    
    # Default options
    options = {"verify_ssl": not ignore_ssl}
    
    # Update with tool-specific options if available
    if tool_options and "wappalyzer" in tool_options:
        options.update(tool_options["wappalyzer"])
    
    execution_result = await scanner.run(target, options=options)
    return scanner.parse_output(execution_result) or []


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


async def run_port_scan(target: str, depth: ScanDepth, tool_options: Dict = None) -> List:
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


async def run_web_scan(target: str, depth: ScanDepth, ignore_ssl: bool, tool_options: Dict = None) -> List:
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


async def run_directory_scan(target: str, depth: ScanDepth, ignore_ssl: bool, tool_options: Dict = None) -> List:
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
        typer.echo(f"\nFound {len(correlated_findings)} issues:")
        for i, finding in enumerate(correlated_findings, 1):
            severity = finding.get("severity", "Unknown").upper()
            severity_color = {
                "CRITICAL": typer.colors.BRIGHT_RED,
                "HIGH": typer.colors.RED,
                "MEDIUM": typer.colors.YELLOW,
                "LOW": typer.colors.GREEN,
                "INFO": typer.colors.BLUE,
            }.get(severity, typer.colors.WHITE)

            typer.echo(
                f"{i}. "
                + typer.style(f"[{severity}] ", fg=severity_color, bold=True)
                + typer.style(finding.get("title", "Unnamed Issue"), bold=True)
            )
            typer.echo(f"   {finding.get('description', 'No description')}")
            if "location" in finding:
                typer.echo(f"   Location: {finding['location']}")
            typer.echo("")
    else:
        typer.echo("No issues found.")

    # Output to file if specified
    if output_file:
        import json

        try:
            with open(output_file, "w") as f:
                if json_format:
                    json.dump(correlated_findings, f, indent=2)
                else:
                    f.write("# Scan Results\n\n")
                    for i, finding in enumerate(correlated_findings, 1):
                        f.write(
                            f"## {i}. [{finding.get('severity', 'Unknown').upper()}] {finding.get('title', 'Unnamed Issue')}\n\n"
                        )
                        f.write(
                            f"{finding.get('description', 'No description')}\n\n"
                        )
                        if "location" in finding:
                            f.write(f"**Location**: {finding['location']}\n\n")
                        f.write("---\n\n")
            typer.echo(f"Results written to {output_file}")
        except Exception as e:
            typer.echo(f"Error writing results to file: {e}", err=True)
