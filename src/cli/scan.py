"""
Scan Command for Sniper Security Tool

This module defines the scan command-line interface for Sniper, which automates
multiple security scanning techniques for a target.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

import typer
from colorama import Fore, Style
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.table import Table

from src.core.config import load_scan_mode_config
from src.core.exceptions import ScanConfigError, ScanExecutionError
from src.core.findings import Finding, Severity
from src.core.logging import setup_logging
from src.core.scan_mode_manager import ScanModeManager
from src.core.validation import validate_target_url
from src.integrations.base import BaseIntegration, ToolNotFoundError
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.docker_utils import check_and_ensure_tools
from src.integrations.nmap import NmapIntegration
from src.integrations.wappalyzer import WappalyzerIntegration
from src.integrations.zap import ZAPIntegration
from src.results.normalizer import ResultNormalizer
from src.results.types import FindingSeverity

# Initialize logger
log = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

# Define app command group
app = typer.Typer(help="Scanning commands for Sniper Security Tool")


# Severity mapping functions
def map_zap_risk_to_severity(risk: str) -> Severity:
    """Map ZAP risk levels to Severity enum."""
    risk_map = {
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Informational": Severity.INFO,
    }
    return risk_map.get(risk, Severity.INFO)


def map_zap_confidence_to_int(confidence: str) -> int:
    """Map ZAP confidence levels to integer percentage."""
    confidence_map = {
        "High": 90,
        "Medium": 70,
        "Low": 50,
        "Confirmed": 100,
    }
    return confidence_map.get(confidence, 50)


def map_status_code_to_severity(status_code: int) -> Severity:
    """Map HTTP status codes to Severity enum."""
    if status_code >= 500:
        return Severity.HIGH
    elif status_code >= 400:
        return Severity.MEDIUM
    elif status_code >= 300:
        return Severity.LOW
    return Severity.INFO


def get_severity_style(severity: Severity) -> str:
    """Get Rich console style for severity level."""
    style_map = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "blue",
    }
    return style_map.get(severity, "")


def get_subdomain_tool(tool_name: str) -> Optional[Type[BaseIntegration]]:
    """Get the appropriate subdomain scanning tool class."""
    tool_map = {
        "sublist3r": "Sublist3rIntegration",
        "amass": "AmassIntegration",
        "subfinder": "SubfinderIntegration",
    }

    if tool_name not in tool_map:
        return None

    try:
        module = __import__(
            f"src.integrations.{tool_name}", fromlist=[tool_map[tool_name]]
        )
        return getattr(module, tool_map[tool_name])
    except (ImportError, AttributeError):
        return None


class ScanModule(str, Enum):
    """Scan modules that can be enabled or disabled."""

    TECHNOLOGIES = "technologies"
    SUBDOMAINS = "subdomains"
    PORTS = "ports"
    WEB = "web"
    DIRECTORIES = "directories"
    VULNS = "vulns"
    ALL = "all"

    @classmethod
    def get_available_modules(cls) -> Set[str]:
        """Return set of available module names."""
        return {member.value for member in cls if member != cls.ALL}


class ScanDepth(str, Enum):
    """Depth/intensity levels for scanning."""

    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class ScanConfig(BaseModel):
    """Scan configuration model."""

    target: str
    modules: List[ScanModule]
    depth: ScanDepth
    ignore_ssl: bool = False
    tool_options: Optional[Dict] = None
    prioritize_endpoints: bool = False
    max_pages: Optional[int] = None
    tool_availability: Optional[Dict] = None


def configure_scan_parameters(
    depth: ScanDepth, threads: int = 10, timeout: int = 3600
) -> None:
    """Configure scan parameters based on depth."""
    if not isinstance(depth, ScanDepth):
        raise ValueError(f"Invalid scan depth: {depth}")

    # Configure based on depth
    if depth == ScanDepth.QUICK:
        threads = min(threads, 5)
        timeout = min(timeout, 1800)
    elif depth == ScanDepth.COMPREHENSIVE:
        threads = max(threads, 15)
        timeout = max(timeout, 7200)

    # Set global parameters (these would be used by scan modules)
    os.environ["SCAN_THREADS"] = str(threads)
    os.environ["SCAN_TIMEOUT"] = str(timeout)


def validate_scan_modules(modules: List[str]) -> List[ScanModule]:
    """Validate and convert string module names to ScanModule enum."""
    available_modules = ScanModule.get_available_modules()

    if not modules:
        raise ScanConfigError("No scan modules specified")

    if "all" in modules:
        return [ScanModule.ALL]

    validated_modules = []
    for module in modules:
        if module not in available_modules:
            raise ScanConfigError(f"Invalid scan module: {module}")
        validated_modules.append(ScanModule(module))

    return validated_modules


def resolve_scan_modules(modules: List[str]) -> List[str]:
    """
    Resolve scan modules from module names or 'all'.

    Args:
        modules: List of module names or ['all']

    Returns:
        List of resolved module names
    """
    if not modules:
        return []

    if "all" in modules:
        return list(ScanModule.get_available_modules())

    # Return only valid modules
    available_modules = ScanModule.get_available_modules()
    return [m for m in modules if m in available_modules]


def parse_modules_callback(value: List[str]) -> List[str]:
    """Process and validate module input from CLI."""
    modules = []
    for item in value:
        # Handle comma-separated lists
        modules.extend(module.strip().lower() for module in item.split(","))

    try:
        validate_scan_modules(modules)
    except ScanConfigError as e:
        raise typer.BadParameter(str(e))

    return modules


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
        False,
        "--prioritize",
        help="Prioritize discovered endpoints (for AI Smart mode only)",
    ),
    max_pages: Optional[int] = typer.Option(
        None,
        "--max-pages",
        help="Maximum number of pages to analyze (for AI Smart mode only)",
    ),
) -> None:
    """Run security scan with specified parameters."""
    try:
        # Initialize logging
        setup_logging()

        # Validate target URL
        validated_target = validate_target_url(target, auto_add_scheme=True)
        if not validated_target:
            raise ScanConfigError(f"Invalid target URL: {target}")

        # Print scan mode if specified
        if scan_mode:
            console.print(f"Running scan with mode: {scan_mode}", style="blue bold")

        # Load scan mode configuration if specified
        tool_options = None
        if scan_mode:
            # Create a ScanModeManager instead of directly calling load_scan_mode_config
            scan_mode_manager = ScanModeManager()
            scan_mode_config = scan_mode_manager.get_scan_mode(scan_mode)

            if scan_mode_config:
                if "modules" in scan_mode_config:
                    modules = scan_mode_config["modules"]
                if (
                    "settings" in scan_mode_config
                    and "scan_depth" in scan_mode_config["settings"]
                ):
                    depth = ScanDepth(scan_mode_config["settings"]["scan_depth"])
                if "tools" in scan_mode_config:
                    tool_options = scan_mode_config["tools"]

        # Check tool availability
        tool_availability = check_and_ensure_tools(
            [
                "wappalyzer",
                "zap",
                "dirsearch",
                "nmap",
                "sublist3r",
                "amass",
                "subfinder",
            ]
        )

        # Log unavailable tools
        unavailable_tools = [
            name for name, (available, _) in tool_availability.items() if not available
        ]
        if unavailable_tools:
            console.print(
                f"Warning: Some tools are not available: {', '.join(unavailable_tools)}",
                style="yellow",
            )

        # Validate and create scan configuration
        scan_config = ScanConfig(
            target=validated_target,
            modules=validate_scan_modules(modules),
            depth=depth,
            ignore_ssl=ignore_ssl,
            tool_options=tool_options,
            prioritize_endpoints=prioritize_endpoints,
            max_pages=max_pages,
            tool_availability=tool_availability,
        )

        # Configure scan parameters
        configure_scan_parameters(scan_config.depth)

        # Run scan and get results
        findings = asyncio.run(execute_scan(scan_config))

        # Output results
        output_scan_results(findings, output, json_format)

    except (ScanConfigError, ScanExecutionError) as e:
        typer.echo(f"Error: {str(e)}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        log.exception("Unexpected error during scan")
        typer.echo(f"An unexpected error occurred: {str(e)}", err=True)
        raise typer.Exit(2)


@app.command("modes")
def list_scan_modes() -> None:
    """List available scan modes and their configurations."""
    try:
        modes = load_scan_mode_config()
        if not modes:
            typer.echo("No scan modes configured.")
            return

        typer.echo("Available scan modes:\n")
        for mode, config in modes.items():
            typer.echo(f"Mode: {mode}")
            if "description" in config:
                typer.echo(f"Description: {config['description']}")
            if "modules" in config:
                typer.echo(f"Modules: {', '.join(config['modules'])}")
            if "depth" in config:
                typer.echo(f"Depth: {config['depth']}")
            typer.echo("")

    except Exception as e:
        typer.echo(f"Error loading scan modes: {str(e)}", err=True)
        raise typer.Exit(1)


async def execute_scan(config: ScanConfig) -> Dict[str, List[Finding]]:
    """Execute scan modules based on configuration."""
    findings = {}
    active_modules = (
        ScanModule.get_available_modules()
        if ScanModule.ALL in config.modules
        else {module.value for module in config.modules}
    )

    scan_functions = {
        ScanModule.TECHNOLOGIES: run_technology_scan,
        ScanModule.SUBDOMAINS: run_subdomain_scan,
        ScanModule.PORTS: run_port_scan,
        ScanModule.WEB: run_web_scan,
        ScanModule.DIRECTORIES: run_directory_scan,
        ScanModule.VULNS: run_vulnerability_scan,
    }

    # Map modules to their required tools
    module_tool_requirements = {
        "technologies": ["wappalyzer"],
        "web": ["zap"],
        "directories": ["dirsearch"],
        "ports": ["nmap"],
        "subdomains": ["sublist3r", "amass", "subfinder"],  # Needs at least one
        "vulns": ["zap"],
    }

    # Check which tools are available
    tool_availability = {}
    if hasattr(config, "tool_availability") and config.tool_availability:
        tool_availability = config.tool_availability

    # Check each module if it can run
    for module in list(active_modules):
        required_tools = module_tool_requirements.get(module, [])
        if not required_tools:
            continue

        # For modules that require at least one tool from several options (like subdomains)
        if module == "subdomains":
            has_one_tool = any(
                tool in tool_availability and tool_availability[tool][0]
                for tool in required_tools
            )
            if not has_one_tool:
                console.print(
                    f"Skipping {module} module: No required tools available",
                    style="yellow",
                )
                active_modules.remove(module)
        else:
            # For modules requiring specific tools
            missing_tools = [
                tool
                for tool in required_tools
                if tool not in tool_availability or not tool_availability[tool][0]
            ]
            if missing_tools:
                console.print(
                    f"Skipping {module} module: Missing required tools: {', '.join(missing_tools)}",
                    style="yellow",
                )
                active_modules.remove(module)

    for module in active_modules:
        try:
            scan_func = scan_functions[ScanModule(module)]
            module_findings = await scan_func(
                config.target, config.depth, config.ignore_ssl, config.tool_options
            )
            if module_findings:
                findings[config.target] = (
                    findings.get(config.target, []) + module_findings
                )
        except ToolNotFoundError as e:
            log.warning(f"Skipping {module} scan: {str(e)}")
            console.print(f"Skipping {module} module: {str(e)}", style="yellow")
        except Exception as e:
            log.error(f"Error during {module} scan: {str(e)}")
            raise ScanExecutionError(f"Failed to execute {module} scan: {str(e)}")

    return findings


async def run_technology_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute technology detection scan using Wappalyzer."""
    log.info(f"Starting technology scan on {target}")

    try:
        wappalyzer = WappalyzerIntegration()

        # Get any Wappalyzer-specific options
        wappalyzer_options = tool_options.get("wappalyzer", {}) if tool_options else {}
        
        # Run the scan with verify_ssl parameter
        results = await wappalyzer.scan(target, verify_ssl=not ignore_ssl)
        findings = []

        # Check if results is a list (newer version) or a dict (older version)
        if isinstance(results, dict) and "technologies" in results:
            # Handle as dict with technologies key
            for tech in results.get("technologies", []):
                finding = Finding(
                    title=f"Technology Detected: {tech['name']}",
                    description=f"Version: {tech.get('version', 'Unknown')}\n"
                    f"Categories: {', '.join(tech.get('categories', []))}",
                    severity=Severity.INFO,
                    confidence=tech.get("confidence", 100),
                    target=target,
                    tool="wappalyzer",
                    raw_data=tech,
                )
                findings.append(finding)
        elif isinstance(results, list):
            # Handle as list of findings
            for tech in results:
                finding = Finding(
                    title=f"Technology Detected: {tech.technology_name if hasattr(tech, 'technology_name') else 'Unknown'}",
                    description=f"Version: {tech.version if hasattr(tech, 'version') else 'Unknown'}\n"
                    f"Categories: {', '.join(tech.categories) if hasattr(tech, 'categories') else 'Unknown'}",
                    severity=Severity.INFO,
                    confidence=100,
                    target=target,
                    tool="wappalyzer",
                    raw_data=tech.__dict__ if hasattr(tech, "__dict__") else {},
                )
                findings.append(finding)
        else:
            log.warning(f"Unexpected Wappalyzer results format: {type(results)}")

        return findings

    except Exception as e:
        log.error(f"Error during technology scan: {str(e)}")
        raise ScanExecutionError(f"Technology scan failed: {str(e)}")


async def run_subdomain_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute subdomain discovery scan."""
    log.info(f"Starting subdomain scan on {target}")
    findings = []

    try:
        tools_config = tool_options or {}

        # Configure scan depth parameters
        if depth == ScanDepth.QUICK:
            max_subdomains = 100
            timeout = 300
        elif depth == ScanDepth.COMPREHENSIVE:
            max_subdomains = 1000
            timeout = 1800
        else:  # STANDARD
            max_subdomains = 500
            timeout = 900

        # Run available subdomain discovery tools
        for tool_name in ["sublist3r", "amass", "subfinder"]:
            try:
                tool_class = get_subdomain_tool(tool_name)
                if not tool_class:
                    continue

                # Initialize without verify_ssl param
                tool = tool_class(
                    options=tools_config.get(tool_name, {})
                )

                # Pass verify_ssl to scan method if supported
                try:
                    subdomains = await tool.scan(
                        target, 
                        max_results=max_subdomains, 
                        timeout=timeout,
                        verify_ssl=not ignore_ssl
                    )
                except TypeError:
                    # If verify_ssl is not supported, call without it
                    subdomains = await tool.scan(
                        target, 
                        max_results=max_subdomains, 
                        timeout=timeout
                    )

                for subdomain in subdomains:
                    finding = Finding(
                        title=f"Subdomain Discovered: {subdomain}",
                        description=f"Active subdomain found by {tool_name}",
                        severity=Severity.INFO,
                        confidence=90,
                        target=target,
                        tool=tool_name,
                        raw_data={"subdomain": subdomain},
                    )
                    findings.append(finding)

            except ToolNotFoundError:
                log.warning(f"{tool_name} not available for subdomain scanning")
            except Exception as e:
                log.error(f"Error with {tool_name}: {str(e)}")

        return findings

    except Exception as e:
        log.error(f"Error during subdomain scan: {str(e)}")
        raise ScanExecutionError(f"Subdomain scan failed: {str(e)}")


async def run_port_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute port scan using Nmap."""
    log.info(f"Starting port scan on {target}")

    try:
        nmap_config = tool_options.get("nmap", {}) if tool_options else {}

        # Configure scan parameters based on depth
        if depth == ScanDepth.QUICK:
            ports = "80,443,8080,8443"  # Common web ports for quick scan
            timing = 4
        elif depth == ScanDepth.COMPREHENSIVE:
            ports = "1-65535"  # All ports
            timing = 4
        else:  # STANDARD
            ports = "1-1000"  # First 1000 ports
            timing = 3

        # Initialize NmapIntegration without options parameter
        nmap = NmapIntegration()
        
        # Extract hostname from target URL
        import re
        hostname = re.sub(r'^https?://', '', target)
        hostname = hostname.split('/')[0]  # Remove any path component
        
        # Call scan with just the ports parameter
        port_findings = await nmap.scan(hostname, ports=ports)
        
        # Convert PortFinding objects to our Finding model
        findings = []
        for finding in port_findings:
            finding_dict = {}
            if hasattr(finding, "__dict__"):
                finding_dict = finding.__dict__.copy()
            elif hasattr(finding, "dict"):
                # Use dict method if available
                try:
                    finding_dict = finding.dict()
                except:
                    pass
            
            finding = Finding(
                title=finding.title,
                description=finding.description,
                severity=Severity.MEDIUM if finding.severity == FindingSeverity.MEDIUM else Severity.LOW,
                confidence=90,
                target=f"{target}:{finding.port}",
                tool="nmap",
                raw_data=finding_dict
            )
            findings.append(finding)

        return findings

    except Exception as e:
        log.error(f"Error during port scan: {str(e)}")
        raise ScanExecutionError(f"Port scan failed: {str(e)}")


async def run_web_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute web vulnerability scan using OWASP ZAP."""
    log.info(f"Starting web vulnerability scan on {target}")

    try:
        zap_config = tool_options.get("zap", {}) if tool_options else {}

        # Configure scan parameters based on depth
        if depth == ScanDepth.QUICK:
            scan_policy = "quick"
            max_spider_duration = 5
        elif depth == ScanDepth.COMPREHENSIVE:
            scan_policy = "comprehensive"
            max_spider_duration = 30
        else:  # STANDARD
            scan_policy = "standard"
            max_spider_duration = 15

        zap = ZAPIntegration(
            verify_ssl=not ignore_ssl,
            options={
                **zap_config,
                "scan_policy": zap_config.get("scan_policy", scan_policy),
                "max_spider_duration": zap_config.get(
                    "max_spider_duration", max_spider_duration
                ),
            },
        )

        results = await zap.scan(target)
        findings = []

        for alert in results.get("alerts", []):
            finding = Finding(
                title=alert["name"],
                description=(
                    f"Risk: {alert['risk']}\n"
                    f"Confidence: {alert['confidence']}\n"
                    f"URL: {alert['url']}\n\n"
                    f"Description: {alert['description']}\n\n"
                    f"Solution: {alert['solution']}"
                ),
                severity=map_zap_risk_to_severity(alert["risk"]),
                confidence=map_zap_confidence_to_int(alert["confidence"]),
                target=alert["url"],
                tool="zap",
                raw_data=alert,
            )
            findings.append(finding)

        return findings

    except Exception as e:
        log.error(f"Error during web scan: {str(e)}")
        raise ScanExecutionError(f"Web scan failed: {str(e)}")


async def run_directory_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute directory/file discovery scan using Dirsearch."""
    log.info(f"Starting directory scan on {target}")

    try:
        dirsearch_config = tool_options.get("dirsearch", {}) if tool_options else {}

        # Configure scan parameters based on depth
        if depth == ScanDepth.QUICK:
            wordlist = "quick.txt"
            threads = 10
        elif depth == ScanDepth.COMPREHENSIVE:
            wordlist = "comprehensive.txt"
            threads = 30
        else:  # STANDARD
            wordlist = "standard.txt"
            threads = 20

        # Initialize DirsearchIntegration without verify_ssl parameter
        dirsearch = DirsearchIntegration(
            options={
                **dirsearch_config,
                "wordlist": dirsearch_config.get("wordlist", wordlist),
                "threads": dirsearch_config.get("threads", threads),
            },
        )

        # Pass verify_ssl to scan method
        results = await dirsearch.scan(target, verify_ssl=not ignore_ssl)
        findings = []

        for entry in results.get("entries", []):
            finding = Finding(
                title=f"Directory/File Found: {entry['path']}",
                description=(
                    f"Status: {entry['status']}\n"
                    f"Size: {entry.get('size', 'unknown')}\n"
                    f"Content Type: {entry.get('content_type', 'unknown')}"
                ),
                severity=map_status_code_to_severity(entry["status"]),
                confidence=90,
                target=f"{target}{entry['path']}",
                tool="dirsearch",
                raw_data=entry,
            )
            findings.append(finding)

        return findings

    except Exception as e:
        log.error(f"Error during directory scan: {str(e)}")
        raise ScanExecutionError(f"Directory scan failed: {str(e)}")


async def run_vulnerability_scan(
    target: str,
    depth: ScanDepth,
    ignore_ssl: bool = False,
    tool_options: Optional[Dict] = None,
) -> List[Finding]:
    """Execute vulnerability scanning using available scanners."""
    log.info(f"Starting vulnerability scan on {target}")
    findings = []

    try:
        # Configure scan depth parameters
        if depth == ScanDepth.QUICK:
            scan_depth = "quick"
            timeout = 600
        elif depth == ScanDepth.COMPREHENSIVE:
            scan_depth = "comprehensive"
            timeout = 3600
        else:  # STANDARD
            scan_depth = "standard"
            timeout = 1800

        # First try to use ZAP if available
        try:
            zap_options = tool_options.get("zap", {}) if tool_options else {}
            zap = ZAPIntegration(verify_ssl=not ignore_ssl, options=zap_options)

            zap_results = await zap.scan(target, timeout=timeout)

            # Process ZAP findings
            if isinstance(zap_results, dict) and "alerts" in zap_results:
                for alert in zap_results["alerts"]:
                    finding = Finding(
                        title=f"ZAP Alert: {alert.get('name', 'Unknown')}",
                        description=alert.get("description", "No description"),
                        severity=map_zap_risk_to_severity(alert.get("risk", "Low")),
                        confidence=map_zap_confidence_to_int(
                            alert.get("confidence", "Low")
                        ),
                        target=target,
                        url=alert.get("url", target),
                        tool="zap",
                        raw_data=alert,
                    )
                    findings.append(finding)

            log.info(f"ZAP scan completed with {len(findings)} findings")

        except (ToolNotFoundError, Exception) as e:
            log.warning(f"ZAP scan failed: {str(e)}")
            # Continue with other scanners

        # Try to use other vulnerability scanners if configured
        # For now, just return what we have from ZAP
        return findings

    except Exception as e:
        log.error(f"Error during vulnerability scan: {str(e)}")
        raise ScanExecutionError(f"Vulnerability scan failed: {str(e)}")


def output_scan_results(
    findings: Dict[str, List[Finding]],
    output_file: Optional[Path] = None,
    json_format: bool = False,
) -> None:
    """Output scan results to console and/or file."""
    try:
        # Debug output to see what's in the findings
        for target, target_findings in findings.items():
            log.info(f"Findings for target {target}: {len(target_findings)}")
            for i, finding in enumerate(target_findings):
                log.info(f"Finding {i}: {type(finding)}")
                log.info(f"Finding {i} attributes: {dir(finding)}")
        
        # Process and normalize findings
        normalizer = ResultNormalizer()
        all_findings = []
        for target_findings in findings.values():
            all_findings.extend(target_findings)

        correlated_findings = normalizer.correlate_findings(all_findings)
        log.info(f"After correlation, have findings for {len(correlated_findings)} targets")
        
        # Flatten all findings
        flattened_findings = []
        for target, target_findings in correlated_findings.items():
            flattened_findings.extend(target_findings)
        
        log.info(f"Total findings after flattening: {len(flattened_findings)}")

        # Console output
        console.print("\nScan Results Summary:", style="bold blue")

        # Display summary table
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count")

        # Group findings by severity
        findings_by_severity = {}
        for i, finding in enumerate(flattened_findings):
            log.info(f"Processing finding {i}: {type(finding)}")
            log.info(f"Finding {i} severity: {type(finding.severity)}")
            findings_by_severity.setdefault(finding.severity, []).append(finding)

        for severity in Severity:
            count = len(findings_by_severity.get(severity, []))
            if count > 0:
                table.add_row(
                    severity.name, str(count), style=get_severity_style(severity)
                )

        console.print(table)

        # Detailed findings output
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)

            if json_format:
                # JSON output
                with output_file.open("w") as f:
                    json.dump(
                        [finding.model_dump() for finding in flattened_findings],
                        f,
                        indent=2,
                    )
            else:
                # Markdown output
                with output_file.open("w") as f:
                    f.write("# Security Scan Results\n\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n\n")

                    # Write findings by severity
                    for severity in Severity:
                        severity_findings = findings_by_severity.get(severity, [])
                        if severity_findings:
                            f.write(f"\n## {severity.name} Findings\n\n")
                            for finding in severity_findings:
                                f.write(f"### {finding.title}\n")
                                f.write(f"- Target: {finding.target}\n")
                                f.write(f"- Confidence: {finding.confidence}%\n")
                                f.write(f"- Tool: {finding.tool}\n\n")
                                f.write(f"{finding.description}\n\n")

            console.print(
                f"\nDetailed results written to: {output_file}", style="green"
            )

    except Exception as e:
        log.error(f"Error outputting results: {str(e)}")
        raise ScanExecutionError(f"Failed to output results: {str(e)}")


if __name__ == "__main__":
    app()
