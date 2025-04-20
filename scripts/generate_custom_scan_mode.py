#!/usr/bin/env python3
"""
Custom Scan Mode Generator for Sniper Security Tool.

This script helps you create a custom scan mode configuration by walking
through a series of questions and generating the appropriate YAML file.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import yaml

# Constants
MODULES = ["technologies", "subdomains", "ports", "web", "directories"]
SCAN_DEPTHS = ["quick", "standard", "comprehensive"]
COMMON_TOOLS = {
    "wappalyzer": {"technologies": True},
    "sublist3r": {"subdomains": True},
    "amass": {"subdomains": True},
    "subfinder": {"subdomains": True},
    "nmap": {"ports": True},
    "zap": {"web": True},
    "nuclei": {"web": True},
    "dirsearch": {"directories": True},
    "gobuster": {"directories": True},
    "ffuf": {"directories": True},
    "sqlmap": {"web": True},
    "nikto": {"web": True},
    "wpscan": {"web": True},
    "httpx": {"technologies": True, "web": True},
}

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
SCAN_MODES_FILE = CONFIG_DIR / "scan_modes.yaml"


def prompt_user(message: str, default: Optional[str] = None) -> str:
    """
    Prompt the user for input with an optional default value.

    Args:
        message: The message to display to the user
        default: Optional default value if the user doesn't provide input

    Returns:
        The user's input or the default value
    """
    if default:
        prompt = f"{message} [{default}]: "
    else:
        prompt = f"{message}: "

    response = input(prompt).strip()
    return response if response else (default or "")


def prompt_yes_no(message: str, default: bool = True) -> bool:
    """
    Prompt the user for a yes/no response.

    Args:
        message: The message to display to the user
        default: Default value (True for yes, False for no)

    Returns:
        True for yes, False for no
    """
    default_str = "Y/n" if default else "y/N"
    prompt = f"{message} [{default_str}]: "

    response = input(prompt).strip().lower()
    if not response:
        return default

    return response.startswith("y")


def prompt_options(
    message: str,
    options: List[str],
    default: Optional[str] = None,
    allow_multiple: bool = False,
) -> Union[str, List[str]]:
    """
    Prompt the user to select from a list of options.

    Args:
        message: The message to display to the user
        options: List of options to choose from
        default: Optional default value
        allow_multiple: Whether to allow selecting multiple options

    Returns:
        The selected option or list of options
    """
    print(f"{message}")
    for i, option in enumerate(options):
        print(f"  {i+1}. {option}")

    if allow_multiple:
        prompt = f"Enter numbers (comma-separated) or 'all'"
        if default:
            prompt += f" [default: {default}]"
        prompt += ": "
    else:
        prompt = f"Enter number"
        if default:
            default_idx = options.index(default) + 1 if default in options else ""
            prompt += f" [default: {default_idx}]"
        prompt += ": "

    response = input(prompt).strip().lower()

    if not response and default:
        return default if allow_multiple else default

    if allow_multiple and response == "all":
        return options

    try:
        if allow_multiple:
            selected = [options[int(idx.strip()) - 1] for idx in response.split(",")]
            return selected
        else:
            return options[int(response) - 1]
    except (ValueError, IndexError):
        print("Invalid input. Please try again.")
        return prompt_options(message, options, default, allow_multiple)


def get_scan_mode_name() -> str:
    """Get the name for the custom scan mode."""
    name = ""
    while not name:
        name = prompt_user(
            "Enter a name for your custom scan mode (e.g., wordpress, microservices)"
        )
        if not name:
            print("Name cannot be empty. Please try again.")

    # Validate the name (no spaces, special characters)
    name = name.lower().replace(" ", "_").replace("-", "_")
    return name


def get_scan_mode_description() -> str:
    """Get the description for the custom scan mode."""
    return prompt_user(
        "Enter a description for your custom scan mode",
        "Custom scan mode for specialized security assessment",
    )


def get_target_types() -> List[str]:
    """Get the target types for the custom scan mode."""
    target_types = [
        "domain",
        "url",
        "ip",
        "network",
        "webapp",
        "api",
        "repository",
        "container",
        "cloud",
        "package",
    ]

    selected = prompt_options(
        "Select the target types for this scan mode (comma-separated numbers):",
        target_types,
        allow_multiple=True,
    )

    return selected


def get_scan_modules() -> List[str]:
    """Get the modules to enable for the custom scan mode."""
    message = (
        "Select which modules to enable for this scan mode (comma-separated numbers):"
    )
    selected = prompt_options(message, MODULES, allow_multiple=True)

    return selected


def get_scan_settings() -> Dict:
    """Get the scan settings for the custom scan mode."""
    settings = {}

    # Get scan depth
    settings["scan_depth"] = prompt_options(
        "Select the scan depth level:", SCAN_DEPTHS, default="standard"
    )

    # Get thread count
    try:
        threads = int(prompt_user("Maximum number of threads to use", "10"))
        settings["max_threads"] = threads
    except ValueError:
        settings["max_threads"] = 10

    # Get timeout
    try:
        timeout = int(prompt_user("Timeout in seconds", "3600"))
        settings["timeout"] = timeout
    except ValueError:
        settings["timeout"] = 3600

    # Get retries
    try:
        retries = int(prompt_user("Number of retries for failed operations", "2"))
        settings["retries"] = retries
    except ValueError:
        settings["retries"] = 2

    # Get delay
    try:
        delay = int(prompt_user("Delay between requests in seconds (0 for none)", "0"))
        if delay > 0:
            settings["delay"] = delay
    except ValueError:
        pass

    return settings


def get_tool_configurations(modules: List[str]) -> Dict:
    """Get tool configurations based on selected modules."""
    tools = {}

    # Show tools based on selected modules
    relevant_tools = []
    for tool, module_map in COMMON_TOOLS.items():
        if any(module in modules for module in module_map.keys()):
            relevant_tools.append(tool)

    if not relevant_tools:
        print("No relevant tools found for the selected modules.")
        return tools

    print("\nSelect tools to include in your scan mode:")
    for tool in relevant_tools:
        if prompt_yes_no(f"Include {tool}?", True):
            tools[tool] = {"enabled": True, "options": {}}

            # Additional tool-specific options based on the tool
            if tool == "nmap":
                # Nmap specific options
                tools[tool]["options"]["ports"] = prompt_user(
                    "Ports to scan (e.g., 80,443 or top1000 or 1-65535)", "top1000"
                )

                timing_template = prompt_user(
                    "Timing template (1-5, higher is faster)", "3"
                )
                try:
                    timing_template = int(timing_template)
                    if 1 <= timing_template <= 5:
                        tools[tool]["options"]["timing_template"] = timing_template
                except ValueError:
                    tools[tool]["options"]["timing_template"] = 3

                if prompt_yes_no("Include vulnerability scanning scripts?", False):
                    tools[tool]["options"]["scripts"] = "vuln,auth"

            elif tool == "zap":
                # ZAP specific options
                active_scan = prompt_yes_no("Enable active scanning?", True)
                tools[tool]["options"]["active_scan"] = active_scan

                ajax_spider = prompt_yes_no("Enable AJAX spider?", False)
                tools[tool]["options"]["ajax_spider"] = ajax_spider

                if active_scan and prompt_yes_no("Use a specific scan policy?", False):
                    policy = prompt_user("Scan policy name", "Default Policy")
                    tools[tool]["options"]["scan_policy"] = policy

            elif tool == "nuclei":
                # Nuclei specific options
                templates = prompt_user(
                    "Template categories (comma-separated)", "cves,vulnerabilities"
                )
                tools[tool]["options"]["templates"] = templates

                severity = prompt_user(
                    "Severity levels (comma-separated)", "critical,high,medium"
                )
                tools[tool]["options"]["severity"] = severity

            elif tool in ["dirsearch", "gobuster", "ffuf"]:
                # Directory scanner specific options
                wordlist = prompt_user("Wordlist to use", "common.txt")
                tools[tool]["options"]["wordlist"] = wordlist

                extensions = prompt_user(
                    "File extensions to scan (comma-separated)", "php,html,js"
                )
                tools[tool]["options"]["extensions"] = extensions

    return tools


def create_scan_mode() -> Dict:
    """Create a custom scan mode configuration by prompting user for inputs."""
    print("\n=== Sniper Custom Scan Mode Generator ===\n")

    # Get basic information
    name = get_scan_mode_name()
    description = get_scan_mode_description()
    target_types = get_target_types()

    # Get module configuration
    print("\n=== Module Configuration ===")
    modules = get_scan_modules()

    # Get scan settings
    print("\n=== Scan Settings ===")
    settings = get_scan_settings()

    # Get tool configurations
    print("\n=== Tool Configuration ===")
    tools = get_tool_configurations(modules)

    # Create scan mode configuration
    scan_mode = {
        "name": name,
        "description": description,
        "target_types": target_types,
        "modules": modules,
        "settings": settings,
        "tools": tools,
    }

    return {name: scan_mode}


def save_scan_mode(
    scan_mode: Dict, output_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Save the scan mode configuration to a file.

    Args:
        scan_mode: Scan mode configuration dictionary
        output_path: Optional path to save the configuration

    Returns:
        Tuple of (success, message)
    """
    # Determine output path
    if not output_path:
        mode_name = list(scan_mode.keys())[0]
        output_path = CONFIG_DIR / f"scan_modes_examples/{mode_name}.yaml"

    output_file = Path(output_path)

    # Create parent directories if they don't exist
    output_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Write configuration to file
        with open(output_file, "w") as f:
            yaml.dump(scan_mode, f, default_flow_style=False)

        return True, f"Scan mode configuration saved to {output_file}"
    except Exception as e:
        return False, f"Error saving scan mode configuration: {str(e)}"


def update_main_config(scan_mode: Dict) -> Tuple[bool, str]:
    """
    Update the main scan_modes.yaml file with the new scan mode.

    Args:
        scan_mode: Scan mode configuration dictionary

    Returns:
        Tuple of (success, message)
    """
    if not SCAN_MODES_FILE.exists():
        return False, f"Main scan modes file not found at {SCAN_MODES_FILE}"

    try:
        # Load existing configuration
        with open(SCAN_MODES_FILE, "r") as f:
            existing_config = yaml.safe_load(f) or {}

        # Update with new scan mode
        existing_config.update(scan_mode)

        # Write back the updated configuration
        with open(SCAN_MODES_FILE, "w") as f:
            yaml.dump(existing_config, f, default_flow_style=False)

        return True, f"Scan mode added to main configuration file {SCAN_MODES_FILE}"
    except Exception as e:
        return False, f"Error updating main configuration file: {str(e)}"


def main():
    """Main function that drives the scan mode generator."""
    parser = argparse.ArgumentParser(
        description="Generate a custom scan mode configuration for Sniper Security Tool"
    )
    parser.add_argument(
        "--output", "-o", help="Path to save the generated scan mode configuration"
    )
    parser.add_argument(
        "--update-main",
        "-u",
        action="store_true",
        help="Update the main scan_modes.yaml file with the new scan mode",
    )

    args = parser.parse_args()

    # Create the scan mode configuration
    scan_mode = create_scan_mode()

    # Save the configuration
    success, message = save_scan_mode(scan_mode, args.output)
    print(message)

    if not success:
        sys.exit(1)

    # Update main configuration if requested
    if args.update_main:
        success, message = update_main_config(scan_mode)
        print(message)

        if not success:
            sys.exit(1)
    else:
        mode_name = list(scan_mode.keys())[0]
        print(f"\nTo use this scan mode, add it to config/scan_modes.yaml or use:")
        print(f"  poetry run sniper scan run example.com --mode {mode_name}")

    print("\nDone!")


if __name__ == "__main__":
    main()
