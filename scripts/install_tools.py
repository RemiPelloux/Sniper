#!/usr/bin/env python3
"""
Sniper Security Tool - Tool Installer

This script installs all the necessary security tools for the Sniper Security Platform.
It can be run in interactive or non-interactive mode, and supports installation
of tools by category or individually.
"""

import argparse
import logging
import os
import sys
import time
from typing import Dict, List, Optional, Set

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.tools.manager import ToolManager, ToolCategory
    from colorama import Fore, Style, init
except ImportError:
    print("Error: Required packages not found. Please install them using:")
    print("pip install colorama")
    sys.exit(1)

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("tool_installation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sniper.install_tools")


def print_banner() -> None:
    """Print the Sniper Security Tool banner."""
    banner = r"""
 ____             _                       
/ ___| _ __  (_) _ __    ___  _ __  
\___ \| '_ \ | || '_ \  / _ \| '__|
 ___) | | | || || |_) ||  __/| |   
|____/|_| |_||_|| .__/  \___||_|   
                |_|                
 Security Tool Installer
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This script will install security tools used by the Sniper Security Platform.{Style.RESET_ALL}")
    print()


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{Fore.YELLOW}! {message}{Style.RESET_ALL}")


def print_info(message: str) -> None:
    """Print an informational message."""
    print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")


def get_install_choices(interactive: bool = True, 
                        all_tools: bool = False,
                        categories: Optional[List[str]] = None,
                        tools: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """
    Determine which tools to install based on user input or command-line arguments.
    
    Args:
        interactive: Whether to prompt the user for input
        all_tools: Whether to install all tools
        categories: List of categories to install
        tools: List of specific tools to install
        
    Returns:
        Dictionary of {category: [tools]} to install
    """
    manager = ToolManager()
    all_tool_info = manager.get_all_tools()
    
    # Get available tools by category
    tools_by_category: Dict[str, List[str]] = {}
    for cat in ToolCategory.all():
        tools_by_category[cat] = []
    
    for name, info in all_tool_info.items():
        category = info.get("category", "utility")
        if category in tools_by_category:
            tools_by_category[category].append(name)
    
    # Check if tool is already installed
    installation_status = manager.get_installation_status()
    
    if all_tools:
        # Install all tools
        return tools_by_category
    
    if categories:
        # Install specified categories
        return {cat: tools for cat, tools in tools_by_category.items() if cat in categories}
    
    if tools:
        # Install specific tools
        result: Dict[str, List[str]] = {cat: [] for cat in ToolCategory.all()}
        for tool in tools:
            if tool in all_tool_info:
                category = all_tool_info[tool].get("category", "utility")
                result[category].append(tool)
        return result
    
    if not interactive:
        # Non-interactive mode with no specific selections
        print_warning("No tools or categories specified in non-interactive mode. No tools will be installed.")
        return {}
    
    # Interactive mode
    choices: Dict[str, List[str]] = {cat: [] for cat in ToolCategory.all()}
    
    print_info("Select categories of tools to install (or specific tools):")
    print()
    
    # Ask about each category
    for category, tools_list in tools_by_category.items():
        if not tools_list:
            continue
            
        installed_count = sum(1 for tool in tools_list if installation_status.get(tool, False))
        total_count = len(tools_list)
        
        print(f"{Fore.CYAN}=== {category.upper()} TOOLS ({installed_count}/{total_count} installed) ==={Style.RESET_ALL}")
        for i, tool in enumerate(tools_list, 1):
            is_installed = installation_status.get(tool, False)
            status = f"{Fore.GREEN}[Installed]" if is_installed else f"{Fore.RED}[Not Installed]"
            desc = all_tool_info[tool].get("description", "")
            print(f"{i}. {tool} {status} - {desc}")
        
        response = input(f"\nInstall all {category} tools? [y/N/list] ")
        if response.lower() == "list":
            # Ask about each tool individually
            for tool in tools_list:
                is_installed = installation_status.get(tool, False)
                if is_installed:
                    print(f"{tool} is already installed. Skip.")
                    continue
                    
                response = input(f"Install {tool}? [y/N] ")
                if response.lower() in ["y", "yes"]:
                    choices[category].append(tool)
        elif response.lower() in ["y", "yes"]:
            # Add all tools in this category
            choices[category] = tools_list
            
        print()
    
    return choices


def install_tools(choices: Dict[str, List[str]], force: bool = False) -> None:
    """
    Install the selected tools.
    
    Args:
        choices: Dictionary of {category: [tools]} to install
        force: Whether to reinstall tools that are already installed
    """
    manager = ToolManager()
    
    # Flatten the choices into a single list
    all_tools_to_install = []
    for tools_list in choices.values():
        all_tools_to_install.extend(tools_list)
    
    if not all_tools_to_install:
        print_warning("No tools selected for installation.")
        return
    
    # Get current installation status
    installation_status = manager.get_installation_status()
    
    # Count tools
    already_installed = sum(1 for tool in all_tools_to_install if installation_status.get(tool, False))
    to_install = len(all_tools_to_install) - already_installed
    
    print_info(f"Will install {to_install} new tools" + (f" and reinstall {already_installed} tools" if force else ""))
    print()
    
    # Install tools by category
    successful = 0
    failed = 0
    skipped = 0
    
    for category, tools_list in sorted(choices.items()):
        if not tools_list:
            continue
            
        print(f"{Fore.CYAN}=== Installing {category.upper()} tools ==={Style.RESET_ALL}")
        
        for tool in tools_list:
            is_installed = installation_status.get(tool, False)
            
            if is_installed and not force:
                print(f"Skipping {tool} (already installed)")
                skipped += 1
                continue
            
            print(f"Installing {tool}...")
            start_time = time.time()
            
            success = manager.install_tool(tool)
            
            elapsed_time = time.time() - start_time
            time_str = f"({elapsed_time:.1f}s)"
            
            if success:
                print_success(f"Installed {tool} {time_str}")
                successful += 1
            else:
                print_error(f"Failed to install {tool} {time_str}")
                failed += 1
        
        print()
    
    # Print summary
    print(f"{Fore.CYAN}=== Installation Summary ==={Style.RESET_ALL}")
    print(f"Successfully installed: {successful}")
    print(f"Failed to install: {failed}")
    print(f"Skipped (already installed): {skipped}")
    
    if failed > 0:
        print_warning("Some tools failed to install. Check the log file for details.")
        print_info("You can try installing them individually or with a different installation method.")


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Sniper Security Tool - Install required security tools"
    )
    
    # Installation scope options
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--all", action="store_true", help="Install all available tools")
    scope_group.add_argument("--categories", nargs="+", help="Install tools in specific categories")
    scope_group.add_argument("--tools", nargs="+", help="Install specific tools")
    
    # Other options
    parser.add_argument("--non-interactive", action="store_true", 
                      help="Run in non-interactive mode (requires --all, --categories, or --tools)")
    parser.add_argument("--force", action="store_true", 
                      help="Force reinstallation of tools that are already installed")
    parser.add_argument("--no-banner", action="store_true", 
                      help="Don't display the banner")
    
    args = parser.parse_args()
    
    # Show banner
    if not args.no_banner:
        print_banner()
    
    # Check if non-interactive mode has required arguments
    if args.non_interactive and not (args.all or args.categories or args.tools):
        print_error("Non-interactive mode requires --all, --categories, or --tools")
        sys.exit(1)
    
    try:
        # Determine which tools to install
        choices = get_install_choices(
            interactive=not args.non_interactive,
            all_tools=args.all,
            categories=args.categories,
            tools=args.tools
        )
        
        # Install tools
        install_tools(choices, force=args.force)
        
    except KeyboardInterrupt:
        print("\nInstallation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error during installation: {e}")
        logger.exception("An error occurred during installation")
        sys.exit(1)


if __name__ == "__main__":
    main() 