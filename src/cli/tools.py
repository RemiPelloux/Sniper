"""
Command-line interface for managing Sniper security tools.

This module provides a CLI for listing, installing, updating, and managing
security tools used by the Sniper Security Tool.
"""

import argparse
import json
import logging
import os
import sys
import textwrap
from typing import Dict, List, Optional, Any

import tabulate
import yaml
from colorama import Fore, Style, init

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.tools.manager import ToolManager, ToolCategory

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("sniper.cli.tools")


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


def list_tools(args: argparse.Namespace) -> None:
    """
    List available tools, optionally filtered by category and installation status.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    # Get all tools
    all_tools = manager.get_all_tools()
    
    # Get installation status
    installation_status = manager.get_installation_status()
    
    # Filter by category if specified
    if args.category:
        filtered_tools = {
            name: info for name, info in all_tools.items()
            if info.get("category") == args.category
        }
    else:
        filtered_tools = all_tools
    
    # Filter by installation status if specified
    if args.installed:
        filtered_tools = {
            name: info for name, info in filtered_tools.items()
            if installation_status.get(name, False)
        }
    elif args.not_installed:
        filtered_tools = {
            name: info for name, info in filtered_tools.items()
            if not installation_status.get(name, False)
        }
    
    # Prepare output format
    if args.json:
        # JSON output
        json_output = []
        for name, info in filtered_tools.items():
            tool_info = dict(info)
            tool_info["installed"] = installation_status.get(name, False)
            json_output.append(tool_info)
        print(json.dumps(json_output, indent=2))
    else:
        # Table output
        table_data = []
        for name, info in filtered_tools.items():
            installed = installation_status.get(name, False)
            status = f"{Fore.GREEN}Installed{Style.RESET_ALL}" if installed else f"{Fore.RED}Not Installed{Style.RESET_ALL}"
            
            description = info.get("description", "")
            if len(description) > 50:
                description = description[:47] + "..."
                
            row = [
                name,
                info.get("category", ""),
                description,
                status
            ]
            
            table_data.append(row)
        
        headers = ["Name", "Category", "Description", "Status"]
        if table_data:
            print(tabulate.tabulate(table_data, headers=headers, tablefmt="simple"))
        else:
            print_warning("No tools found matching the specified criteria.")
        
        print(f"\nTotal: {len(table_data)} tools")


def show_tool(args: argparse.Namespace) -> None:
    """
    Show detailed information about a specific tool.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    tool_info = manager.get_tool(args.name)
    if not tool_info:
        print_error(f"Tool '{args.name}' not found")
        return
    
    # Check if the tool is installed
    is_installed = manager.check_tool_availability(args.name)
    
    # Display basic information
    print(f"{Fore.CYAN}=== {tool_info.get('name')} ==={Style.RESET_ALL}")
    print(f"Category: {tool_info.get('category', 'Unknown')}")
    print(f"Description: {tool_info.get('description', 'No description available')}")
    print(f"Status: {Fore.GREEN}Installed{Style.RESET_ALL}" if is_installed else f"Status: {Fore.RED}Not Installed{Style.RESET_ALL}")
    
    # Display additional information
    if "website" in tool_info:
        print(f"Website: {tool_info['website']}")
        
    if "documentation" in tool_info:
        print(f"Documentation: {tool_info['documentation']}")
        
    if "execution_time" in tool_info:
        print(f"Execution Time: {tool_info['execution_time']}")
        
    if "target_types" in tool_info:
        print(f"Target Types: {', '.join(tool_info['target_types'])}")
    
    # Display installation methods
    if "install" in tool_info:
        print("\nInstallation Methods:")
        for method, command in tool_info["install"].items():
            print(f"  - {method}: {command}")
    
    # Display update methods
    if "update" in tool_info:
        print("\nUpdate Methods:")
        for method, command in tool_info["update"].items():
            print(f"  - {method}: {command}")
    
    print()


def install_tool(args: argparse.Namespace) -> None:
    """
    Install one or more tools.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    if args.all:
        # Install all tools
        all_tools = manager.get_all_tools()
        
        if args.category:
            # Filter by category
            tools_to_install = manager.get_tool_names_by_category(args.category)
        else:
            tools_to_install = list(all_tools.keys())
        
        print_info(f"Installing {len(tools_to_install)} tools...")
        
        success_count = 0
        for tool_name in tools_to_install:
            print(f"Installing {tool_name}...")
            if manager.install_tool(tool_name, args.method):
                print_success(f"Installed {tool_name}")
                success_count += 1
            else:
                print_error(f"Failed to install {tool_name}")
        
        print(f"\nInstalled {success_count} of {len(tools_to_install)} tools")
    else:
        # Install specific tools
        for tool_name in args.tools:
            print(f"Installing {tool_name}...")
            if manager.install_tool(tool_name, args.method):
                print_success(f"Installed {tool_name}")
            else:
                print_error(f"Failed to install {tool_name}")


def update_tool(args: argparse.Namespace) -> None:
    """
    Update one or more tools.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    if args.all:
        # Update all installed tools
        installation_status = manager.get_installation_status()
        tools_to_update = [name for name, installed in installation_status.items() if installed]
        
        if args.category:
            # Filter by category
            category_tools = manager.get_tool_names_by_category(args.category)
            tools_to_update = [name for name in tools_to_update if name in category_tools]
        
        print_info(f"Updating {len(tools_to_update)} tools...")
        
        success_count = 0
        for tool_name in tools_to_update:
            print(f"Updating {tool_name}...")
            if manager.update_tool(tool_name):
                print_success(f"Updated {tool_name}")
                success_count += 1
            else:
                print_error(f"Failed to update {tool_name}")
        
        print(f"\nUpdated {success_count} of {len(tools_to_update)} tools")
    else:
        # Update specific tools
        for tool_name in args.tools:
            # Check if the tool is installed
            if not manager.check_tool_availability(tool_name):
                print_warning(f"Tool '{tool_name}' is not installed. Installing instead...")
                if manager.install_tool(tool_name):
                    print_success(f"Installed {tool_name}")
                else:
                    print_error(f"Failed to install {tool_name}")
                continue
            
            print(f"Updating {tool_name}...")
            if manager.update_tool(tool_name):
                print_success(f"Updated {tool_name}")
            else:
                print_error(f"Failed to update {tool_name}")


def add_tool(args: argparse.Namespace) -> None:
    """
    Add a new custom tool.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    # Check if the tool already exists
    if manager.get_tool(args.name):
        print_error(f"Tool '{args.name}' already exists")
        return
    
    # Create tool information
    tool_info = {
        "name": args.name,
        "category": args.category,
        "description": args.description,
    }
    
    if args.binary:
        tool_info["binary"] = args.binary
    
    if args.check_command:
        tool_info["check_command"] = args.check_command
    
    # Add installation methods
    if args.install:
        install_methods = {}
        for method_str in args.install:
            try:
                method, command = method_str.split(":", 1)
                install_methods[method.strip()] = command.strip()
            except ValueError:
                print_error(f"Invalid installation method format: {method_str}")
                print_info("Format should be 'method:command'")
                return
        
        if install_methods:
            tool_info["install"] = install_methods
    
    # Add update methods
    if args.update:
        update_methods = {}
        for method_str in args.update:
            try:
                method, command = method_str.split(":", 1)
                update_methods[method.strip()] = command.strip()
            except ValueError:
                print_error(f"Invalid update method format: {method_str}")
                print_info("Format should be 'method:command'")
                return
        
        if update_methods:
            tool_info["update"] = update_methods
    
    # Add additional properties
    if args.website:
        tool_info["website"] = args.website
    
    if args.documentation:
        tool_info["documentation"] = args.documentation
    
    if args.execution_time:
        tool_info["execution_time"] = args.execution_time
    
    if args.target_types:
        tool_info["target_types"] = args.target_types
    
    # Add the tool
    if manager.add_tool(tool_info):
        print_success(f"Added custom tool '{args.name}'")
    else:
        print_error(f"Failed to add custom tool '{args.name}'")


def remove_tool(args: argparse.Namespace) -> None:
    """
    Remove a custom tool.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    if manager.remove_tool(args.name):
        print_success(f"Removed custom tool '{args.name}'")
    else:
        print_error(f"Failed to remove tool '{args.name}'")
        print_info("Note: Only custom tools can be removed.")


def categories(args: argparse.Namespace) -> None:
    """
    List available tool categories.
    
    Args:
        args: Command-line arguments
    """
    print(f"{Fore.CYAN}Available Tool Categories:{Style.RESET_ALL}")
    for category in ToolCategory.all():
        print(f"  - {category}")


def check_updates(args: argparse.Namespace) -> None:
    """
    Check for tool updates.
    
    Args:
        args: Command-line arguments
    """
    manager = ToolManager()
    
    # Get installed tools
    installation_status = manager.get_installation_status()
    installed_tools = [name for name, installed in installation_status.items() if installed]
    
    # Check for updates (placeholder implementation)
    print_info("Checking for updates...")
    updates_available = manager.check_for_updates()
    
    # Filter to just installed tools
    updates_available = {name: needs_update for name, needs_update in updates_available.items() if name in installed_tools}
    
    # Display results
    tools_to_update = [name for name, needs_update in updates_available.items() if needs_update]
    
    if tools_to_update:
        print_info(f"Updates available for {len(tools_to_update)} tools:")
        for tool_name in tools_to_update:
            print(f"  - {tool_name}")
        
        # Prompt to update
        if not args.no_prompt:
            response = input("\nDo you want to update these tools? [y/N] ")
            if response.lower() in ["y", "yes"]:
                for tool_name in tools_to_update:
                    print(f"Updating {tool_name}...")
                    if manager.update_tool(tool_name):
                        print_success(f"Updated {tool_name}")
                    else:
                        print_error(f"Failed to update {tool_name}")
    else:
        print_success("All tools are up to date.")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Sniper Security Tool - Tool Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              List all tools:
                sniper-tools list
                
              List tools in a specific category:
                sniper-tools list --category reconnaissance
                
              Show details for a specific tool:
                sniper-tools show nmap
                
              Install a tool:
                sniper-tools install nmap
                
              Install all tools in a category:
                sniper-tools install --all --category vulnerability_scanning
                
              Update an installed tool:
                sniper-tools update nmap
                
              Add a custom tool:
                sniper-tools add --name custom-tool --category utility --description "My custom tool" --binary custom-tool
                
              Remove a custom tool:
                sniper-tools remove custom-tool
        """)
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available tools")
    list_parser.add_argument("--category", help="Filter by category")
    list_parser.add_argument("--installed", action="store_true", help="Show only installed tools")
    list_parser.add_argument("--not-installed", action="store_true", help="Show only not installed tools")
    list_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    list_parser.set_defaults(func=list_tools)
    
    # Show command
    show_parser = subparsers.add_parser("show", help="Show detailed information about a tool")
    show_parser.add_argument("name", help="Name of the tool")
    show_parser.set_defaults(func=show_tool)
    
    # Install command
    install_parser = subparsers.add_parser("install", help="Install tools")
    install_parser.add_argument("tools", nargs="*", help="Names of tools to install")
    install_parser.add_argument("--all", action="store_true", help="Install all tools")
    install_parser.add_argument("--category", help="Filter by category (when using --all)")
    install_parser.add_argument("--method", help="Installation method override")
    install_parser.set_defaults(func=install_tool)
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update installed tools")
    update_parser.add_argument("tools", nargs="*", help="Names of tools to update")
    update_parser.add_argument("--all", action="store_true", help="Update all installed tools")
    update_parser.add_argument("--category", help="Filter by category (when using --all)")
    update_parser.set_defaults(func=update_tool)
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add a custom tool")
    add_parser.add_argument("--name", required=True, help="Name of the tool")
    add_parser.add_argument("--category", required=True, help="Category of the tool")
    add_parser.add_argument("--description", required=True, help="Description of the tool")
    add_parser.add_argument("--binary", help="Binary executable name")
    add_parser.add_argument("--check-command", help="Command to check if the tool is installed")
    add_parser.add_argument("--install", nargs="+", help="Installation methods (format: method:command)")
    add_parser.add_argument("--update", nargs="+", help="Update methods (format: method:command)")
    add_parser.add_argument("--website", help="Website URL")
    add_parser.add_argument("--documentation", help="Documentation URL")
    add_parser.add_argument("--execution-time", choices=["fast", "medium", "slow"], help="Execution time category")
    add_parser.add_argument("--target-types", nargs="+", help="Target types the tool supports")
    add_parser.set_defaults(func=add_tool)
    
    # Remove command
    remove_parser = subparsers.add_parser("remove", help="Remove a custom tool")
    remove_parser.add_argument("name", help="Name of the tool to remove")
    remove_parser.set_defaults(func=remove_tool)
    
    # Categories command
    categories_parser = subparsers.add_parser("categories", help="List available tool categories")
    categories_parser.set_defaults(func=categories)
    
    # Check updates command
    updates_parser = subparsers.add_parser("check-updates", help="Check for tool updates")
    updates_parser.add_argument("--no-prompt", action="store_true", help="Don't prompt to install updates")
    updates_parser.set_defaults(func=check_updates)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute the command
    if hasattr(args, "func"):
        try:
            args.func(args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print_error(f"Error: {e}")
            logger.exception("An error occurred")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
