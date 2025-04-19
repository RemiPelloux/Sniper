"""
Command-line interface for managing Sniper security tools.

This module provides a CLI for listing, installing, updating, and managing
security tools used by the Sniper Security Tool using Typer.
"""

import json
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import tabulate
import typer
import yaml
from colorama import Fore, Style, init
from typing_extensions import Annotated

# Add parent directory to path for imports
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.tools.manager import ToolCategory, ToolInstallMethod, ToolManager

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Rename app to avoid conflict if this module is imported elsewhere
tools_app = typer.Typer(
    name="tools",
    help="Manage security tools used by Sniper",
    no_args_is_help=True,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
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


@tools_app.command("list")
def list_tools(
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category", "-c", help="Filter tools by category (e.g., reconnaissance)"
        ),
    ] = None,
    installed: Annotated[
        Optional[bool],
        typer.Option("--installed", "-i", help="Show only installed tools"),
    ] = None,
    not_installed: Annotated[
        Optional[bool],
        typer.Option(
            "--not-installed", "-n", help="Show only tools that are not installed"
        ),
    ] = None,
    json_output: Annotated[
        Optional[bool], typer.Option("--json", help="Output in JSON format")
    ] = None,
) -> None:
    """
    List available tools, optionally filtered by category and installation status.
    """
    manager = ToolManager()

    # Get all tools
    all_tools = manager.get_all_tools()

    # Get installation status
    installation_status = manager.get_installation_status()

    # Filter by category if specified
    if category:
        try:
            ToolCategory(category)  # Validate category
            # Correctly indented block for filtering
            filtered_tools = {
                name: info
                for name, info in all_tools.items()
                if info.get("category") == category
            }
        except ValueError:
            # This block executes if ToolCategory(category) fails
            print_error(
                f"Invalid category: {category}. Available categories: {[c.value for c in ToolCategory]}"
            )
            raise typer.Exit(code=1)
    else:
        # This executes if no category filter is applied
        filtered_tools = all_tools

    # Filter by installation status if specified
    if installed and not_installed:
        print_error("--installed and --not-installed options are mutually exclusive.")
        raise typer.Exit(code=1)
    elif installed:
        filtered_tools = {
            name: info
            for name, info in filtered_tools.items()
            if installation_status.get(name, False)
        }
    elif not_installed:
        filtered_tools = {
            name: info
            for name, info in filtered_tools.items()
            if not installation_status.get(name, False)
        }

    # Prepare output format
    if json_output:
        # JSON output
        json_output_data = []
        for name, info in filtered_tools.items():
            tool_info = dict(info)
            tool_info["installed"] = installation_status.get(name, False)
            json_output_data.append(tool_info)
        print(json.dumps(json_output_data, indent=2))
    else:
        # Table output
        table_data = []
        for name, info in filtered_tools.items():
            is_installed = installation_status.get(name, False)
            status = (
                f"{Fore.GREEN}Installed{Style.RESET_ALL}"
                if is_installed
                else f"{Fore.RED}Not Installed{Style.RESET_ALL}"
            )

            description = info.get("description", "")
            wrapped_description = textwrap.fill(description, width=50)

            row = [name, info.get("category", "Unknown"), wrapped_description, status]

            table_data.append(row)

        headers = ["Name", "Category", "Description", "Status"]
        if table_data:
            print(tabulate.tabulate(table_data, headers=headers, tablefmt="pretty"))
        else:
            print_warning("No tools found matching the specified criteria.")

        # Print summary with filters
        summary_parts = [f"\nTotal: {len(table_data)} tools"]
        if category:
            summary_parts.append(f"Category: {category}")
        if installed:
            summary_parts.append("Status: Installed")
        if not_installed:
            summary_parts.append("Status: Not Installed")
        print(", ".join(summary_parts))


@tools_app.command("show")
def show_tool(
    name: Annotated[
        str, typer.Argument(help="The name of the tool to show details for")
    ],
) -> None:
    """
    Show detailed information about a specific tool.
    """
    manager = ToolManager()

    tool_info = manager.get_tool(name)
    if not tool_info:
        print_error(f"Tool '{name}' not found")
        raise typer.Exit(code=1)

    # Check if the tool is installed
    is_installed = manager.check_tool_availability(name)

    # Display basic information
    print(f"{Fore.CYAN}=== {tool_info.get('name', name)} ==={Style.RESET_ALL}")
    print(f"Category: {tool_info.get('category', 'Unknown')}")
    print(f"Description: {tool_info.get('description', 'No description available')}")
    status_text = (
        f"{Fore.GREEN}Installed{Style.RESET_ALL}"
        if is_installed
        else f"{Fore.RED}Not Installed{Style.RESET_ALL}"
    )
    print(f"Status: {status_text}")

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
    install_methods = tool_info.get("install")
    if install_methods and isinstance(install_methods, dict):
        print("\nInstallation Methods:")
        for method, command in install_methods.items():
            command_str = (
                str(command) if not isinstance(command, (str, bytes)) else command
            )
            print(f"  - {method}: {command_str}")

    # Display update methods
    update_methods = tool_info.get("update")
    if update_methods and isinstance(update_methods, dict):
        print("\nUpdate Methods:")
        for method, command in update_methods.items():
            command_str = (
                str(command) if not isinstance(command, (str, bytes)) else command
            )
            print(f"  - {method}: {command_str}")

    print()


@tools_app.command("install")
def install_tool(
    tools: Annotated[
        Optional[List[str]],
        typer.Argument(help="Specific tool(s) to install", show_default=False),
    ] = None,
    all_tools: Annotated[
        Optional[bool], typer.Option("--all", help="Install all available tools")
    ] = None,
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            "-c",
            help="Install all tools in a specific category (used with --all)",
        ),
    ] = None,
    method: Annotated[
        Optional[str],
        typer.Option(
            "--method", "-m", help="Specify installation method (e.g., apt, brew, pip)"
        ),
    ] = None,
) -> None:
    """
    Install one or more tools. Provide tool names or use --all.
    """
    manager = ToolManager()

    tools_to_install: List[str] = []

    # Determine which tools to install
    if all_tools:
        if tools:
            print_error("Cannot specify tool names when using --all.")
            raise typer.Exit(code=1)

        available_tools = manager.get_all_tools()

        if category:
            try:
                ToolCategory(category)
                tools_to_install = manager.get_tool_names_by_category(category)
                if not tools_to_install:
                    print_warning(f"No tools found in category: {category}")
                    return
            except ValueError:
                print_error(
                    f"Invalid category: {category}. Available categories: {[c.value for c in ToolCategory]}"
                )
                raise typer.Exit(code=1)
        else:
            tools_to_install = list(available_tools.keys())

        if not tools_to_install:
            print_warning("No tools selected for installation.")
            return

        print_info(f"Attempting to install {len(tools_to_install)} tools...")
    elif tools:
        tools_to_install = tools
        print_info(
            f"Attempting to install {len(tools_to_install)} specified tool(s)..."
        )
    else:
        # No tools specified and --all not used, show help (Typer might handle this)
        print_error("Please specify tool names to install or use the --all flag.")
        # Consider showing help here, though Typer's no_args_is_help might cover the main app
        raise typer.Exit(code=1)

    # Perform installation
    success_count = 0
    failure_count = 0
    for tool_name in tools_to_install:
        print(f"Installing {tool_name}...")
        try:
            if manager.install_tool(tool_name):
                print_success(f"Successfully installed {tool_name}")
                success_count += 1
            else:
                # ToolManager should ideally log specific errors
                print_error(
                    f"Installation failed for {tool_name}. Check logs for details."
                )
                failure_count += 1
        except Exception as e:
            # Catch exceptions during installation process
            print_error(f"Error during installation of {tool_name}: {e}")
            failure_count += 1

    # Print summary
    total_attempted = len(tools_to_install)
    print(f"\nInstallation Summary:")
    print_success(f"Successfully installed: {success_count}")
    if failure_count > 0:
        print_error(f"Failed to install: {failure_count}")
    print(f"Total attempted: {total_attempted}")


@tools_app.command("update")
def update_tool(
    tools: Annotated[
        Optional[List[str]],
        typer.Argument(help="Specific tool(s) to update", show_default=False),
    ] = None,
    all_tools: Annotated[
        Optional[bool], typer.Option("--all", help="Update all installed tools")
    ] = None,
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            "-c",
            help="Update all installed tools in a specific category (used with --all)",
        ),
    ] = None,
    method: Annotated[
        Optional[str],
        typer.Option("--method", "-m", help="Specify update method (if applicable)"),
    ] = None,
) -> None:
    """
    Update one or more installed tools. Provide tool names or use --all.
    """
    manager = ToolManager()

    tools_to_update: List[str] = []
    installed_tools = manager.get_installation_status()  # Get {name: installed_bool}
    installed_tool_names = {
        name for name, is_installed in installed_tools.items() if is_installed
    }

    # Determine which tools to update
    if all_tools:
        if tools:
            print_error("Cannot specify tool names when using --all.")
            raise typer.Exit(code=1)

        target_tools = installed_tool_names  # Start with all installed tools

        if category:
            try:
                ToolCategory(category)  # Validate category
                tools_in_category = set(manager.get_tool_names_by_category(category))
                # Filter target_tools to only include those in the specified category
                target_tools = target_tools.intersection(tools_in_category)

                if not target_tools:
                    print_warning(f"No installed tools found in category: {category}")
                    return

            except ValueError:
                print_error(
                    f"Invalid category: {category}. Available categories: {[c.value for c in ToolCategory]}"
                )
                raise typer.Exit(code=1)

        tools_to_update = list(target_tools)

        if not tools_to_update:
            print_warning("No installed tools selected for update.")
            return

        print_info(f"Attempting to update {len(tools_to_update)} installed tools...")

    elif tools:
        # Validate specified tools are installed
        not_installed = [t for t in tools if t not in installed_tool_names]
        if not_installed:
            print_warning(
                f"The following specified tools are not installed and will be skipped: {', '.join(not_installed)}"
            )

        tools_to_update = [t for t in tools if t in installed_tool_names]

        if not tools_to_update:
            print_error("None of the specified tools are installed or valid.")
            raise typer.Exit(code=1)

        print_info(
            f"Attempting to update {len(tools_to_update)} specified installed tool(s)..."
        )
    else:
        print_error("Please specify tool names to update or use the --all flag.")
        raise typer.Exit(code=1)

    # Perform update
    success_count = 0
    failure_count = 0
    skipped_count = 0

    for tool_name in tools_to_update:
        print(f"Updating {tool_name}...")
        try:
            # Pass the specific method if provided by the user
            result = manager.update_tool(tool_name, method=method)
            if result is True:
                print_success(f"Successfully updated {tool_name}")
                success_count += 1
            elif result is False:
                print_warning(
                    f"Update failed or was not applicable for {tool_name}. Check logs."
                )
                failure_count += 1
            else:  # result is None or some other non-boolean indicating skipped/not applicable
                print_info(
                    f"Update skipped for {tool_name} (No update method or not needed)."
                )
                skipped_count += 1
        except Exception as e:
            print_error(f"Error during update of {tool_name}: {e}")
            failure_count += 1

    # Print summary
    total_attempted = len(tools_to_update)
    print("\nUpdate Summary:")
    print_success(f"Successfully updated: {success_count}")
    if failure_count > 0:
        print_error(f"Failed to update: {failure_count}")
    if skipped_count > 0:
        print_info(f"Skipped/Not applicable: {skipped_count}")
    print(f"Total attempted: {total_attempted}")


@tools_app.command("add")
def add_tool(
    config_file: Annotated[
        Path,
        typer.Argument(
            ...,
            help="Path to the YAML configuration file for the tool(s)",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """
    Add a new custom tool from a YAML configuration file.
    """
    manager = ToolManager()

    try:
        with open(config_file, "r") as file:
            tool_data = yaml.safe_load(file)

        if not isinstance(tool_data, dict):
            print_error(
                f"Invalid format in {config_file}. Expected a dictionary (YAML mapping)."
            )
            raise typer.Exit(code=1)

        added_count = 0
        failed_count = 0
        for tool_name, tool_config in tool_data.items():
            print_info(f"Attempting to add tool: {tool_name}")
            if isinstance(tool_config, dict):
                if manager.add_tool(tool_name, tool_config, custom=True):
                    print_success(f"Successfully added custom tool: {tool_name}")
                    added_count += 1
                else:
                    # ToolManager should log specific errors
                    print_error(
                        f"Failed to add tool: {tool_name}. It might already exist or have invalid config."
                    )
                    failed_count += 1
            else:
                print_error(
                    f"Invalid configuration format for tool '{tool_name}' in {config_file}. Expected a dictionary."
                )
                failed_count += 1

        print("\nAdd Tool Summary:")
        print_success(f"Tools added: {added_count}")
        if failed_count > 0:
            print_error(f"Tools failed to add: {failed_count}")
    except FileNotFoundError:
        print_error(f"Configuration file not found: {config_file}")
        raise typer.Exit(code=1)
    except yaml.YAMLError as e:
        print_error(f"Error parsing YAML file {config_file}: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


@tools_app.command("remove")
def remove_tool(
    names: Annotated[
        List[str], typer.Argument(..., help="Name(s) of the custom tool(s) to remove")
    ],
) -> None:
    """
    Remove one or more custom tools.
    """
    manager = ToolManager()
    removed_count = 0
    failed_count = 0

    for name in names:
        print_info(f"Attempting to remove tool: {name}")
        try:
            if manager.remove_tool(name):
                print_success(f"Successfully removed custom tool: {name}")
                removed_count += 1
            else:
                # ToolManager should log specific errors or indicate why
                print_error(
                    f"Failed to remove tool: {name}. It might not be a custom tool or not found."
                )
                failed_count += 1
        except Exception as e:
            print_error(f"Error removing tool {name}: {e}")
            failed_count += 1

    print("\nRemove Tool Summary:")
    print_success(f"Tools removed: {removed_count}")
    if failed_count > 0:
        print_error(f"Tools failed to remove: {failed_count}")


@tools_app.command("categories")
def list_categories() -> None:
    """
    List all available tool categories.
    """
    manager = ToolManager()
    categories = manager.get_tool_categories()

    if categories:
        print_info("Available Tool Categories:")
        for category in sorted(list(categories)):
            print(f"  - {category}")
    else:
        print_warning("No tool categories found.")


@tools_app.command("check-updates")
def check_updates(
    tools: Annotated[
        Optional[List[str]],
        typer.Argument(
            help="Specific tool(s) to check for updates", show_default=False
        ),
    ] = None,
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            "-c",
            help="Check updates only for installed tools in a specific category",
        ),
    ] = None,
) -> None:
    """
    Check for available updates for installed tools.
    """
    manager = ToolManager()
    installed_tools = manager.get_installation_status()  # Get {name: installed_bool}
    installed_tool_names = {
        name for name, is_installed in installed_tools.items() if is_installed
    }

    tools_to_check: List[str] = []

    # Determine which tools to check
    if tools:
        # Validate specified tools are installed
        not_installed = [t for t in tools if t not in installed_tool_names]
        if not_installed:
            print_warning(
                f"The following specified tools are not installed and cannot be checked: {', '.join(not_installed)}"
            )

        tools_to_check = [t for t in tools if t in installed_tool_names]

        if not tools_to_check:
            print_error("None of the specified tools are installed or valid.")
            raise typer.Exit(code=1)

        print_info(
            f"Checking updates for {len(tools_to_check)} specified installed tool(s)..."
        )

    else:  # Check all installed tools by default, potentially filtered by category
        target_tools = installed_tool_names  # Start with all installed tools

        if category:
            try:
                ToolCategory(category)  # Validate category
                tools_in_category = set(manager.get_tool_names_by_category(category))
                # Filter target_tools to only include those in the specified category
                target_tools = target_tools.intersection(tools_in_category)

                if not target_tools:
                    print_warning(f"No installed tools found in category: {category}")
                    return

            except ValueError:
                print_error(
                    f"Invalid category: {category}. Available categories: {[c.value for c in ToolCategory]}"
                )
                raise typer.Exit(code=1)

        tools_to_check = list(target_tools)

        if not tools_to_check:
            print_warning("No installed tools found to check for updates.")
            return

        print_info(f"Checking updates for {len(tools_to_check)} installed tools...")

    # Perform check
    updates_available: Dict[str, Any] = {}
    check_errors: Dict[str, str] = {}

    for tool_name in tools_to_check:
        print(f"Checking {tool_name}...")
        try:
            update_info = manager.check_for_updates(tool_name)
            if update_info:
                updates_available[tool_name] = update_info
                print_success(f"Update available for {tool_name}: {update_info}")
            else:
                print_info(f"No update found or check not applicable for {tool_name}.")
        except Exception as e:
            print_error(f"Error checking updates for {tool_name}: {e}")
            check_errors[tool_name] = str(e)

    # Print Summary
    print("\nUpdate Check Summary:")
    if updates_available:
        print_success(f"Updates available for {len(updates_available)} tool(s):")
        for name, info in updates_available.items():
            print(f"  - {name}: {info}")
    else:
        print_info("No updates found for the checked tools.")

    if check_errors:
        print_error(f"\nErrors occurred while checking {len(check_errors)} tool(s):")
        for name, err in check_errors.items():
            print(f"  - {name}: {err}")

    if not updates_available and not check_errors:
        print_info("All checked tools are up-to-date or do not support update checks.")


if __name__ == "__main__":
    tools_app()
