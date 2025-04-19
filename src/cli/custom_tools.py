#!/usr/bin/env python3
"""
Custom Tools CLI commands for Sniper Security Tool.

This module provides CLI commands for managing custom tools in the Sniper platform using Typer.
"""

import json
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import List, Optional

import tabulate
import typer
import yaml
from colorama import Fore, Style, init
from typing_extensions import Annotated

# Add parent directory to path to allow imports from src/
parent_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(parent_dir))

from src.cli.tools import print_error, print_info, print_success, print_warning
from src.tools.manager import ToolCategory, ToolManager

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sniper.cli.custom_tools")

# Define the Typer app
custom_tools_app = typer.Typer(
    name="custom-tools",
    help="Manage custom tools for Sniper Security Tool.",
    no_args_is_help=True,
)


@custom_tools_app.command("list")
def list_custom_tools(
    category: Annotated[
        Optional[str], typer.Option("--category", "-c", help="Filter by tool category")
    ] = None,
    available: Annotated[
        Optional[bool],
        typer.Option("--available", "-a", help="Show only available (installed) tools"),
    ] = None,
    json_output: Annotated[
        Optional[bool], typer.Option("--json", help="Output in JSON format")
    ] = None,
) -> None:
    """List all tools, highlighting custom ones."""
    manager = ToolManager()
    all_tools = {}

    if available:
        print_warning("Filtering by available status might require ToolManager update.")
        all_tools = manager.get_available_tools(category=category)
    else:
        all_tools = manager.get_all_tools()
        if category:
            try:
                category_enum = ToolCategory(category)
                all_tools = manager.get_tools_by_category(category_enum)
            except ValueError:
                print_error(f"Invalid category: {category}")
                print_info(f"Valid categories: {[c.value for c in ToolCategory]}")
                raise typer.Exit(code=1)

    custom_tools_dir = parent_dir / "config" / "custom_tools"
    custom_tool_names = set()
    if custom_tools_dir.is_dir():
        custom_tool_names = {p.stem for p in custom_tools_dir.glob("*.yaml")}

    installation_status = manager.get_installation_status()

    output_data = []
    for name, info in all_tools.items():
        is_custom = name in custom_tool_names
        is_available = installation_status.get(name, False)
        output_data.append(
            {
                "name": name,
                "category": info.get("category", "unknown"),
                "description": info.get("description", ""),
                "is_custom": is_custom,
                "is_available": is_available,
            }
        )

    custom_tools_count = sum(1 for tool in output_data if tool["is_custom"])

    if json_output:
        print(json.dumps(output_data, indent=2))
    else:
        table_data = []
        for tool in output_data:
            status = (
                f"{Fore.GREEN}Available{Style.RESET_ALL}"
                if tool["is_available"]
                else f"{Fore.RED}Unavailable{Style.RESET_ALL}"
            )
            custom_marker = (
                f"{Fore.CYAN}✓ Custom{Style.RESET_ALL}" if tool["is_custom"] else ""
            )
            desc = tool["description"]
            short_desc = textwrap.shorten(desc, width=40, placeholder="...")
            table_data.append(
                [tool["name"], tool["category"], short_desc, custom_marker, status]
            )

        headers = ["Name", "Category", "Description", "Type", "Status"]
        if table_data:
            print(tabulate.tabulate(table_data, headers=headers, tablefmt="pretty"))
        else:
            print_warning("No tools found matching the specified criteria.")

        print(f"\nTotal tools listed: {len(output_data)}")
        print(f"Custom tools: {custom_tools_count}")


@custom_tools_app.command("add")
def add_custom_tool(
    name: Annotated[str, typer.Argument(help="Unique name for the custom tool.")],
    category: Annotated[
        str, typer.Option("--category", "-c", help="Tool category")
    ] = ToolCategory.MISCELLANEOUS.value,
    description: Annotated[
        Optional[str], typer.Option("--description", "-d", help="Tool description")
    ] = None,
    binary: Annotated[
        Optional[str], typer.Option("--binary", "-b", help="Binary executable name")
    ] = None,
    check_command: Annotated[
        Optional[str],
        typer.Option("--command", help="Command to check if the tool is installed"),
    ] = None,
    install_apt: Annotated[
        Optional[str], typer.Option(help="APT installation command or package name")
    ] = None,
    install_brew: Annotated[
        Optional[str], typer.Option(help="Homebrew installation command or formula")
    ] = None,
    install_pip: Annotated[
        Optional[str], typer.Option(help="Pip installation command or package name")
    ] = None,
    install_script: Annotated[
        Optional[str], typer.Option(help="Path to a custom installation script")
    ] = None,
    website: Annotated[Optional[str], typer.Option(help="Tool website URL")] = None,
    docs: Annotated[Optional[str], typer.Option(help="Documentation URL")] = None,
    update: Annotated[
        bool, typer.Option("--update", help="Update the tool if it already exists.")
    ] = False,
) -> None:
    """Add or update a custom tool definition."""
    manager = ToolManager()

    try:
        ToolCategory(category)
    except ValueError:
        print_error(
            f"Invalid category: {category}. Valid categories: {[c.value for c in ToolCategory]}"
        )
        raise typer.Exit(code=1)

    if manager.get_tool(name) and not update:
        print_error(f"Tool '{name}' already exists. Use --update to overwrite.")
        raise typer.Exit(code=1)
    elif manager.get_tool(name) and update:
        print_info(f"Updating existing custom tool: {name}")
    else:
        print_info(f"Adding new custom tool: {name}")

    tool_config = {
        "name": name,
        "category": category,
        "description": description or f"Custom tool: {name}",
        **({"binary": binary} if binary else {}),
        **({"check_command": check_command} if check_command else {}),
        **({"website": website} if website else {}),
        **({"documentation": docs} if docs else {}),
        "execution_time": "medium",
        "target_types": ["generic"],
        "recommendation_score": 50,
    }

    install_methods = {}
    if install_apt:
        install_methods[ToolInstallMethod.APT.value] = install_apt
    if install_brew:
        install_methods[ToolInstallMethod.BREW.value] = install_brew
    if install_pip:
        install_methods[ToolInstallMethod.PIP.value] = install_pip
    if install_script:
        install_methods["script"] = install_script
    if install_methods:
        tool_config["install"] = install_methods

    if manager.add_tool(name, tool_config, custom=True):
        action = "updated" if update else "added"
        print_success(f"Successfully {action} custom tool: {name}")
        print_info(f"Configuration saved in {manager.custom_tools_dir}")
    else:
        action = "update" if update else "add"
        print_error(f"Failed to {action} custom tool: {name}")
        raise typer.Exit(code=1)


@custom_tools_app.command("remove")
def remove_custom_tool(
    name: Annotated[str, typer.Argument(help="Name of the custom tool to remove.")],
) -> None:
    """Remove a custom tool definition."""
    manager = ToolManager()

    if not manager.get_tool(name):
        print_error(f"Tool '{name}' does not exist.")
        raise typer.Exit(code=1)

    custom_tool_file = Path(manager.custom_tools_dir) / f"{name}.yaml"
    if not custom_tool_file.is_file():
        print_error(
            f"'{name}' is not a custom tool defined in {manager.custom_tools_dir}."
        )
        print_info("Only tools defined in the custom tools directory can be removed.")
        raise typer.Exit(code=1)

    if typer.confirm(
        f"Are you sure you want to remove the custom tool definition for '{name}'?"
    ):
        if manager.remove_tool(name):
            print_success(f"Successfully removed custom tool: {name}")
        else:
            print_error(f"Failed to remove custom tool file for: {name}")
            raise typer.Exit(code=1)
    else:
        print_info("Removal aborted.")


@custom_tools_app.command("import")
def import_custom_tool(
    file_path: Annotated[
        Path,
        typer.Argument(
            ...,
            help="Path to the YAML file containing custom tool definitions.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Import one or more custom tools from a YAML file."""
    manager = ToolManager()
    print_info(f"Importing tools from: {file_path}")

    try:
        with open(file_path, "r") as f:
            imported_data = yaml.safe_load(f)

        if not isinstance(imported_data, dict):
            print_error(
                f"Invalid format in {file_path}. Expected a YAML dictionary (mapping) of tool names to configurations."
            )
            raise typer.Exit(code=1)

        success_count = 0
        fail_count = 0
        for tool_name, tool_config in imported_data.items():
            if not isinstance(tool_config, dict):
                print_warning(
                    f"Skipping invalid entry '{tool_name}': configuration is not a dictionary."
                )
                fail_count += 1
                continue

            if manager.add_tool(tool_name, tool_config, custom=True):
                success_count += 1
                print_success(f"Imported and saved tool: {tool_name}")
            else:
                print_error(
                    f"Failed to import tool: {tool_name}. Check logs or if it already exists."
                )
                fail_count += 1

        print(f"\nImport Summary:")
        print_success(f"Successfully imported: {success_count}")
        if fail_count > 0:
            print_error(f"Failed/Skipped entries: {fail_count}")

    except yaml.YAMLError as e:
        print_error(f"Error parsing YAML file {file_path}: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        print_error(f"An unexpected error occurred during import: {e}")
        raise typer.Exit(code=1)


# Remove the __main__ block if this is meant to be imported
# if __name__ == '__main__':
#     custom_tools_app()
