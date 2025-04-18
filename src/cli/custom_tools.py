#!/usr/bin/env python3
"""
Custom Tools CLI commands for Sniper Security Tool.

This module provides CLI commands for managing custom tools in the Sniper platform.
"""

import os
import sys
import click
import yaml
import logging
from pathlib import Path

# Add parent directory to path to allow imports from src/
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(parent_dir)

from src.tools.manager import ToolManager, ToolCategory

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sniper.cli.custom_tools")

@click.group()
def custom_tools():
    """Manage custom tools for Sniper Security Tool."""
    pass

@custom_tools.command('list')
@click.option('--category', '-c', help='Filter by tool category')
@click.option('--available', '-a', is_flag=True, help='Show only available (installed) tools')
def list_tools(category, available):
    """List custom tools."""
    manager = ToolManager()
    
    if available:
        tools_dict = manager.get_available_tools(category)
    else:
        if category:
            try:
                category_enum = ToolCategory(category)
                tools_dict = manager.get_tools_by_category(category_enum)
            except ValueError:
                click.echo(f"Invalid category: {category}")
                click.echo(f"Valid categories: {[c.value for c in ToolCategory]}")
                return
        else:
            tools_dict = manager.get_all_tools()
    
    # Count custom tools vs standard tools
    custom_tools_dir = os.path.join(parent_dir, "config", "custom_tools")
    custom_tool_files = set([os.path.splitext(f)[0] for f in os.listdir(custom_tools_dir) if f.endswith('.yaml')])
    custom_tools_count = 0
    
    click.echo(f"\nTotal tools: {len(tools_dict)}")
    click.echo("-" * 60)
    click.echo(f"{'Name':<20} {'Category':<20} {'Custom':<10} {'Available':<10}")
    click.echo("-" * 60)
    
    for name, info in tools_dict.items():
        is_custom = name in custom_tool_files
        if is_custom:
            custom_tools_count += 1
        
        is_available = manager.check_tool_availability(name)
        category = info.get("category", "unknown")
        
        click.echo(f"{name:<20} {category:<20} {'✓' if is_custom else ' ':<10} {'✓' if is_available else ' ':<10}")
    
    click.echo("-" * 60)
    click.echo(f"Custom tools: {custom_tools_count}/{len(tools_dict)}")

@custom_tools.command('add')
@click.argument('name')
@click.option('--category', '-c', default="miscellaneous", help='Tool category')
@click.option('--description', '-d', help='Tool description')
@click.option('--binary', '-b', help='Binary name')
@click.option('--command', help='Check command to verify installation')
@click.option('--apt', help='APT installation command')
@click.option('--brew', help='Homebrew installation command')
@click.option('--pip', help='Pip installation command')
@click.option('--website', help='Tool website URL')
@click.option('--docs', help='Documentation URL')
def add_tool(name, category, description, binary, command, apt, brew, pip, website, docs):
    """Add a custom tool."""
    manager = ToolManager()
    
    # Check if tool already exists
    if manager.get_tool(name):
        if not click.confirm(f"Tool '{name}' already exists. Update it?"):
            click.echo("Aborted.")
            return
    
    # Create tool configuration
    tool_config = {
        "name": name,
        "category": category,
        "description": description or f"Custom tool: {name}"
    }
    
    if binary:
        tool_config["binary"] = binary
        
    if command:
        tool_config["check_command"] = command
        
    # Add installation methods
    install = {}
    if apt:
        install["apt"] = apt
    if brew:
        install["brew"] = brew
    if pip:
        install["pip"] = pip
        
    if install:
        tool_config["install"] = install
        
    # Add optional fields
    if website:
        tool_config["website"] = website
    if docs:
        tool_config["documentation"] = docs
        
    # Default fields
    tool_config["execution_time"] = "medium"
    tool_config["target_types"] = ["generic"]
    tool_config["recommendation_score"] = 50
    
    # Add the tool
    if manager.add_tool(name, tool_config, custom=True):
        click.echo(f"Successfully added custom tool: {name}")
    else:
        click.echo(f"Failed to add custom tool: {name}")

@custom_tools.command('remove')
@click.argument('name')
def remove_tool(name):
    """Remove a custom tool."""
    manager = ToolManager()
    
    # Check if tool exists
    if not manager.get_tool(name):
        click.echo(f"Tool '{name}' does not exist.")
        return
        
    # Check if it's a custom tool
    custom_tools_dir = os.path.join(parent_dir, "config", "custom_tools")
    custom_tool_file = os.path.join(custom_tools_dir, f"{name}.yaml")
    if not os.path.exists(custom_tool_file):
        click.echo(f"'{name}' is not a custom tool and cannot be removed.")
        return
        
    if click.confirm(f"Are you sure you want to remove custom tool '{name}'?"):
        if manager.remove_tool(name):
            click.echo(f"Successfully removed custom tool: {name}")
        else:
            click.echo(f"Failed to remove custom tool: {name}")

@custom_tools.command('import')
@click.argument('file_path', type=click.Path(exists=True))
def import_tool(file_path):
    """Import a custom tool from a YAML file."""
    manager = ToolManager()
    
    try:
        with open(file_path, 'r') as f:
            tool_data = yaml.safe_load(f)
            
        if not tool_data:
            click.echo("Empty YAML file.")
            return
            
        success_count = 0
        for tool_name, tool_config in tool_data.items():
            if manager.add_tool(tool_name, tool_config, custom=True):
                success_count += 1
                click.echo(f"Successfully imported tool: {tool_name}")
            else:
                click.echo(f"Failed to import tool: {tool_name}")
                
        click.echo(f"Import complete: {success_count}/{len(tool_data)} tools imported.")
            
    except Exception as e:
        click.echo(f"Error importing tool: {str(e)}")

if __name__ == '__main__':
    custom_tools() 