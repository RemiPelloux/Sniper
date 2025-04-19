#!/usr/bin/env python3
"""
Convert tools.yaml to individual tool config files.

This script reads the existing tools.yaml configuration file and converts it
to individual YAML files per tool in the config/tools directory.
"""

import os
import sys
from pathlib import Path

import yaml


def convert_tools_config(source_file, output_dir):
    """
    Convert a single tools YAML file to individual tool files.

    Args:
        source_file (str): Path to the source tools.yaml file
        output_dir (str): Directory to output individual tool files
    """
    print(f"Converting {source_file} to individual files in {output_dir}")

    # Ensure output directory exists
    Path(output_dir).mkdir(exist_ok=True, parents=True)

    # Read the source file
    try:
        with open(source_file, "r") as f:
            tools_data = yaml.safe_load(f)

        if not tools_data:
            print("Error: Source file is empty or not a valid YAML file")
            return

        # Process each tool
        for tool_name, tool_config in tools_data.items():
            # Create a sanitized filename
            safe_name = tool_name.lower().replace(" ", "_").replace("-", "_")
            file_path = os.path.join(output_dir, f"{safe_name}.yaml")

            # Create the tool file
            with open(file_path, "w") as f:
                yaml.dump({tool_name: tool_config}, f, default_flow_style=False)

            print(f"Created {file_path}")

        print(f"Converted {len(tools_data)} tools successfully")

    except Exception as e:
        print(f"Error converting tools: {str(e)}")
        sys.exit(1)


def main():
    # Get project root directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    # Default paths
    default_source = os.path.join(project_root, "config", "tools.yaml")
    default_output = os.path.join(project_root, "config", "tools")

    # Allow command-line override
    source_file = sys.argv[1] if len(sys.argv) > 1 else default_source
    output_dir = sys.argv[2] if len(sys.argv) > 2 else default_output

    # Check if source file exists
    if not os.path.exists(source_file):
        print(f"Error: Source file {source_file} does not exist")
        sys.exit(1)

    # Convert the tools
    convert_tools_config(source_file, output_dir)

    # Also convert custom tools if they exist
    custom_source = os.path.join(project_root, "config", "custom_tools.yaml")
    custom_output = os.path.join(project_root, "config", "custom_tools")

    if os.path.exists(custom_source):
        convert_tools_config(custom_source, custom_output)


if __name__ == "__main__":
    main()
