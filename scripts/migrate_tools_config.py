#!/usr/bin/env python3
"""
Migration script to convert the tools.yaml configuration file into individual tool YAML files.

This script reads the existing tools.yaml file and creates individual YAML files
for each tool in the config/tools directory. This makes it easier to manage tools
by allowing each tool to be configured in its own file.

Usage:
    python migrate_tools_config.py
"""

import logging
import os
import sys
from pathlib import Path

import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sniper.migrate_tools")

# Configuration
SOURCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "tools.yaml"
)
TARGET_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "tools")


def migrate_tools_config():
    """
    Migrate tools from a single YAML file to individual files.

    Returns:
        int: The number of tools successfully migrated
    """
    if not os.path.exists(SOURCE_FILE):
        logger.error(f"Source file {SOURCE_FILE} does not exist!")
        return 0

    # Create target directory if it doesn't exist
    os.makedirs(TARGET_DIR, exist_ok=True)
    logger.info(f"Ensuring target directory exists: {TARGET_DIR}")

    # Read the source file
    try:
        logger.info(f"Reading source file: {SOURCE_FILE}")
        with open(SOURCE_FILE, "r") as f:
            tools = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error reading source file: {e}")
        return 0

    if not tools:
        logger.warning("No tools found in source file!")
        return 0

    logger.info(f"Found {len(tools)} tools to migrate")
    success_count = 0

    # Process each tool
    for tool_name, tool_config in tools.items():
        # Create sanitized filename
        safe_name = tool_name.lower().replace(" ", "_").replace("-", "_")
        target_path = os.path.join(TARGET_DIR, f"{safe_name}.yaml")

        try:
            # Write tool to its own file
            with open(target_path, "w") as f:
                yaml.dump({tool_name: tool_config}, f, default_flow_style=False)

            logger.info(f"Successfully migrated tool '{tool_name}' to {target_path}")
            success_count += 1
        except Exception as e:
            logger.error(f"Error migrating tool '{tool_name}': {e}")

    logger.info(
        f"Migration complete: {success_count}/{len(tools)} tools successfully migrated"
    )
    return success_count


if __name__ == "__main__":
    logger.info("Starting tools configuration migration...")
    count = migrate_tools_config()

    if count > 0:
        logger.info(
            f"Migration successful! {count} tools migrated to individual files."
        )
        sys.exit(0)
    else:
        logger.error("Migration failed! No tools were migrated.")
        sys.exit(1)
