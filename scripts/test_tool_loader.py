#!/usr/bin/env python3
"""
Test script to verify that tools are being loaded correctly from both
the standard tools directory and the custom tools directory.
"""

import logging
import os
import platform
import sys

# Add the src directory to the Python path
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from tools.manager import ToolCategory, ToolManager

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sniper.test_tools")


def main():
    """
    Main function to test tool loading.
    """
    # Get the standard tools directory
    tools_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "tools"
    )
    custom_tools_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "custom_tools"
    )

    logger.info(f"Standard tools directory: {tools_dir}")
    logger.info(f"Custom tools directory: {custom_tools_dir}")

    # Create the tool manager
    manager = ToolManager(tools_dir=tools_dir, custom_tools_dir=custom_tools_dir)

    # Log the total number of tools loaded
    total_tools = len(manager.get_all_tools())
    logger.info(f"Total tools loaded: {total_tools}")

    # Check if the custom tools were loaded
    custom_tools = ["dirb", "jwt_tool", "feroxbuster", "semgrep"]
    for tool_name in custom_tools:
        tool = manager.get_tool(tool_name)
        if tool:
            logger.info(
                f"Custom tool '{tool_name}' was loaded successfully: {tool['description']}"
            )
        else:
            logger.error(f"Custom tool '{tool_name}' was not loaded!")

    # Check tool availability
    os_type = platform.system().lower()
    logger.info(f"Checking tool availability on {os_type} system")

    # Get available tools
    available_tools = manager.get_available_tools()
    logger.info(f"Available tools: {len(available_tools)}/{total_tools}")

    # List installed tools
    if available_tools:
        installed_tool_names = list(available_tools.keys())
        logger.info(
            f"Installed tools: {', '.join(installed_tool_names[:5])}"
            + ("..." if len(installed_tool_names) > 5 else "")
        )

    # List tools by category
    logger.info("Tools by category:")
    for category in ToolCategory:
        category_tools = manager.get_tools_by_category(category)
        logger.info(f"  Category {category.value}: {len(category_tools)} tools")

        # List the tool names in this category
        tool_names = list(category_tools.keys())
        if tool_names:
            logger.info(
                f"  Tools in {category.value}: {', '.join(tool_names[:5])}"
                + ("..." if len(tool_names) > 5 else "")
            )
        else:
            logger.info(f"  No tools found in {category.value} category")

    # Show installation methods for a sample of tools
    logger.info("Installation methods for sample tools:")
    sample_tools = ["nmap", "dirb", "jwt_tool", "feroxbuster"]
    for tool_name in sample_tools:
        tool = manager.get_tool(tool_name)
        if not tool:
            logger.warning(f"Tool {tool_name} not found")
            continue

        install_info = tool.get("install", {})
        available_methods = list(install_info.keys())
        logger.info(f"  {tool_name}: {', '.join(available_methods)}")

        # Show appropriate installation command for current OS
        if os_type == "darwin" and "brew" in install_info:
            logger.info(f"  Recommended installation for macOS: {install_info['brew']}")
        elif os_type == "linux" and "apt" in install_info:
            logger.info(f"  Recommended installation for Linux: {install_info['apt']}")
        elif "pip" in install_info:
            logger.info(
                f"  Recommended cross-platform installation: {install_info['pip']}"
            )


if __name__ == "__main__":
    main()
