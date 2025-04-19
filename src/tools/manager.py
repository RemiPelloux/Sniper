"""
Tool Manager Module for Sniper Security Tool.

This module provides functionality to manage security tools used by the Sniper platform,
including installation, verification, listing, and dynamic addition/removal of tools.
"""

import importlib.util
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pkg_resources
import requests
import yaml

logger = logging.getLogger("sniper.tools.manager")


class ToolCategory(Enum):
    """
    Enum representing different categories of security tools.
    """

    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    MISCELLANEOUS = "miscellaneous"


class ToolInstallMethod(Enum):
    """
    Enum representing different methods for installing tools.
    """

    APT = "apt"
    BREW = "brew"
    PIP = "pip"
    NPM = "npm"
    GIT = "git"
    MANUAL = "manual"


class ToolManager:
    """
    Manages security tools for the Sniper Security Platform.

    This class is responsible for loading, adding, removing, and retrieving tools
    used by the platform. It also provides functionality to check if tools are installed
    and to install them if needed.

    Attributes:
        tools (Dict): Dictionary of tools loaded from configuration files
        _os_type (str): The operating system type (Linux, Darwin, Windows)
        _package_managers (List[str]): List of available package managers on the system
    """

    def __init__(
        self, tools_dir: Optional[str] = None, custom_tools_dir: Optional[str] = None
    ) -> None:
        """
        Initialize the ToolManager.

        Args:
            tools_dir (Optional[str]): Path to the directory containing tool configuration files
            custom_tools_dir (Optional[str]): Path to the directory containing custom tool configuration files
        """
        self.tools = {}

        # Detect OS type
        self._os_type = platform.system()

        # Detect package managers
        self._package_managers = []
        self._detect_package_managers()

        # Set default paths if none provided
        if not tools_dir:
            tools_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "tools",
            )
        if not custom_tools_dir:
            custom_tools_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "custom_tools",
            )

        # Ensure directories exist
        Path(tools_dir).mkdir(exist_ok=True, parents=True)
        Path(custom_tools_dir).mkdir(exist_ok=True, parents=True)

        # Store the directories
        self.tools_dir = tools_dir
        self.custom_tools_dir = custom_tools_dir

        # Load tools
        self._load_tools_from_directory(tools_dir)
        self._load_tools_from_directory(custom_tools_dir)

    def _detect_package_managers(self) -> None:
        """
        Detect available package managers based on the operating system.
        """
        if self._os_type == "Linux":
            # Check for apt (Debian/Ubuntu)
            if shutil.which("apt"):
                self._package_managers.append("apt")

        elif self._os_type == "Darwin":  # macOS
            # Check for Homebrew
            if shutil.which("brew"):
                self._package_managers.append("brew")

        # Python's pip should be available on all platforms
        if shutil.which("pip") or shutil.which("pip3"):
            self._package_managers.append("pip")

        # Check for npm
        if shutil.which("npm"):
            self._package_managers.append("npm")

        logger.info(f"Detected package managers: {', '.join(self._package_managers)}")

    def _load_tools_from_directory(self, directory_path: str) -> None:
        """
        Load tools from all YAML files in the specified directory.

        Args:
            directory_path (str): Path to the directory containing tool configuration files
        """
        try:
            directory = Path(directory_path)
            if not directory.exists():
                logger.warning(f"Tool directory does not exist: {directory_path}")
                return

            # Load each YAML file in the directory
            for file_path in directory.glob("*.yaml"):
                try:
                    with open(file_path, "r") as file:
                        tool_data = yaml.safe_load(file)

                    if not tool_data:
                        logger.warning(f"Empty tool configuration file: {file_path}")
                        continue

                    # Process each tool in the file
                    for tool_name, tool_config in tool_data.items():
                        self.tools[tool_name] = tool_config
                        logger.debug(f"Loaded tool: {tool_name}")

                except Exception as e:
                    logger.error(f"Error loading tool from {file_path}: {str(e)}")

            logger.info(f"Loaded {len(self.tools)} tools from {directory_path}")

        except Exception as e:
            logger.error(
                f"Error loading tools from directory {directory_path}: {str(e)}"
            )

    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a tool by name.

        Args:
            name (str): The name of the tool to retrieve

        Returns:
            Optional[Dict[str, Any]]: The tool configuration or None if not found
        """
        return self.tools.get(name)

    def get_tools_by_category(
        self, category: ToolCategory
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get all tools in a specific category.

        Args:
            category (ToolCategory): The category to filter by

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of tools in the specified category
        """
        category_value = (
            category.value if isinstance(category, ToolCategory) else category
        )
        return {
            name: config
            for name, config in self.tools.items()
            if "category" in config and config["category"] == category_value
        }

    def get_tool_categories(self) -> Set[str]:
        """
        Get all unique tool categories in the loaded tools.

        Returns:
            Set[str]: Set of unique tool categories
        """
        return {
            config.get("category", "miscellaneous") for config in self.tools.values()
        }

    def add_tool(self, name: str, config: Dict[str, Any], custom: bool = True) -> bool:
        """
        Add a new tool to the manager.

        Args:
            name (str): The name of the tool
            config (Dict[str, Any]): The tool configuration
            custom (bool): Whether this is a custom tool (default: True)

        Returns:
            bool: True if the tool was added successfully, False otherwise
        """
        if name in self.tools:
            logger.warning(f"Tool '{name}' already exists. Updating configuration.")

        self.tools[name] = config

        # Save the tool to a file if it's a custom tool
        if custom:
            return self._save_custom_tool(name, config)
        return True

    def _save_custom_tool(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Save a custom tool configuration to a file.

        Args:
            name (str): The name of the tool
            config (Dict[str, Any]): The tool configuration

        Returns:
            bool: True if the tool was saved successfully, False otherwise
        """
        try:
            # Create a sanitized filename
            safe_name = name.lower().replace(" ", "_").replace("-", "_")
            file_path = os.path.join(self.custom_tools_dir, f"{safe_name}.yaml")

            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Save the tool configuration
            with open(file_path, "w") as file:
                yaml.dump({name: config}, file, default_flow_style=False)

            logger.info(f"Saved custom tool '{name}' to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving custom tool '{name}': {str(e)}")
            return False

    def remove_tool(self, name: str) -> bool:
        """
        Remove a tool from the manager.

        Args:
            name (str): The name of the tool to remove

        Returns:
            bool: True if the tool was removed successfully, False otherwise
        """
        if name not in self.tools:
            logger.warning(f"Tool '{name}' does not exist.")
            return False

        # Check if it's a custom tool and remove the file
        safe_name = name.lower().replace(" ", "_").replace("-", "_")
        custom_file_path = os.path.join(self.custom_tools_dir, f"{safe_name}.yaml")

        if os.path.exists(custom_file_path):
            try:
                os.remove(custom_file_path)
                logger.info(f"Removed custom tool file: {custom_file_path}")
            except Exception as e:
                logger.error(
                    f"Error removing custom tool file '{custom_file_path}': {str(e)}"
                )
                return False

        # Remove from the in-memory dictionary
        del self.tools[name]
        logger.info(f"Removed tool '{name}'")
        return True

    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all loaded tools.

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of all tools
        """
        return self.tools.copy()

    def check_tool_availability(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and available.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if the tool is available, False otherwise
        """
        tool_info = self.get_tool(tool_name)
        if not tool_info:
            logger.error(f"Tool '{tool_name}' not found")
            return False

        # Check if we have a command to test
        if "check_command" in tool_info:
            cmd = tool_info["check_command"]
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                return result.returncode == 0
            except Exception as e:
                logger.error(f"Error checking tool '{tool_name}': {e}")
                return False

        # Check if we have a binary to test
        if "binary" in tool_info:
            binary = tool_info["binary"]
            return shutil.which(binary) is not None

        # Check if we have a Python package to test
        if "python_package" in tool_info:
            package = tool_info["python_package"]
            try:
                pkg_resources.get_distribution(package)
                return True
            except pkg_resources.DistributionNotFound:
                return False

        logger.warning(f"No method available to check tool '{tool_name}'")
        return False

    def get_available_tools(
        self, category: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get all available (installed) tools, optionally filtered by category.

        Args:
            category: Optional category to filter by

        Returns:
            Dictionary of available tools
        """
        all_tools = self.get_all_tools()
        available_tools = {}

        for name, info in all_tools.items():
            if category and info.get("category") != category:
                continue

            if self.check_tool_availability(name):
                available_tools[name] = info

        return available_tools

    def install_tool(self, tool_name: str) -> bool:
        """
        Install a tool by name.

        Args:
            tool_name: Name of the tool to install

        Returns:
            True if installation succeeded, False otherwise
        """
        tool_info = self.get_tool(tool_name)
        if not tool_info:
            logger.error(f"Tool '{tool_name}' not found in configuration")
            return False

        if self.check_tool_availability(tool_name):
            logger.info(f"Tool '{tool_name}' is already installed")
            return True

        if "installation" not in tool_info:
            logger.error(f"No installation information for tool '{tool_name}'")
            return False

        installation = tool_info["installation"]
        method = installation.get("method", "").lower()

        # Install based on method
        if method == "apt" and "apt" in self._package_managers:
            return self._install_apt(installation.get("package", tool_name))
        elif method == "brew" and "brew" in self._package_managers:
            return self._install_brew(installation.get("package", tool_name))
        elif method == "pip" and "pip" in self._package_managers:
            return self._install_pip(installation.get("package", tool_name))
        elif method == "npm" and "npm" in self._package_managers:
            return self._install_npm(installation.get("package", tool_name))
        elif method == "git":
            return self._install_git(
                installation.get("repository"), installation.get("commands", [])
            )
        elif method == "binary":
            return self._install_binary(
                installation.get("url") or installation.get("path")
            )
        else:
            logger.error(
                f"Unsupported installation method '{method}' for tool '{tool_name}'"
            )
            return False

    def _install_apt(self, package: str) -> bool:
        """Install a package using apt-get."""
        try:
            cmd = ["apt-get", "install", "-y", package]
            logger.info(f"Installing {package} with apt-get")
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing {package} with apt-get: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing {package}: {e}")
            return False

    def _install_brew(self, package: str) -> bool:
        """Install a package using Homebrew."""
        try:
            cmd = ["brew", "install", package]
            logger.info(f"Installing {package} with Homebrew")
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing {package} with Homebrew: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing {package}: {e}")
            return False

    def _install_pip(self, package: str) -> bool:
        """Install a package using pip."""
        try:
            cmd = ["pip", "install", package]
            logger.info(f"Installing {package} with pip")
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing {package} with pip: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing {package}: {e}")
            return False

    def _install_npm(self, package: str) -> bool:
        """Install a package using npm."""
        try:
            cmd = ["npm", "install", "-g", package]
            logger.info(f"Installing {package} with npm")
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing {package} with npm: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing {package}: {e}")
            return False

    def _install_git(self, repository: str, commands: List[str]) -> bool:
        """Install a tool from a git repository."""
        if not repository:
            logger.error("No repository URL provided")
            return False

        try:
            # Create a temporary directory
            import tempfile

            temp_dir = tempfile.mkdtemp()

            # Clone the repository
            cmd = ["git", "clone", repository, temp_dir]
            logger.info(f"Cloning {repository}")
            subprocess.run(
                cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            # Run installation commands
            for command in commands:
                cmd = f"cd {temp_dir} && {command}"
                logger.info(f"Running: {cmd}")
                subprocess.run(
                    cmd,
                    shell=True,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            # Clean up
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Error installing from git: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing from git: {e}")
            return False

    def _install_binary(self, url_or_path: str) -> bool:
        """Install a binary from a URL or local path."""
        if not url_or_path:
            logger.error("No URL or path provided for binary installation")
            return False

        # Determine if it's a URL or local path
        if url_or_path.startswith(("http://", "https://")):
            # Download from URL
            try:
                logger.info(f"Downloading binary from {url_or_path}")
                response = requests.get(url_or_path, timeout=30)
                if response.status_code != 200:
                    logger.error(f"Failed to download binary: {response.status_code}")
                    return False

                # Determine local path
                filename = os.path.basename(url_or_path)
                local_path = os.path.join("/tmp", filename)

                # Save the file
                with open(local_path, "wb") as f:
                    f.write(response.content)

                # Make executable
                os.chmod(local_path, 0o755)

                # Move to a PATH directory
                dest_path = os.path.join("/usr/local/bin", filename)
                shutil.move(local_path, dest_path)

                return True
            except Exception as e:
                logger.error(f"Error installing binary: {e}")
                return False
        else:
            # Local path - just make executable and copy
            try:
                os.chmod(url_or_path, 0o755)
                dest_path = os.path.join(
                    "/usr/local/bin", os.path.basename(url_or_path)
                )
                shutil.copy(url_or_path, dest_path)
                return True
            except Exception as e:
                logger.error(f"Error installing local binary: {e}")
                return False

    def check_for_updates(self) -> Dict[str, bool]:
        """
        Check for updates to installed tools.

        Returns:
            Dictionary of {tool_name: needs_update} pairs
        """
        # Implementation will depend on how updates are handled for each tool
        # This is a placeholder for the full implementation
        update_status = {}
        available_tools = self.get_available_tools()

        for name, info in available_tools.items():
            # For simplicity, just return False for each tool
            # In a real implementation, this would check version info
            update_status[name] = False

        return update_status
