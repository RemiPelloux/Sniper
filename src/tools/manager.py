"""
Tool Manager Module for Sniper Security Tool.

This module provides functionality to manage security tools used by the Sniper platform,
including installation, verification, listing, and dynamic addition/removal of tools.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Any, Tuple, Union
import pkg_resources
import requests
import yaml

logger = logging.getLogger("sniper.tools.manager")

# Default locations
DEFAULT_TOOLS_CONFIG = os.path.join(os.path.dirname(__file__), "../../config/tools.yaml")
DEFAULT_CUSTOM_TOOLS_CONFIG = os.path.join(os.path.dirname(__file__), "../../config/custom_tools.yaml")


class ToolCategory:
    """Tool categories for organization and filtering."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    UTILITY = "utility"
    
    @classmethod
    def all(cls) -> List[str]:
        """Get all defined categories."""
        return [
            cls.RECONNAISSANCE,
            cls.VULNERABILITY_SCANNING,
            cls.EXPLOITATION,
            cls.POST_EXPLOITATION,
            cls.REPORTING,
            cls.UTILITY
        ]


class ToolInstallMethod:
    """Supported installation methods for tools."""
    APT = "apt"
    YUM = "yum"
    BREW = "brew"
    PIP = "pip"
    GEM = "gem"
    NPM = "npm"
    GO = "go"
    CARGO = "cargo"
    BINARY = "binary"
    DOCKER = "docker"
    MANUAL = "manual"
    
    @classmethod
    def get_package_managers(cls) -> List[str]:
        """Get all package manager-based install methods."""
        return [
            cls.APT, cls.YUM, cls.BREW, 
            cls.PIP, cls.GEM, cls.NPM, 
            cls.GO, cls.CARGO
        ]


class ToolManager:
    """
    Manages security tools for the Sniper Security Platform.
    
    This class handles:
    - Loading tool definitions
    - Checking tool availability
    - Installing and updating tools
    - Adding and removing tools
    - Providing tool information
    """
    
    def __init__(self, tools_config_path: str = DEFAULT_TOOLS_CONFIG,
                 custom_tools_config_path: str = DEFAULT_CUSTOM_TOOLS_CONFIG):
        """
        Initialize the Tool Manager.
        
        Args:
            tools_config_path: Path to the main tools configuration file
            custom_tools_config_path: Path to the custom tools configuration file
        """
        self.tools_config_path = tools_config_path
        self.custom_tools_config_path = custom_tools_config_path
        self.tools = {}
        self.custom_tools = {}
        self.platform = self._detect_platform()
        
        # Load tool definitions
        self._load_tools()
    
    def _detect_platform(self) -> Dict[str, str]:
        """
        Detect the current platform and available package managers.
        
        Returns:
            Dictionary with platform information
        """
        system = platform.system().lower()
        info = {
            "system": system,
            "package_managers": []
        }
        
        # Check for common package managers
        if system == "linux":
            distro = platform.freedesktop_os_release()["ID"].lower() if hasattr(platform, "freedesktop_os_release") else ""
            info["distro"] = distro
            
            # Check for APT (Debian/Ubuntu)
            if shutil.which("apt") or shutil.which("apt-get"):
                info["package_managers"].append(ToolInstallMethod.APT)
            
            # Check for YUM/DNF (RedHat/CentOS/Fedora)
            if shutil.which("yum") or shutil.which("dnf"):
                info["package_managers"].append(ToolInstallMethod.YUM)
                
        elif system == "darwin":
            info["distro"] = "macos"
            # Check for Homebrew
            if shutil.which("brew"):
                info["package_managers"].append(ToolInstallMethod.BREW)
                
        # Check for language-specific package managers
        pm_commands = {
            ToolInstallMethod.PIP: "pip",
            ToolInstallMethod.GEM: "gem",
            ToolInstallMethod.NPM: "npm",
            ToolInstallMethod.GO: "go",
            ToolInstallMethod.CARGO: "cargo",
            ToolInstallMethod.DOCKER: "docker"
        }
        
        for pm, cmd in pm_commands.items():
            if shutil.which(cmd):
                info["package_managers"].append(pm)
                
        return info
    
    def _load_tools(self) -> None:
        """Load built-in and custom tool definitions."""
        # Load built-in tools
        if os.path.exists(self.tools_config_path):
            try:
                with open(self.tools_config_path, 'r') as f:
                    self.tools = yaml.safe_load(f)
                logger.info(f"Loaded {len(self.tools)} tools from configuration")
            except Exception as e:
                logger.error(f"Error loading tools configuration: {e}")
                self.tools = {}
        else:
            logger.warning(f"Tools configuration file not found at {self.tools_config_path}")
            self.tools = {}
            
        # Load custom tools
        if os.path.exists(self.custom_tools_config_path):
            try:
                with open(self.custom_tools_config_path, 'r') as f:
                    self.custom_tools = yaml.safe_load(f)
                logger.info(f"Loaded {len(self.custom_tools)} custom tools")
            except Exception as e:
                logger.error(f"Error loading custom tools configuration: {e}")
                self.custom_tools = {}
        else:
            # Create the custom tools file if it doesn't exist
            try:
                os.makedirs(os.path.dirname(self.custom_tools_config_path), exist_ok=True)
                with open(self.custom_tools_config_path, 'w') as f:
                    yaml.dump({}, f)
                logger.info(f"Created empty custom tools configuration at {self.custom_tools_config_path}")
                self.custom_tools = {}
            except Exception as e:
                logger.error(f"Error creating custom tools configuration: {e}")
                self.custom_tools = {}
    
    def save_custom_tools(self) -> bool:
        """
        Save the custom tools configuration to file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(self.custom_tools_config_path), exist_ok=True)
            with open(self.custom_tools_config_path, 'w') as f:
                yaml.dump(self.custom_tools, f)
            logger.info(f"Saved custom tools configuration to {self.custom_tools_config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving custom tools configuration: {e}")
            return False
    
    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all tools (built-in and custom).
        
        Returns:
            Dictionary of all tools
        """
        # Combine built-in and custom tools, with custom tools taking precedence
        return {**self.tools, **self.custom_tools}
    
    def get_tool(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific tool by name.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool information dictionary or None if not found
        """
        # Check custom tools first
        if tool_name in self.custom_tools:
            return self.custom_tools[tool_name]
        
        # Then check built-in tools
        if tool_name in self.tools:
            return self.tools[tool_name]
        
        return None
    
    def add_tool(self, tool_info: Dict[str, Any]) -> bool:
        """
        Add a new custom tool or update an existing one.
        
        Args:
            tool_info: Dictionary containing tool information
            
        Returns:
            True if successful, False otherwise
        """
        required_fields = ["name", "category", "description"]
        
        # Validate required fields
        for field in required_fields:
            if field not in tool_info:
                logger.error(f"Missing required field '{field}' for tool")
                return False
        
        # Add the tool to custom tools
        tool_name = tool_info["name"]
        self.custom_tools[tool_name] = tool_info
        
        # Save custom tools configuration
        return self.save_custom_tools()
    
    def remove_tool(self, tool_name: str) -> bool:
        """
        Remove a custom tool.
        
        Args:
            tool_name: Name of the tool to remove
            
        Returns:
            True if successful, False otherwise
        """
        # Can only remove custom tools
        if tool_name in self.custom_tools:
            del self.custom_tools[tool_name]
            return self.save_custom_tools()
        else:
            logger.error(f"Cannot remove built-in tool '{tool_name}'. Only custom tools can be removed.")
            return False
    
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
                    timeout=10
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
    
    def get_available_tools(self, category: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
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
    
    def install_tool(self, tool_name: str, method: Optional[str] = None) -> bool:
        """
        Install a tool.
        
        Args:
            tool_name: Name of the tool to install
            method: Optional installation method override
            
        Returns:
            True if installation was successful, False otherwise
        """
        tool_info = self.get_tool(tool_name)
        if not tool_info:
            logger.error(f"Tool '{tool_name}' not found")
            return False
        
        # If already installed, skip
        if self.check_tool_availability(tool_name):
            logger.info(f"Tool '{tool_name}' is already installed")
            return True
        
        # Get installation methods
        install_methods = tool_info.get("install", {})
        if not install_methods:
            logger.error(f"No installation methods defined for tool '{tool_name}'")
            return False
        
        # If method is specified, use that
        if method and method in install_methods:
            return self._run_install_method(tool_name, method, install_methods[method])
        
        # Try to find a compatible installation method
        for pm in self.platform["package_managers"]:
            if pm in install_methods:
                return self._run_install_method(tool_name, pm, install_methods[pm])
        
        # Try binary installation if available
        if "binary" in install_methods:
            return self._run_install_method(tool_name, "binary", install_methods["binary"])
        
        # Try manual installation if available
        if "manual" in install_methods:
            instructions = install_methods["manual"]
            logger.info(f"Manual installation required for tool '{tool_name}'")
            logger.info(f"Instructions: {instructions}")
            return False
        
        logger.error(f"No compatible installation method found for tool '{tool_name}'")
        return False
    
    def _run_install_method(self, tool_name: str, method: str, command: str) -> bool:
        """
        Run an installation command.
        
        Args:
            tool_name: Name of the tool being installed
            method: Installation method
            command: Command to run
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Installing tool '{tool_name}' using {method}: {command}")
        
        try:
            if method == "binary":
                # Binary installation might have special handling
                return self._install_binary(command)
            
            # For package managers
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully installed tool '{tool_name}'")
                return True
            else:
                logger.error(f"Error installing tool '{tool_name}': {result.stderr.decode()}")
                return False
            
        except subprocess.TimeoutExpired:
            logger.error(f"Installation timeout for tool '{tool_name}'")
            return False
        except Exception as e:
            logger.error(f"Error during installation of tool '{tool_name}': {e}")
            return False
    
    def _install_binary(self, url_or_path: str) -> bool:
        """
        Install a binary from URL or path.
        
        Args:
            url_or_path: URL or path to the binary
            
        Returns:
            True if successful, False otherwise
        """
        if url_or_path.startswith(("http://", "https://")):
            # Download the binary
            try:
                response = requests.get(url_or_path, timeout=60)
                if response.status_code != 200:
                    logger.error(f"Failed to download binary: {response.status_code}")
                    return False
                
                # Determine local path
                filename = os.path.basename(url_or_path)
                local_path = os.path.join("/tmp", filename)
                
                # Save the file
                with open(local_path, 'wb') as f:
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
                dest_path = os.path.join("/usr/local/bin", os.path.basename(url_or_path))
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
    
    def update_tool(self, tool_name: str) -> bool:
        """
        Update a specific tool.
        
        Args:
            tool_name: Name of the tool to update
            
        Returns:
            True if update was successful, False otherwise
        """
        tool_info = self.get_tool(tool_name)
        if not tool_info:
            logger.error(f"Tool '{tool_name}' not found")
            return False
        
        # Get update methods
        update_methods = tool_info.get("update", {})
        if not update_methods:
            logger.warning(f"No update methods defined for tool '{tool_name}'")
            # Fall back to reinstallation
            return self.install_tool(tool_name)
        
        # Try to find a compatible update method
        for pm in self.platform["package_managers"]:
            if pm in update_methods:
                return self._run_update_method(tool_name, pm, update_methods[pm])
        
        # Fall back to reinstallation
        logger.info(f"No specific update method found for tool '{tool_name}', attempting reinstall")
        return self.install_tool(tool_name)
    
    def _run_update_method(self, tool_name: str, method: str, command: str) -> bool:
        """
        Run an update command.
        
        Args:
            tool_name: Name of the tool being updated
            method: Update method
            command: Command to run
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Updating tool '{tool_name}' using {method}: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully updated tool '{tool_name}'")
                return True
            else:
                logger.error(f"Error updating tool '{tool_name}': {result.stderr.decode()}")
                return False
            
        except subprocess.TimeoutExpired:
            logger.error(f"Update timeout for tool '{tool_name}'")
            return False
        except Exception as e:
            logger.error(f"Error during update of tool '{tool_name}': {e}")
            return False
    
    def get_tool_names_by_category(self, category: str) -> List[str]:
        """
        Get names of all tools in a specific category.
        
        Args:
            category: Category to filter by
            
        Returns:
            List of tool names in the category
        """
        tools = self.get_all_tools()
        return [name for name, info in tools.items() if info.get("category") == category]
    
    def get_installation_status(self) -> Dict[str, bool]:
        """
        Get installation status for all tools.
        
        Returns:
            Dictionary mapping tool names to installation status
        """
        all_tools = self.get_all_tools()
        status = {}
        
        for name in all_tools:
            status[name] = self.check_tool_availability(name)
            
        return status 