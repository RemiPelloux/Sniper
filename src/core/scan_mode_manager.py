"""
Scan Mode Manager Module for Sniper Security Tool.

This module provides functionality to manage scan modes used by the Sniper platform,
including loading, listing, and retrieving scan modes with their configurations.
"""

import logging
import os
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

logger = logging.getLogger("sniper.core.scan_mode_manager")


class ScanModeManager:
    """
    Manages scanning modes for the Sniper Security Platform.

    This class is responsible for loading and retrieving scan modes
    which define preconfigured scanning profiles with different sets of tools,
    depths, and options for various security scanning scenarios.

    Attributes:
        scan_modes (Dict): Dictionary of scan modes loaded from configuration file
    """

    def __init__(self, scan_modes_file: Optional[str] = None) -> None:
        """
        Initialize the ScanModeManager.

        Args:
            scan_modes_file (Optional[str]): Path to the YAML file containing scan mode configurations
        """
        self.scan_modes = {}

        # Set default path if none provided
        if not scan_modes_file:
            scan_modes_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "scan_modes.yaml",
            )

        # Load scan modes
        self._load_scan_modes(scan_modes_file)

    def _load_scan_modes(self, file_path: str) -> None:
        """
        Load scan modes from the specified YAML file.

        Args:
            file_path (str): Path to the YAML file containing scan mode configurations
        """
        try:
            config_file = Path(file_path)
            if not config_file.exists():
                logger.warning(
                    f"Scan modes configuration file does not exist: {file_path}"
                )
                return

            # Load the YAML file
            with open(file_path, "r") as file:
                scan_mode_data = yaml.safe_load(file)

            if not scan_mode_data:
                logger.warning(f"Empty scan mode configuration file: {file_path}")
                return

            # Process each scan mode in the file
            for mode_name, mode_config in scan_mode_data.items():
                self.scan_modes[mode_name] = mode_config
                logger.debug(f"Loaded scan mode: {mode_name}")

            logger.info(f"Loaded {len(self.scan_modes)} scan modes from {file_path}")

        except Exception as e:
            logger.error(f"Error loading scan modes from {file_path}: {str(e)}")

    def get_scan_mode(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a scan mode by name.

        Args:
            name (str): The name of the scan mode to retrieve

        Returns:
            Optional[Dict[str, Any]]: The scan mode configuration or None if not found
        """
        return self.scan_modes.get(name)

    def get_all_scan_modes(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all available scan modes.

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of all scan modes
        """
        return self.scan_modes

    def get_scan_mode_names(self) -> List[str]:
        """
        Get a list of all scan mode names.

        Returns:
            List[str]: List of scan mode names
        """
        return list(self.scan_modes.keys())

    def get_scan_mode_by_target_type(
        self, target_type: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get scan modes suitable for a specific target type.

        Args:
            target_type (str): The target type to filter by (e.g., 'domain', 'url', 'ip')

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of scan modes suitable for the target type
        """
        return {
            name: config
            for name, config in self.scan_modes.items()
            if "target_types" in config and target_type in config["target_types"]
        }

    def get_modules_for_scan_mode(self, mode_name: str) -> List[str]:
        """
        Get the list of modules enabled for a specific scan mode.

        Args:
            mode_name (str): The name of the scan mode

        Returns:
            List[str]: List of modules enabled for the scan mode or empty list if mode not found
        """
        mode = self.get_scan_mode(mode_name)
        if not mode or "modules" not in mode:
            return []
        return mode["modules"]

    def get_tools_for_scan_mode(self, mode_name: str) -> Dict[str, Dict[str, Any]]:
        """
        Get the tools configuration for a specific scan mode.

        Args:
            mode_name (str): The name of the scan mode

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of tool configurations for the scan mode
                                       or empty dict if mode not found
        """
        mode = self.get_scan_mode(mode_name)
        if not mode or "tools" not in mode:
            return {}
        return mode["tools"]

    def get_settings_for_scan_mode(self, mode_name: str) -> Dict[str, Any]:
        """
        Get the general settings for a specific scan mode.

        Args:
            mode_name (str): The name of the scan mode

        Returns:
            Dict[str, Any]: Dictionary of settings for the scan mode or empty dict if mode not found
        """
        mode = self.get_scan_mode(mode_name)
        if not mode or "settings" not in mode:
            return {}
        return mode["settings"]
