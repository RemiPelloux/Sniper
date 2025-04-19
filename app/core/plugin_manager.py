"""
Core Plugin Management System for Sniper.

Defines the interface for plugins and the manager responsible for discovering,
loading, and interacting with them.
"""

import importlib
import inspect
import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

logger = logging.getLogger(__name__)


class PluginInterface(ABC):
    """
    Abstract Base Class for all Sniper plugins.

    Plugins should inherit from this class and implement the required methods.
    """

    name: str = "BasePlugin"
    description: str = "Base description"

    @abstractmethod
    def load(self) -> bool:
        """
        Load necessary resources or perform setup for the plugin.
        Returns True if loading was successful, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def unload(self) -> bool:
        """
        Clean up resources used by the plugin.
        Returns True if unloading was successful, False otherwise.
        """
        raise NotImplementedError

    def register_cli_commands(self, cli_app):
        """
        Optional method for plugins to register Typer CLI commands.
        Plugins can add their own subcommands to the main Sniper CLI.

        Args:
            cli_app: The main Typer application instance.
        """
        pass  # Default implementation does nothing


class PluginManager:
    """
    Manages the lifecycle and discovery of Sniper plugins.
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initializes the PluginManager.

        Args:
            plugin_dirs: A list of directories to search for plugins.
                         If None, defaults to ["app/plugins"].
        """
        self.plugin_dirs = plugin_dirs if plugin_dirs else ["app/plugins"]
        self.plugins: Dict[str, PluginInterface] = {}
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self._discovered_plugin_classes: Dict[str, Type[PluginInterface]] = {}

    def discover_plugins(self):
        """
        Scans the specified plugin directories for valid plugins.
        Looks for subclasses of PluginInterface.
        """
        self._discovered_plugin_classes = {}
        for plugin_dir in self.plugin_dirs:
            if not os.path.isdir(plugin_dir):
                logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue

            for item in os.listdir(plugin_dir):
                item_path = os.path.join(plugin_dir, item)
                if os.path.isdir(item_path):
                    module_name = f"{plugin_dir.replace('/', '.')}.{item}"
                    try:
                        # Dynamically import the module (__init__.py or specific files)
                        # Look for a primary plugin file first, e.g., sandbox_plugin.py
                        potential_plugin_file = f"{item}_plugin.py"
                        plugin_file_path = os.path.join(item_path, potential_plugin_file)
                        module_spec = None

                        if os.path.exists(plugin_file_path):
                             module_spec = importlib.util.spec_from_file_location(
                                f"{module_name}.{item}_plugin", plugin_file_path
                            )
                        else:
                             # Fallback: Look for __init__.py or other .py files
                             # This part could be more sophisticated
                             init_path = os.path.join(item_path, "__init__.py")
                             if os.path.exists(init_path):
                                module_spec = importlib.util.spec_from_file_location(
                                     f"{module_name}", init_path
                                )

                        if module_spec and module_spec.loader:
                            module = importlib.util.module_from_spec(module_spec)
                            module_spec.loader.exec_module(module)

                            for _, obj in inspect.getmembers(module):
                                if (
                                    inspect.isclass(obj)
                                    and issubclass(obj, PluginInterface)
                                    and obj is not PluginInterface
                                ):
                                    if obj.name in self._discovered_plugin_classes:
                                        logger.warning(
                                            f"Duplicate plugin name '{obj.name}' found. "
                                            f"Overwriting previous entry."
                                        )
                                    self._discovered_plugin_classes[obj.name] = obj
                                    logger.debug(f"Discovered plugin: {obj.name}")
                        # else:
                        #     logger.debug(f"No loadable module found in {item_path}")

                    except ImportError as e:
                        logger.error(f"Error importing plugin module {module_name}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error discovering plugins in {item_path}: {e}")

        logger.info(f"Discovered {len(self._discovered_plugin_classes)} potential plugin classes.")


    def instantiate_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Instantiates a discovered plugin class by name."""
        if plugin_name in self.plugins:
            return self.plugins[plugin_name] # Already instantiated

        plugin_class = self._discovered_plugin_classes.get(plugin_name)
        if not plugin_class:
            logger.error(f"Plugin class '{plugin_name}' not discovered.")
            return None

        try:
            instance = plugin_class()
            self.plugins[plugin_name] = instance
            logger.info(f"Instantiated plugin: {plugin_name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to instantiate plugin '{plugin_name}': {e}")
            return None


    def load_plugin(self, plugin_name: str) -> bool:
        """Loads a specific plugin by name."""
        if plugin_name in self.loaded_plugins:
            logger.warning(f"Plugin '{plugin_name}' already loaded.")
            return True

        plugin_instance = self.plugins.get(plugin_name)
        if not plugin_instance:
             plugin_instance = self.instantiate_plugin(plugin_name)
             if not plugin_instance:
                  return False # Failed to instantiate

        try:
            if plugin_instance.load():
                self.loaded_plugins[plugin_name] = plugin_instance
                logger.info(f"Successfully loaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Plugin '{plugin_name}' load() method returned False.")
                # Remove from instantiated if load fails?
                if plugin_name in self.plugins:
                     del self.plugins[plugin_name]
                return False
        except Exception as e:
            logger.error(f"Error loading plugin '{plugin_name}': {e}")
            # Remove from instantiated if load fails?
            if plugin_name in self.plugins:
                 del self.plugins[plugin_name]
            return False

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unloads a specific plugin by name."""
        if plugin_name not in self.loaded_plugins:
            logger.warning(f"Plugin '{plugin_name}' not loaded or already unloaded.")
            return True

        plugin_instance = self.loaded_plugins[plugin_name]
        try:
            if plugin_instance.unload():
                del self.loaded_plugins[plugin_name]
                # Keep instance in self.plugins for potential reload? Or remove?
                # Let's remove it for now to ensure clean state.
                if plugin_name in self.plugins:
                    del self.plugins[plugin_name]
                logger.info(f"Successfully unloaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Plugin '{plugin_name}' unload() method returned False.")
                return False
        except Exception as e:
            logger.error(f"Error unloading plugin '{plugin_name}': {e}")
            return False

    def load_all_plugins(self):
        """Discovers and loads all available plugins."""
        self.discover_plugins()
        loaded_count = 0
        for name in self._discovered_plugin_classes:
             if self.load_plugin(name):
                  loaded_count += 1
        logger.info(f"Loaded {loaded_count} out of {len(self._discovered_plugin_classes)} discovered plugins.")


    def unload_all_plugins(self):
        """Unloads all currently loaded plugins."""
        # Iterate over a copy of keys as dictionary size changes during iteration
        plugin_names = list(self.loaded_plugins.keys())
        unloaded_count = 0
        for name in plugin_names:
            if self.unload_plugin(name):
                unloaded_count += 1
        logger.info(f"Unloaded {unloaded_count} plugins.")

    def register_all_cli_commands(self, cli_app):
        """Calls register_cli_commands on all loaded plugins."""
        logger.info("Registering CLI commands for loaded plugins...")
        for name, plugin_instance in self.loaded_plugins.items():
            try:
                plugin_instance.register_cli_commands(cli_app)
                logger.debug(f"Registered CLI commands for plugin: {name}")
            except Exception as e:
                logger.error(f"Error registering CLI commands for plugin '{name}': {e}")

# Global instance (optional, can be managed by app context)
# plugin_manager = PluginManager() 