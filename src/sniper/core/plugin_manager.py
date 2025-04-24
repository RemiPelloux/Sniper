"""
Core Plugin Management System for Sniper.

Defines the interface for plugins and the manager responsible for discovering,
loading, and interacting with them.
"""

import importlib
import importlib.util  # Added for spec_from_file_location
import inspect
import logging
import os
import sys  # Added for sys.path manipulation if needed, though spec_from_file_location might avoid this
from abc import ABC, abstractmethod
from pathlib import Path  # Import Path
from typing import Dict, List, Optional, Type

# Assuming logger is configured elsewhere or use standard logging
# logger = logging.getLogger(__name__)
# Using standard logging for now if specific logger isn't importable here
logger = logging.getLogger("sniper.core.plugin_manager")


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
                         If None, defaults to ["app/plugins"] or ["src/sniper/plugins"] 
                         based on directory existence.
        """
        # Use project standard path as the default
        # Check if app/plugins exists first, otherwise fallback to src/sniper/plugins
        if os.path.exists("app/plugins"):
            default_plugin_dir = "app/plugins"
        else:
            default_plugin_dir = "src/sniper/plugins"

        self.plugin_dirs = (
            plugin_dirs if plugin_dirs is not None else [default_plugin_dir]
        )
        logger.debug(f"PluginManager initialized to search in: {self.plugin_dirs}")
        self.plugins: Dict[str, PluginInterface] = {}
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self._discovered_plugin_classes: Dict[str, Type[PluginInterface]] = {}

    def discover_plugins(self):
        """
        Scans the specified plugin directories for valid plugins.
        Looks for subclasses of PluginInterface.
        Loads modules directly from file paths.
        """
        self._discovered_plugin_classes = {}
        # Store original sys.path to restore later if modified
        original_sys_path = list(sys.path)

        for plugin_dir_str in self.plugin_dirs:
            plugin_dir = Path(plugin_dir_str).resolve()
            logger.debug(f"Scanning for plugins in: {plugin_dir}")
            if not plugin_dir.is_dir():
                logger.warning(
                    f"Plugin directory not found or not a directory: {plugin_dir_str}"
                )
                continue

            # Add parent of plugin dir to sys.path to handle potential relative imports *within* plugins
            # Though ideally plugins should be self-contained or use absolute imports based on project structure
            # parent_dir = str(plugin_dir.parent)
            # if parent_dir not in sys.path:
            #     sys.path.insert(0, parent_dir)
            #     logger.debug(f"Temporarily added {parent_dir} to sys.path")

            for item_path in plugin_dir.iterdir():
                # We look for python files directly in the plugin dir, or in immediate subdirectories
                # that might represent a plugin package
                if (
                    item_path.is_file()
                    and item_path.suffix == ".py"
                    and item_path.stem != "__init__"
                ):
                    # Case 1: Direct .py file plugin
                    self._load_plugin_from_file(item_path)
                elif item_path.is_dir() and (item_path / "__init__.py").exists():
                    # Case 2: Directory as a plugin package

                    # First check __init__.py itself for plugins
                    init_file = item_path / "__init__.py"
                    self._load_plugin_from_file(init_file)

                    # Then check other .py files in the directory
                    for py_file in item_path.glob("*.py"):
                        if (
                            py_file.stem != "__init__"
                        ):  # Skip __init__ itself since we already processed it
                            self._load_plugin_from_file(py_file)
                elif (
                    item_path.is_dir()
                ):  # Check non-package dirs too? Maybe for resources?
                    # Consider if plugins might need non-code resources loaded differently
                    pass

            # Also check base directory __init__.py if it exists
            base_init = plugin_dir / "__init__.py"
            if base_init.exists():
                self._load_plugin_from_file(base_init)

        # Restore original sys.path
        # sys.path = original_sys_path
        # logger.debug("Restored original sys.path")

        logger.info(
            f"Discovered {len(self._discovered_plugin_classes)} potential plugin classes."
        )

    def _load_plugin_from_file(self, py_file_path: Path):
        """Loads plugin classes from a single Python file path."""
        # Create a unique module name based on file path to avoid collisions
        # Using parts relative to a base or just the file name might be sufficient
        # Example: 'plugins.good.good_plugin' - needs careful construction
        # For simplicity, let's use a name derived from the path but ensure it's unique
        # A safer approach uses spec_from_file_location which handles this better.
        module_name = f"sniper_plugin.{py_file_path.parent.name}.{py_file_path.stem}"  # Example unique name

        try:
            # Use spec_from_file_location to load the module directly
            spec = importlib.util.spec_from_file_location(
                module_name, str(py_file_path)
            )
            if spec is None or spec.loader is None:
                logger.error(f"Could not create module spec for {py_file_path}")
                return

            module = importlib.util.module_from_spec(spec)
            # Add module to sys.modules BEFORE execution to handle circular imports within the plugin
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Inspect the loaded module for PluginInterface subclasses
            for _, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, PluginInterface)
                    and obj is not PluginInterface
                    # Ensure the class is defined in *this* loaded module, not imported from elsewhere
                    and obj.__module__ == module_name
                ):
                    plugin_name = getattr(obj, "name", obj.__name__)
                    if plugin_name in self._discovered_plugin_classes:
                        logger.warning(
                            f"Duplicate plugin name '{plugin_name}' found in {py_file_path}. "
                            f"Overwriting previous entry from {self._discovered_plugin_classes[plugin_name].__module__}."
                        )
                    self._discovered_plugin_classes[plugin_name] = obj
                    logger.debug(
                        f"Discovered plugin '{plugin_name}' from {py_file_path}"
                    )

        except ImportError as e:
            # Log import errors that occur *within* the plugin code itself
            logger.error(
                f"Error importing dependencies within plugin file {py_file_path}: {e}",
                exc_info=True,
            )
            # Remove potentially partially loaded module?
            if module_name in sys.modules:
                del sys.modules[module_name]
        except Exception as e:
            logger.error(
                f"Unexpected error processing plugin file {py_file_path}: {e}",
                exc_info=True,
            )
            # Clean up sys.modules?
            if module_name in sys.modules:
                del sys.modules[module_name]

    def instantiate_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Instantiates a discovered plugin class by name."""
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]  # Already instantiated

        plugin_class = self._discovered_plugin_classes.get(plugin_name)
        if not plugin_class:
            # Discover plugins if not already done or if class not found
            if not self._discovered_plugin_classes:
                logger.warning(
                    "Plugin classes not discovered yet. Running discovery..."
                )
                self.discover_plugins()
                plugin_class = self._discovered_plugin_classes.get(plugin_name)

            if not plugin_class:
                logger.error(f"Plugin class '{plugin_name}' not found after discovery.")
                return None

        try:
            instance = plugin_class()
            self.plugins[plugin_name] = instance
            logger.info(f"Instantiated plugin: {plugin_name}")
            return instance
        except Exception as e:
            logger.error(f"Failed to instantiate plugin '{plugin_name}': {e}")
            # Remove class from discovery? Maybe not, could be transient issue.
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
                logger.error(
                    f"Cannot load plugin '{plugin_name}': failed to instantiate."
                )
                return False  # Failed to instantiate

        try:
            logger.debug(f"Attempting to load plugin: {plugin_name}")
            if plugin_instance.load():
                self.loaded_plugins[plugin_name] = plugin_instance
                logger.info(f"Successfully loaded plugin: {plugin_name}")
                return True
            else:
                logger.error(f"Plugin '{plugin_name}' load() method returned False.")
                # Remove from instantiated if load fails, prevent retries
                if plugin_name in self.plugins:
                    del self.plugins[plugin_name]
                if plugin_name in self._discovered_plugin_classes:
                    del self._discovered_plugin_classes[
                        plugin_name
                    ]  # Prevent rediscovery?
                return False
        except Exception as e:
            logger.error(f"Error loading plugin '{plugin_name}': {e}", exc_info=True)
            # Remove from instantiated if load fails
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
            if plugin_name in self._discovered_plugin_classes:
                del self._discovered_plugin_classes[plugin_name]
            return False

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unloads a specific plugin by name."""
        if plugin_name not in self.loaded_plugins:
            try:
                logger.debug(f"Plugin '{plugin_name}' not loaded or already unloaded.")
            except ValueError:
                pass
            return True

        plugin_instance = self.loaded_plugins[plugin_name]
        try:
            logger.debug(f"Attempting to unload plugin: {plugin_name}")
        except ValueError:
            pass
            
        try:
            if plugin_instance.unload():
                del self.loaded_plugins[plugin_name]
                # Keep instance in self.plugins for potential reload? Or remove?
                # Let's remove it for now to ensure clean state.
                if plugin_name in self.plugins:
                    del self.plugins[plugin_name]
                try:
                    logger.info(f"Successfully unloaded plugin: {plugin_name}")
                except ValueError:
                    print(f"Successfully unloaded plugin: {plugin_name}")
                return True
            else:
                try:
                    logger.error(f"Plugin '{plugin_name}' unload() method returned False.")
                except ValueError:
                    print(f"Plugin '{plugin_name}' unload() method returned False.")
                return False
        except Exception as e:
            try:
                logger.error(f"Error unloading plugin '{plugin_name}': {e}", exc_info=True)
            except ValueError:
                print(f"Error unloading plugin '{plugin_name}': {e}")
            return False

    def load_all_plugins(self):
        """Discovers and loads all available plugins."""
        if not self._discovered_plugin_classes:
            self.discover_plugins()

        loaded_count = 0
        # Iterate over a copy of keys as discover_plugins might change the dict
        discovered_names = list(self._discovered_plugin_classes.keys())
        for name in discovered_names:
            if self.load_plugin(name):
                loaded_count += 1
        logger.info(
            f"Loaded {loaded_count} out of {len(discovered_names)} discovered plugins."
        )

    def unload_all_plugins(self):
        """Unloads all currently loaded plugins."""
        # Iterate over a copy of keys as dictionary size changes during iteration
        plugin_names = list(self.loaded_plugins.keys())
        unloaded_count = 0
        if not plugin_names:
            try:
                logger.info("No plugins currently loaded to unload.")
            except ValueError:
                print("No plugins currently loaded to unload.")
            return

        try:
            logger.info(f"Unloading {len(plugin_names)} loaded plugins...")
        except ValueError:
            print(f"Unloading {len(plugin_names)} loaded plugins...")
            
        for name in plugin_names:
            if self.unload_plugin(name):
                unloaded_count += 1
                
        try:
            logger.info(f"Unloaded {unloaded_count} plugins successfully.")
        except ValueError:
            print(f"Unloaded {unloaded_count} plugins successfully.")

    def register_all_cli_commands(self, cli_app):
        """Calls register_cli_commands on all loaded plugins."""
        logger.info("Registering CLI commands for loaded plugins...")
        if not self.loaded_plugins:
            logger.info("No loaded plugins to register commands for.")
            return

        for name, plugin_instance in self.loaded_plugins.items():
            try:
                # Check if method exists and is callable - belts and suspenders
                if hasattr(plugin_instance, "register_cli_commands") and callable(
                    plugin_instance.register_cli_commands
                ):
                    plugin_instance.register_cli_commands(cli_app)
                    logger.debug(f"Called register_cli_commands for plugin: {name}")
                else:
                    logger.warning(
                        f"Plugin '{name}' does not have a callable register_cli_commands method."
                    )
            except Exception as e:
                logger.error(
                    f"Error registering CLI commands for plugin '{name}': {e}",
                    exc_info=True,
                )
