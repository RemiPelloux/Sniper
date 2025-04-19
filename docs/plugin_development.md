# Sniper Plugin Development Guide

This guide explains how to develop custom plugins for the Sniper Security Tool.

## 1. Overview

Sniper's plugin system allows developers to extend its core functionality. Plugins can:

*   Add new CLI commands.
*   Integrate custom scanning logic or tools.
*   Introduce new data processing or reporting capabilities.
*   Interact with external systems.

The system relies on a `PluginManager` that discovers, loads, and manages plugins.

## 2. Plugin Structure

Plugins reside within the `app/plugins/` directory. Each plugin should have its own subdirectory.

```
sniper/
├── app/
│   ├── plugins/
│   │   ├── __init__.py
│   │   ├── <your_plugin_name>/
│   │   │   ├── __init__.py
│   │   │   ├── <plugin_module>.py  # Contains your plugin class
│   │   │   └── ... (other plugin files)
│   │   └── sandbox/             # Example: Sandbox plugin
│   │       ├── __init__.py
│   │       ├── sandbox_plugin.py
│   │       └── docker-compose.yml
│   └── ...
├── src/
│   ├── core/
│   │   ├── plugin_interface.py # Defines the base class
│   │   └── plugin_manager.py   # Handles plugin loading
│   └── ...
└── ...
```

*   **`app/plugins/<your_plugin_name>/`**: The main directory for your plugin.
*   **`__init__.py`**: Standard Python package marker files.
*   **`<plugin_module>.py`**: The Python file containing your main plugin class implementation.

## 3. Creating a Plugin

### 3.1. Implement the Plugin Interface

Your main plugin class must inherit from `src.core.plugin_interface.PluginInterface` and implement its required methods and attributes.

**`src.core.plugin_interface.PluginInterface`:**

```python
from abc import ABC, abstractmethod
import typer

class PluginInterface(ABC):
    """Abstract base class for all plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a brief description of the plugin."""
        pass

    @abstractmethod
    def load(self) -> None:
        """Perform any setup required when the plugin is loaded."""
        pass

    @abstractmethod
    def unload(self) -> None:
        """Perform any cleanup required when the plugin is unloaded."""
        pass

    @abstractmethod
    def register_cli_commands(self, app: typer.Typer) -> None:
        """Register Typer CLI commands for the plugin."""
        pass

```

**Example (`app/plugins/my_scanner/scanner_plugin.py`):**

```python
import typer
from src.core.plugin_interface import PluginInterface
from src.core.log_config import logger

class MyScannerPlugin(PluginInterface):
    @property
    def name(self) -> str:
        return "MyScanner"

    @property
    def description(self) -> str:
        return "A custom scanner plugin."

    def load(self) -> None:
        logger.info(f"Loading plugin: {self.name}")
        # Add initialization logic here (e.g., check dependencies, load config)

    def unload(self) -> None:
        logger.info(f"Unloading plugin: {self.name}")
        # Add cleanup logic here

    def register_cli_commands(self, app: typer.Typer) -> None:
        plugin_app = typer.Typer()

        @plugin_app.command("run")
        def run_scan(target: str):
            """Run my custom scan against a target."""
            logger.info(f"[{self.name}] Running scan against {target}")
            # Add actual scan logic here
            print(f"Scan results for {target}...")

        # Add the plugin's commands under a subcommand named after the plugin
        app.add_typer(plugin_app, name=self.name.lower(), help=self.description)
        logger.debug(f"Registered CLI commands for plugin: {self.name}")

```

### 3.2. Plugin Discovery

The `PluginManager` (in `src.core.plugin_manager.py`) automatically discovers plugins located in subdirectories within `app/plugins/`. It looks for Python files and attempts to instantiate classes that:

1.  Inherit from `PluginInterface`.
2.  Are not `PluginInterface` itself.

Ensure your plugin class is defined within a `.py` file directly inside your plugin's directory (e.g., `app/plugins/my_scanner/scanner_plugin.py`).

### 3.3 Registering CLI Commands

The `register_cli_commands` method is crucial for integrating your plugin with Sniper's CLI. You receive the main `typer.Typer` application instance (`app`) as an argument.

**Best Practice:** Create a new `typer.Typer` instance for your plugin's commands and add it as a subcommand to the main `app` using `app.add_typer()`. This keeps the CLI organized.

```python
    def register_cli_commands(self, app: typer.Typer) -> None:
        plugin_app = typer.Typer()

        # Define your commands within plugin_app
        @plugin_app.command("command1")
        def cmd1():
            print("Executing command1 from MyScanner")

        @plugin_app.command("command2")
        def cmd2(option: str):
            print(f"Executing command2 from MyScanner with option: {option}")

        # Add plugin_app as a subcommand (e.g., 'sniper myscanner command1')
        app.add_typer(plugin_app, name=self.name.lower(), help=self.description)
```

## 4. Plugin SDK / Interface Details

Currently, the primary interface for plugins is the `PluginInterface` base class.

*   **`name` (property):** Must return a string that is unique among all plugins. Used for identification and potentially for CLI subcommand naming.
*   **`description` (property):** A brief description used in help messages and logging.
*   **`load()`:** Called by the `PluginManager` when Sniper starts and loads plugins. Use this for initialization, checking prerequisites (like Docker for the Sandbox plugin), or loading configuration specific to your plugin.
*   **`unload()`:** Called when Sniper shuts down (gracefully). Use this for cleanup tasks.
*   **`register_cli_commands(app: typer.Typer)`:** Called during CLI setup. Use this to add your plugin's commands to the main Sniper CLI application.

**Accessing Core Functionality:**

Plugins currently run within the main Sniper application process. They can import and use other Sniper modules (e.g., logging, configuration, core services) **with caution**. Be mindful of:

*   **Tight Coupling:** Directly depending on internal Sniper modules can make your plugin brittle and harder to maintain across Sniper updates.
*   **Future Changes:** The internal structure of Sniper might change. Relying on stable, documented interfaces (like `PluginInterface`) is safer.

*(Future enhancements might include a more formal SDK with helper functions or dedicated APIs for plugins to interact with the core system in a more decoupled way.)*

## 5. Best Practices

*   **Logging:** Use Sniper's shared logger (`from src.core.log_config import logger`) for consistent logging.
*   **Error Handling:** Implement robust error handling within your plugin's logic.
*   **Dependencies:** If your plugin has external Python dependencies, list them. Consider how users will install them (perhaps provide instructions or a `requirements.txt` within your plugin directory).
*   **Prerequisites:** Check for necessary external tools or services (like Docker) in your `load()` method and inform the user if they are missing.
*   **Configuration:** If your plugin needs configuration, consider using Sniper's main configuration mechanism or loading settings from a file within your plugin's directory.

## 6. Example: Sandbox Plugin

Refer to the `app/plugins/sandbox/` directory for a working example. It demonstrates:

*   Implementing `PluginInterface`.
*   Registering CLI commands (`list`, `start`, `stop`, `status`).
*   Interacting with external systems (Docker via `python-on-whales`).
*   Checking prerequisites (`load()` checks for Docker).

---
*This guide provides a starting point. The plugin system may evolve, so refer to the latest code and documentation.* 