import atexit  # Import atexit for cleanup
import logging

# Import Path for absolute path calculation
from pathlib import Path
from typing import Any  # Import Any

import typer

# Import __version__ directly
from src import __version__

# Import subcommand apps
from src.cli import custom_tools, ml, report, scan, tools
from src.core.logging import setup_logging

# Update PluginManager import
from src.sniper.core.plugin_manager import PluginManager

# from importlib import metadata # Removed unused import


# # Setup logging based on loaded settings - MOVED TO main callback
# setup_logging()

# Get a logger for this module
log = logging.getLogger(__name__)

# --- Plugin Manager Setup ---
# Calculate absolute path to the standard plugins directory
# Assuming main.py is in src/cli/main.py
project_root = Path(__file__).resolve().parent.parent.parent
# Update path to point to src/sniper/plugins
plugins_dir_abs = project_root / "src" / "sniper" / "plugins"

# Instantiate the Plugin Manager with the absolute path
log.info(f"Initializing PluginManager with directory: {plugins_dir_abs}")
plugin_manager = PluginManager(plugin_dirs=[str(plugins_dir_abs)])


# Register a cleanup function to unload plugins on exit
@atexit.register
def cleanup_plugins() -> None:
    log.info("Unloading plugins before exit...")
    plugin_manager.unload_all_plugins()
    log.info("Plugin cleanup complete.")


# --- End Plugin Manager Setup ---


# Function to get version
def _get_version() -> str:
    # Directly return the imported version
    return __version__
    # try:
    #     # Assumes the package name matches the name in pyproject.toml
    #     return metadata.version("sniper-cli")
    # except metadata.PackageNotFoundError:
    #     return "0.0.0-dev"  # Default if package not installed properly


app = typer.Typer(
    name="sniper",
    help="Penetration Testing CLI Tool with ML Enhancement.",
    add_completion=False,
    no_args_is_help=True,  # Show help if no command is given
)

# Register built-in subcommands
app.add_typer(scan.app, name="scan")  # Make sure name is explicitly set
app.add_typer(report.app, name="report")
app.add_typer(tools.tools_app, name="tools")
app.add_typer(ml.ml, name="ml")
app.add_typer(custom_tools.custom_tools_app, name="custom-tools")

# --- Load Plugins and Register Commands ---
try:
    log.info("Loading and registering plugins...")
    plugin_manager.load_all_plugins()
    plugin_manager.register_all_cli_commands(app)  # Pass the main app instance
    log.info("Plugin loading and registration complete.")
except Exception as e:
    log.error(f"Failed during plugin initialization: {e}", exc_info=True)
    # Decide if the app should fail to start if plugins fail
    # For now, we log the error and continue
# --- End Plugin Loading ---


# Separate callback for version handling
def _version_callback(value: bool) -> None:
    if value:
        version = _get_version()
        print(f"Sniper CLI v{version}")
        raise typer.Exit()


@app.callback()  # Use callback for top-level options like --version
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,  # Process this before commands
    ),
) -> None:
    """Main entry point for the Sniper CLI."""
    # Setup logging only if not exiting for version
    # Note: is_eager=True means this callback runs *after* the version callback if version was provided
    setup_logging()
    # Split log message to ensure it's under length limit
    log.debug("Logging setup complete.")
    log.debug("Executing main callback.")

    # Original debug message (if needed)
    log.debug("Main callback finished.")


if __name__ == "__main__":
    app()
