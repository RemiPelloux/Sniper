import logging
import atexit # Import atexit for cleanup

import typer

# Import __version__ directly
from src import __version__

# Import subcommand apps
from src.cli import ml, report, scan, tools, custom_tools
from src.core.logging import setup_logging
from app.core.plugin_manager import PluginManager # Import PluginManager

# from importlib import metadata # Removed unused import


# # Setup logging based on loaded settings - MOVED TO main callback
# setup_logging()

# Get a logger for this module
log = logging.getLogger(__name__)

# --- Plugin Manager Setup ---
# Instantiate the Plugin Manager
# TODO: Consider making plugin_dirs configurable
plugin_manager = PluginManager()

# Register a cleanup function to unload plugins on exit
@atexit.register
def cleanup_plugins():
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
app.add_typer(scan.app)
app.add_typer(report.app)
app.add_typer(tools.tools_app)
app.add_typer(ml.ml)
app.add_typer(custom_tools.custom_tools, name="custom-tools")

# --- Load Plugins and Register Commands ---
try:
    log.info("Loading and registering plugins...")
    plugin_manager.load_all_plugins()
    plugin_manager.register_all_cli_commands(app) # Pass the main app instance
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
