"""
Sandbox Plugin Implementation for Sniper.

Provides a controlled environment with vulnerable applications for testing
Sniper's capabilities and for user training.
"""

import json
import logging
import os
import subprocess
from typing import List, Optional

import typer

from src.sniper.core.plugin_manager import PluginInterface, PluginManager

logger = logging.getLogger(__name__)

sandbox_app = typer.Typer(help="Manage the Sniper Sandbox environment.")

# Define available sandbox environments (maps name to docker-compose file)
# Assumes docker-compose files are located within the plugin directory
SANDBOX_ENVIRONMENTS = {
    "dvwa": "docker-compose.dvwa.yml",
    "juiceshop": "docker-compose.juiceshop.yml",
    # Add more pre-configured environments here
}


class SandboxPlugin(PluginInterface):
    """
    Manages sandbox environments (vulnerable applications) using Docker Compose.
    """

    name: str = "Sandbox"
    description: str = (
        "Manages vulnerable sandbox environments for testing and training."
    )
    # Store the path relative to this plugin file
    plugin_dir: str = os.path.dirname(os.path.abspath(__file__))

    def load(self) -> bool:
        """Load the sandbox plugin. Checks for Docker and Docker Compose."""
        logger.info("Loading Sandbox Plugin...")
        if not self._check_docker_prerequisites():
            logger.error("Docker or Docker Compose not found. Sandbox plugin disabled.")
            return False
        logger.info("Sandbox Plugin loaded successfully.")
        return True

    def unload(self) -> bool:
        """Unload the sandbox plugin. Stops any running environments."""
        logger.info("Unloading Sandbox Plugin...")
        # Attempt to stop all known environments upon unload
        for env_name in SANDBOX_ENVIRONMENTS:
            self._stop_environment(env_name, silent=True)
        logger.info("Sandbox Plugin unloaded.")
        return True

    def register_cli_commands(self, cli_app):
        """Register the 'sandbox' subcommand with the main CLI."""
        cli_app.add_typer(sandbox_app, name="sandbox")
        logger.debug("Registered 'sandbox' CLI commands.")

    def _check_docker_prerequisites(self) -> bool:
        """Check if Docker and Docker Compose (v2) are available."""
        try:
            subprocess.run(["docker", "--version"], check=True, capture_output=True)
            # Check for Docker Compose v2 (docker compose ...)
            subprocess.run(
                ["docker", "compose", "version"], check=True, capture_output=True
            )
            return True
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.debug(f"Docker prerequisite check failed: {e}")
            return False

    def _get_compose_file_path(self, environment_name: str) -> Optional[str]:
        """Get the full path to the docker-compose file for an environment."""
        compose_filename = SANDBOX_ENVIRONMENTS.get(environment_name)
        if not compose_filename:
            return None
        return os.path.join(self.plugin_dir, compose_filename)

    def _run_docker_compose(self, command: List[str]) -> bool:
        """Runs a docker compose command, handling errors."""
        try:
            # Use docker compose (v2 syntax)
            full_command = ["docker", "compose"] + command
            logger.debug(f"Running Docker Compose command: {' '.join(full_command)}")
            # Set cwd to the plugin directory to ensure compose finds relative paths
            result = subprocess.run(
                full_command,
                check=True,
                capture_output=True,
                text=True,
                cwd=self.plugin_dir,
            )
            logger.debug(f"Docker Compose stdout:\n{result.stdout}")
            if result.stderr:
                logger.warning(f"Docker Compose stderr:\n{result.stderr}")
            return True
        except FileNotFoundError:
            logger.error(
                "'docker compose' command not found. Is Docker installed correctly?"
            )
            return False
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Docker Compose command failed (Exit Code: {e.returncode}):\n"
                f"Command: {' '.join(e.cmd)}\n"
                f"Stderr: {e.stderr}\n"
                f"Stdout: {e.stdout}"
            )
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred running Docker Compose: {e}")
            return False

    def _start_environment(self, environment_name: str) -> bool:
        """Starts a specific sandbox environment."""
        compose_file = self._get_compose_file_path(environment_name)
        if not compose_file:
            logger.error(f"Unknown sandbox environment: {environment_name}")
            return False
        if not os.path.exists(compose_file):
            logger.error(f"Docker Compose file not found: {compose_file}")
            return False

        logger.info(f"Starting sandbox environment: {environment_name}...")
        command = ["-f", compose_file, "up", "-d"]  # Run in detached mode
        return self._run_docker_compose(command)

    def _stop_environment(self, environment_name: str, silent: bool = False) -> bool:
        """Stops a specific sandbox environment."""
        compose_file = self._get_compose_file_path(environment_name)
        if not compose_file:
            if not silent:
                logger.error(f"Unknown sandbox environment: {environment_name}")
            return False
        # Don't fail if the file doesn't exist, maybe it was already cleaned up
        # if not os.path.exists(compose_file):
        #      if not silent: logger.error(f"Docker Compose file not found: {compose_file}")
        #      return False

        if not silent:
            logger.info(f"Stopping sandbox environment: {environment_name}...")
        else:
            logger.debug(
                f"Silently stopping sandbox environment: {environment_name}..."
            )

        command = ["-f", compose_file, "down"]  # Stops and removes containers
        return self._run_docker_compose(command)

    def _get_status(self, environment_name: str) -> str:
        """Gets the status of a specific sandbox environment."""
        compose_file = self._get_compose_file_path(environment_name)
        if not compose_file or not os.path.exists(compose_file):
            return "Unknown / Not Found"

        command = ["-f", compose_file, "ps", "--format", "json"]
        try:
            full_command = ["docker", "compose"] + command
            result = subprocess.run(
                full_command,
                check=True,
                capture_output=True,
                text=True,
                cwd=self.plugin_dir,
            )
            # Parse the JSON output (each line is a JSON object for a service)
            services = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        services.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Could not parse Docker Compose ps output line: {line}"
                        )

            if not services:
                return "Stopped"

            # Check if all services are running
            all_running = all(s.get("State") == "running" for s in services)
            some_running = any(s.get("State") == "running" for s in services)

            if all_running:
                return "Running"
            elif some_running:
                return "Partially Running"
            else:
                # Consider other states like 'exited', 'paused'
                return "Stopped / Issues"

        except subprocess.CalledProcessError:
            # If 'ps' fails, likely means no running containers for this compose file
            return "Stopped"
        except Exception as e:
            logger.error(f"Error getting status for {environment_name}: {e}")
            return "Error"

    def _get_access_info(self, environment_name: str) -> Optional[str]:
        """Provides basic access info (e.g., URL) for a known environment."""
        # This needs to be customized per environment
        if environment_name == "dvwa":
            # Assuming default DVWA setup
            return "Access DVWA at http://localhost:80 (Default: admin/password)"
        elif environment_name == "juiceshop":
            # Assuming default Juice Shop setup
            return "Access OWASP Juice Shop at http://localhost:3000"
        else:
            return None  # No specific info for other environments


# --- CLI Command Implementations ---


def _get_sandbox_plugin_instance() -> Optional[SandboxPlugin]:
    """Helper to get the loaded SandboxPlugin instance."""
    # This assumes a global or context-managed plugin manager
    # For now, we instantiate it directly for CLI usage, but this should
    # ideally use the main app's plugin manager instance.
    # TODO: Refactor to use a shared plugin manager context.
    temp_manager = PluginManager()
    temp_manager.discover_plugins()
    instance = temp_manager.instantiate_plugin("Sandbox")
    if isinstance(instance, SandboxPlugin):
        # Perform prerequisite check here if needed for CLI commands
        if not instance._check_docker_prerequisites():
            typer.echo(
                "Error: Docker or Docker Compose not found. Cannot manage sandbox.",
                err=True,
            )
            raise typer.Exit(code=1)
        return instance
    else:
        typer.echo("Error: Could not load Sandbox Plugin.", err=True)
        raise typer.Exit(code=1)


@sandbox_app.command("start")
def start_sandbox(
    environment: str = typer.Argument(
        ...,
        help=f"Name of the sandbox environment to start. Available: {list(SANDBOX_ENVIRONMENTS.keys())}",
    )
):
    """Start a specific sandbox environment (e.g., dvwa, juiceshop)."""
    plugin = _get_sandbox_plugin_instance()
    if plugin and plugin._start_environment(environment):
        typer.echo(f"Sandbox environment '{environment}' started successfully.")
        access_info = plugin._get_access_info(environment)
        if access_info:
            typer.echo(access_info)
    else:
        typer.echo(f"Failed to start sandbox environment '{environment}'.", err=True)
        raise typer.Exit(code=1)


@sandbox_app.command("stop")
def stop_sandbox(
    environment: str = typer.Argument(
        ...,
        help=f"Name of the sandbox environment to stop. Available: {list(SANDBOX_ENVIRONMENTS.keys())}",
    )
):
    """Stop a specific sandbox environment."""
    plugin = _get_sandbox_plugin_instance()
    if plugin and plugin._stop_environment(environment):
        typer.echo(f"Sandbox environment '{environment}' stopped successfully.")
    else:
        typer.echo(f"Failed to stop sandbox environment '{environment}'.", err=True)
        # Don't exit with error if stop fails, might already be stopped
        # raise typer.Exit(code=1)


@sandbox_app.command("status")
def sandbox_status(
    environment: Optional[str] = typer.Argument(
        None,
        help=f"Name of the sandbox environment to check. If omitted, checks all. Available: {list(SANDBOX_ENVIRONMENTS.keys())}",
    )
):
    """Check the status of sandbox environments."""
    plugin = _get_sandbox_plugin_instance()
    if not plugin:
        raise typer.Exit(code=1)

    environments_to_check = (
        [environment] if environment else list(SANDBOX_ENVIRONMENTS.keys())
    )

    typer.echo("Sandbox Status:")
    for env_name in environments_to_check:
        if env_name not in SANDBOX_ENVIRONMENTS:
            typer.echo(f"- {env_name}: Unknown")
            continue
        status = plugin._get_status(env_name)
        typer.echo(f"- {env_name}: {status}")
        if status == "Running":
            access_info = plugin._get_access_info(env_name)
            if access_info:
                typer.echo(f"  {access_info}")


@sandbox_app.command("list")
def list_sandboxes():
    """List available sandbox environments."""
    typer.echo("Available Sandbox Environments:")
    if not SANDBOX_ENVIRONMENTS:
        typer.echo("  (No environments defined)")
        return

    for name, file in SANDBOX_ENVIRONMENTS.items():
        typer.echo(f"- {name} (Defined in: {file})")


# Example placeholder docker-compose files need to be created
# in app/plugins/sandbox/ directory:
# - docker-compose.dvwa.yml
# - docker-compose.juiceshop.yml
