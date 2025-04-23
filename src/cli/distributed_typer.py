"""
Command-line interface for the distributed scanning architecture using Typer.

This module provides Typer-based commands to start and manage master and worker nodes
in the Sniper distributed scanning architecture.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import typer
from rich.console import Console
from rich.table import Table

from src.core.logging import setup_logging
from src.distributed.base import TaskPriority
from src.cli.distributed_client import create_master_client
from src.distributed.client import create_worker_client
from src.distributed.master import MasterNodeServer
from src.distributed.worker import WorkerNodeClient

# Default configuration for autodiscovery (since import is problematic)
DEFAULT_AUTODISCOVERY_CONFIG = {
    "master": {
        "host": "0.0.0.0",
        "port": 5000,
        "protocol": "rest",
        "distribution_strategy": "smart",
        "worker_timeout": 60,
        "auto_scaling": True,
        "min_nodes": 1,
        "max_nodes": 10,
        "scaling_policy": "queue_depth",
        "scaling_provider": "docker",
    },
    "worker": {
        "capabilities": ["autonomous_test", "vulnerability_scan", "recon"],
        "max_tasks": 5,
        "heartbeat_interval": 30,
    }
}

# Configure logging
logger = logging.getLogger("sniper.distributed.cli")

# Initialize console for rich output
console = Console()

# Create Typer app instances
distributed_app = typer.Typer(
    help="Distributed scanning commands for Sniper Security Tool",
    no_args_is_help=True,
)

# Create subcommands
master_app = typer.Typer(help="Master node commands", no_args_is_help=True)
worker_app = typer.Typer(help="Worker node commands", no_args_is_help=True)
tasks_app = typer.Typer(help="Task management commands", no_args_is_help=True)
workers_app = typer.Typer(help="Worker management commands", no_args_is_help=True)

# Add subcommands to main app
distributed_app.add_typer(master_app, name="master")
distributed_app.add_typer(worker_app, name="worker")
distributed_app.add_typer(tasks_app, name="tasks")
distributed_app.add_typer(workers_app, name="workers")


# Helper function to parse host:port string
def parse_host_port(host_port: str) -> Tuple[str, int]:
    """Parse a host:port string into separate host and port."""
    if ":" in host_port:
        host, port_str = host_port.split(":", 1)
        return host, int(port_str)
    return host_port, 5000  # Default port


# Master node commands
@master_app.command("start")
def master_start(
    host: str = typer.Option("0.0.0.0", "--host", help="Host address to bind to"),
    port: int = typer.Option(5000, "--port", help="Port to listen on"),
    protocol: str = typer.Option(
        "rest",
        "--protocol",
        help="Communication protocol to use",
        show_choices=True,
        case_sensitive=False,
    ),
    distribution_strategy: str = typer.Option(
        "capability_based",
        "--distribution-strategy",
        "-d",
        help="Task distribution strategy",
        show_choices=True,
        case_sensitive=False,
    ),
    worker_timeout: int = typer.Option(
        60, "--worker-timeout", help="Seconds after which a worker is considered offline"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file"
    ),
    auto_scaling: bool = typer.Option(
        False, "--auto-scaling", help="Enable auto-scaling of worker nodes"
    ),
    min_nodes: int = typer.Option(
        1, "--min-nodes", help="Minimum number of worker nodes"
    ),
    max_nodes: int = typer.Option(
        10, "--max-nodes", help="Maximum number of worker nodes"
    ),
    scaling_policy: str = typer.Option(
        "queue_depth",
        "--scaling-policy",
        help="Auto-scaling policy",
        show_choices=True,
        case_sensitive=False,
    ),
    scaling_provider: str = typer.Option(
        "docker",
        "--scaling-provider",
        help="Provider for worker nodes",
        show_choices=True,
        case_sensitive=False,
    ),
    provider_config: Optional[Path] = typer.Option(
        None, "--provider-config", help="Path to provider configuration file"
    ),
    log_level: str = typer.Option(
        "info",
        "--log-level",
        "-l",
        help="Logging level",
        show_choices=True,
        case_sensitive=False,
    ),
) -> None:
    """Start a master node with the specified configuration."""
    setup_logging(level=log_level.upper())

    logger.info(f"Starting master node on {host}:{port}")
    logger.info(f"Using {distribution_strategy} distribution strategy")

    # Load provider config if specified
    provider_config_data = None
    if provider_config:
        try:
            with open(provider_config, "r") as f:
                provider_config_data = json.load(f)
                logger.info(f"Loaded provider configuration from {provider_config}")
        except Exception as e:
            logger.error(f"Error loading provider config: {e}")
            raise typer.Exit(code=1)

    # Create and start master node
    try:
        master = MasterNodeServer(
            config_path=str(config) if config else None,
            host=host,
            port=port,
            protocol_type=protocol,
            distribution_strategy=distribution_strategy,
            worker_timeout=worker_timeout,
            auto_scaling=auto_scaling,
            min_nodes=min_nodes,
            max_nodes=max_nodes,
            scaling_policy=scaling_policy,
            scaling_provider=scaling_provider,
            provider_config_path=str(provider_config) if provider_config else None,
        )

        # Handle interrupts
        def signal_handler(sig, frame):
            logger.info("Shutting down master node...")
            master.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start the server
        master.start()

        # Print success message
        console.print(f"[green]Master node started successfully on {host}:{port}[/green]")
        
        # Keep the process running
        logger.info("Master node running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error starting master node: {e}", exc_info=True)
        console.print(f"[red]Failed to start master node: {str(e)}[/red]")
        raise typer.Exit(code=1)


@master_app.command("stop")
def master_stop(
    host: str = typer.Option("localhost", "--host", help="Master node host"),
    port: int = typer.Option(5000, "--port", help="Master node port"),
) -> None:
    """Stop a running master node."""
    try:
        client = create_master_client(host=host, port=port)
        if client.stop():
            console.print("[green]Master node stopped[/green]")
        else:
            console.print("[red]Failed to stop master node[/red]")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error stopping master node: {str(e)}[/red]")
        raise typer.Exit(code=1)


@master_app.command("status")
def master_status(
    host: str = typer.Option("localhost", "--host", help="Master node host"),
    port: int = typer.Option(5000, "--port", help="Master node port"),
) -> None:
    """Get status of a master node."""
    try:
        client = create_master_client(host=host, port=port)
        status = client.get_status()

        # Create a rich table for displaying status
        table = Table(title="Master Node Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in status.items():
            table.add_row(key, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error getting master node status: {str(e)}[/red]")
        raise typer.Exit(code=1)


# Worker node commands
@worker_app.command("start")
def worker_start(
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
    worker_id: Optional[str] = typer.Option(
        None, "--worker-id", help="Unique ID for this worker (generated if not provided)"
    ),
    protocol: str = typer.Option(
        "rest",
        "--protocol",
        help="Communication protocol to use",
        show_choices=True,
        case_sensitive=False,
    ),
    capabilities: str = typer.Option(
        "",
        "--capabilities",
        "-c",
        help="Comma-separated list of task types this worker can execute",
    ),
    max_tasks: int = typer.Option(
        5, "--max-tasks", help="Maximum number of concurrent tasks"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file"
    ),
    log_level: str = typer.Option(
        "info",
        "--log-level",
        "-l",
        help="Logging level",
        show_choices=True,
        case_sensitive=False,
    ),
) -> None:
    """Start a worker node that connects to a master node."""
    setup_logging(level=log_level.upper())

    # Parse master host:port
    master_host, master_port = parse_host_port(master)

    logger.info(f"Starting worker node connecting to {master_host}:{master_port}")

    # Process capabilities
    capabilities_list = capabilities.split(",") if capabilities else None
    if capabilities_list and '' in capabilities_list:
        capabilities_list.remove('')

    # Create and start worker node
    try:
        worker = WorkerNodeClient(
            master_host=master_host,
            master_port=master_port,
            worker_id=worker_id,
            protocol_type=protocol,
            capabilities=capabilities_list,
            max_tasks=max_tasks,
            heartbeat_interval=30,  # Default heartbeat interval
            config_path=str(config) if config else None,
        )

        # Handle interrupts
        def signal_handler(sig, frame):
            logger.info("Shutting down worker node...")
            asyncio.run(worker.stop())
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start the worker using asyncio
        asyncio.run(worker.start())

        # Print success message
        console.print("[green]Worker node started[/green]")
        
        # Keep the process running
        logger.info("Worker node running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error starting worker node: {e}", exc_info=True)
        console.print(f"[red]Failed to start worker node: {str(e)}[/red]")
        raise typer.Exit(code=1)


@worker_app.command("stop")
def worker_stop(
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
    worker_id: Optional[str] = typer.Option(
        None,
        "--worker-id",
        help="Worker ID to stop (stops local worker if not specified)",
    ),
) -> None:
    """Stop a worker node."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_worker_client(master_host=master_host, master_port=master_port)
        if asyncio.run(client.stop(worker_id)):
            console.print("[green]Worker node stopped[/green]")
        else:
            console.print("[red]Failed to stop worker node[/red]")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error stopping worker node: {str(e)}[/red]")
        raise typer.Exit(code=1)


@worker_app.command("status")
def worker_status(
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
    worker_id: Optional[str] = typer.Option(
        None,
        "--worker-id",
        help="Worker ID to check (checks local worker if not specified)",
    ),
) -> None:
    """Get status of a worker node."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_worker_client(master_host=master_host, master_port=master_port)
        status = asyncio.run(client.get_status(worker_id))

        # Create a rich table for displaying status
        table = Table(title="Worker Node Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in status.items():
            table.add_row(key, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error getting worker node status: {str(e)}[/red]")
        raise typer.Exit(code=1)


# Workers management commands
@workers_app.command("list")
def list_workers(
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
    status_filter: Optional[str] = typer.Option(
        None,
        "--status",
        help="Filter workers by status (ACTIVE, IDLE, OFFLINE)",
    ),
) -> None:
    """List all workers registered with the master node."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_master_client(host=master_host, port=master_port)
        workers = client.get_workers(status=status_filter)

        if not workers:
            console.print("[yellow]No workers found[/yellow]")
            return

        # Create a rich table for displaying workers
        table = Table(title="Registered Workers")
        table.add_column("ID", style="cyan")
        table.add_column("Hostname", style="blue")
        table.add_column("Address", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Capabilities", style="yellow")
        table.add_column("Last Heartbeat", style="magenta")

        for worker in workers:
            status_style = {
                "ACTIVE": "green",
                "IDLE": "blue",
                "OFFLINE": "red",
                "ERROR": "red bold",
            }.get(worker["status"], "white")
            
            table.add_row(
                worker["id"],
                worker["hostname"],
                worker["address"],
                f"[{status_style}]{worker['status']}[/{status_style}]",
                ", ".join(worker.get("capabilities", [])),
                worker.get("last_heartbeat", "N/A"),
            )

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error listing workers: {str(e)}[/red]")
        raise typer.Exit(code=1)


# Tasks management commands
@tasks_app.command("list")
def list_tasks(
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
    status_filter: Optional[str] = typer.Option(
        None,
        "--status",
        help="Filter tasks by status (PENDING, RUNNING, COMPLETED, FAILED)",
    ),
    task_type: Optional[str] = typer.Option(
        None, "--type", help="Filter tasks by type"
    ),
) -> None:
    """List all tasks managed by the master node."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_master_client(host=master_host, port=master_port)
        tasks = client.get_tasks(status=status_filter, task_type=task_type)

        if not tasks:
            console.print("[yellow]No tasks found[/yellow]")
            return

        # Create a rich table for displaying tasks
        table = Table(title="Tasks")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="blue")
        table.add_column("Target", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Worker", style="magenta")
        table.add_column("Created", style="blue")
        table.add_column("Priority", style="yellow")

        for task in tasks:
            status_style = {
                "PENDING": "yellow",
                "RUNNING": "green",
                "COMPLETED": "blue",
                "FAILED": "red",
                "CANCELED": "magenta",
            }.get(task["status"], "white")
            
            table.add_row(
                task["id"],
                task["type"],
                str(task.get("target", "N/A")),
                f"[{status_style}]{task['status']}[/{status_style}]",
                task.get("assigned_worker", "N/A"),
                task.get("created_at", "N/A"),
                task.get("priority", "MEDIUM"),
            )

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error listing tasks: {str(e)}[/red]")
        raise typer.Exit(code=1)


@tasks_app.command("cancel")
def cancel_task(
    task_id: str = typer.Argument(..., help="ID of the task to cancel"),
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
) -> None:
    """Cancel a running or pending task."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_master_client(host=master_host, port=master_port)
        if client.cancel_task(task_id):
            console.print(f"[green]Task {task_id} canceled successfully[/green]")
        else:
            console.print(f"[red]Failed to cancel task {task_id}[/red]")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error canceling task: {str(e)}[/red]")
        raise typer.Exit(code=1)


@tasks_app.command("info")
def task_info(
    task_id: str = typer.Argument(..., help="ID of the task to get info for"),
    master: str = typer.Option(
        "localhost:5000", "--master", "-m", help="Master node address (host:port)"
    ),
) -> None:
    """Get detailed information about a task."""
    try:
        # Parse master host:port
        master_host, master_port = parse_host_port(master)
        
        client = create_master_client(host=master_host, port=master_port)
        task_info = client.get_task_info(task_id)

        if not task_info:
            console.print(f"[yellow]Task {task_id} not found[/yellow]")
            raise typer.Exit(code=1)

        # Create a rich table for displaying task info
        table = Table(title=f"Task Information: {task_id}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in task_info.items():
            if key == "result" and value and isinstance(value, (dict, list)):
                # Format complex result data
                table.add_row(key, json.dumps(value, indent=2))
            else:
                table.add_row(key, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error getting task info: {str(e)}[/red]")
        raise typer.Exit(code=1)


# Root command for starting auto-discovery
@distributed_app.command("auto")
def auto_discovery(
    config: Optional[Path] = typer.Option(
        None, "--config", help="Path to configuration file"
    ),
    log_level: str = typer.Option(
        "info",
        "--log-level",
        "-l",
        help="Logging level",
        show_choices=True,
        case_sensitive=False,
    ),
) -> None:
    """Start a complete distributed system with auto-discovery and management."""
    setup_logging(level=log_level.upper())

    logger.info("Starting Sniper distributed system with auto-discovery")
    
    # Modified to not use the problematic import
    console.print("[yellow]Auto-discovery mode functionality is currently in development[/yellow]")
    console.print("[green]Starting a master node instead with default settings[/green]")
    
    try:
        # Create and start master node with default settings
        master = MasterNodeServer(
            host=DEFAULT_AUTODISCOVERY_CONFIG["master"]["host"],
            port=DEFAULT_AUTODISCOVERY_CONFIG["master"]["port"],
            protocol_type=DEFAULT_AUTODISCOVERY_CONFIG["master"]["protocol"],
            distribution_strategy=DEFAULT_AUTODISCOVERY_CONFIG["master"]["distribution_strategy"],
            worker_timeout=DEFAULT_AUTODISCOVERY_CONFIG["master"]["worker_timeout"],
            auto_scaling=DEFAULT_AUTODISCOVERY_CONFIG["master"]["auto_scaling"],
            min_nodes=DEFAULT_AUTODISCOVERY_CONFIG["master"]["min_nodes"],
            max_nodes=DEFAULT_AUTODISCOVERY_CONFIG["master"]["max_nodes"]
        )
        
        # Handle interrupts
        def signal_handler(sig, frame):
            logger.info("Shutting down master node...")
            master.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start the server
        master.start()
        console.print(f"[green]Master node started on {DEFAULT_AUTODISCOVERY_CONFIG['master']['host']}:{DEFAULT_AUTODISCOVERY_CONFIG['master']['port']}[/green]")
        
        # Keep the process running
        logger.info("Master node running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping on user request")
            master.stop()
    except Exception as e:
        logger.error(f"Error starting distributed system: {e}", exc_info=True)
        console.print(f"[red]Failed to start distributed system: {str(e)}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    distributed_app() 