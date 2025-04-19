"""
Command-line interface for the distributed scanning architecture.

This module provides commands to start and manage master and worker nodes
in the Sniper distributed scanning architecture.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from src.core.logging import setup_logging
from src.distributed.master import MasterNodeServer
from src.distributed.worker import WorkerNodeServer

# Configure logging
logger = logging.getLogger("sniper.distributed.cli")


def start_master(args):
    """Start a master node with the specified configuration."""
    setup_logging(level=args.log_level.upper())

    logger.info(f"Starting master node on {args.host}:{args.port}")
    logger.info(f"Using {args.distribution_strategy} distribution strategy")

    # Load provider config if specified
    provider_config = None
    if args.provider_config:
        try:
            with open(args.provider_config, "r") as f:
                provider_config = json.load(f)
                logger.info(
                    f"Loaded provider configuration from {args.provider_config}"
                )
        except Exception as e:
            logger.error(f"Error loading provider config: {e}")
            return 1

    # Create and start master node
    try:
        master = MasterNodeServer(
            config_path=args.config,
            host=args.host,
            port=args.port,
            protocol_type=args.protocol,
            distribution_strategy=args.distribution_strategy,
            worker_timeout=args.worker_timeout,
            auto_scaling=args.auto_scaling,
            min_nodes=args.min_nodes,
            max_nodes=args.max_nodes,
            scaling_policy=args.scaling_policy,
            scaling_provider=args.scaling_provider,
            provider_config_path=args.provider_config,
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

        # Keep the process running
        logger.info("Master node running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error starting master node: {e}", exc_info=True)
        return 1

    return 0


def start_worker(args):
    """Start a worker node that connects to a master node."""
    setup_logging(level=args.log_level.upper())

    logger.info(
        f"Starting worker node connecting to {args.master_host}:{args.master_port}"
    )

    # Create and start worker node
    try:
        worker = WorkerNodeServer(
            master_host=args.master_host,
            master_port=args.master_port,
            worker_id=args.worker_id,
            protocol_type=args.protocol,
            capabilities=args.capabilities.split(",") if args.capabilities else None,
            max_tasks=args.max_tasks,
            config_path=args.config,
        )

        # Handle interrupts
        def signal_handler(sig, frame):
            logger.info("Shutting down worker node...")
            worker.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start the worker
        worker.start()

        # Keep the process running
        logger.info("Worker node running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error starting worker node: {e}", exc_info=True)
        return 1

    return 0


def status_command(args):
    """Check the status of a distributed scanning deployment."""
    setup_logging(level=args.log_level.upper())

    logger.info(f"Checking status of {args.host}:{args.port}")

    # Implementation to be added later - this would connect to
    # the master node and retrieve status information
    logger.warning("Status command not yet implemented")
    return 0


def main() -> int:
    """
    Main entry point for the distributed CLI.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = argparse.ArgumentParser(
        description="Sniper Distributed Scanning Architecture CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Logging level",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Master node command
    master_parser = subparsers.add_parser("master", help="Start a master node")
    master_parser.add_argument(
        "--host", default="0.0.0.0", help="Host address to bind to"
    )
    master_parser.add_argument(
        "--port", type=int, default=5000, help="Port to listen on"
    )
    master_parser.add_argument(
        "--protocol",
        default="rest",
        choices=["rest", "grpc", "ws"],
        help="Communication protocol to use",
    )
    master_parser.add_argument(
        "--distribution-strategy",
        default="capability_based",
        choices=[
            "round_robin",
            "capability_based",
            "priority_based",
            "load_balanced",
            "smart",
        ],
        help="Task distribution strategy",
    )
    master_parser.add_argument(
        "--worker-timeout",
        type=int,
        default=60,
        help="Seconds after which a worker is considered offline",
    )
    master_parser.add_argument("--config", help="Path to configuration file")

    # Auto-scaling options
    master_parser.add_argument(
        "--auto-scaling",
        action="store_true",
        help="Enable auto-scaling of worker nodes",
    )
    master_parser.add_argument(
        "--min-nodes", type=int, default=1, help="Minimum number of worker nodes"
    )
    master_parser.add_argument(
        "--max-nodes", type=int, default=10, help="Maximum number of worker nodes"
    )
    master_parser.add_argument(
        "--scaling-policy",
        default="queue_depth",
        choices=["queue_depth", "cpu_utilization", "task_type", "hybrid"],
        help="Auto-scaling policy",
    )
    master_parser.add_argument(
        "--scaling-provider",
        default="docker",
        choices=["local", "docker", "kubernetes", "aws", "azure", "gcp"],
        help="Provider for worker nodes",
    )
    master_parser.add_argument(
        "--provider-config", help="Path to provider configuration file"
    )
    master_parser.set_defaults(func=start_master)

    # Worker node command
    worker_parser = subparsers.add_parser("worker", help="Start a worker node")
    worker_parser.add_argument(
        "--master-host", required=True, help="Host address of the master node"
    )
    worker_parser.add_argument(
        "--master-port", type=int, default=5000, help="Port of the master node"
    )
    worker_parser.add_argument(
        "--worker-id", help="Unique ID for this worker (generated if not provided)"
    )
    worker_parser.add_argument(
        "--protocol",
        default="rest",
        choices=["rest", "grpc", "ws"],
        help="Communication protocol to use",
    )
    worker_parser.add_argument(
        "--capabilities",
        help="Comma-separated list of task types this worker can execute",
    )
    worker_parser.add_argument(
        "--max-tasks", type=int, default=5, help="Maximum number of concurrent tasks"
    )
    worker_parser.add_argument("--config", help="Path to configuration file")
    worker_parser.set_defaults(func=start_worker)

    # Status command
    status_parser = subparsers.add_parser(
        "status", help="Check status of distributed scanning deployment"
    )
    status_parser.add_argument(
        "--host", default="localhost", help="Host address of the master node"
    )
    status_parser.add_argument(
        "--port", type=int, default=5000, help="Port of the master node"
    )
    status_parser.set_defaults(func=status_command)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
