#!/usr/bin/env python
"""
Simple script to run a Sniper worker node
"""

import sys
from src.cli.distributed import start_worker
import argparse

if __name__ == "__main__":
    # Create parser similar to the CLI distributed module
    parser = argparse.ArgumentParser(description="Start a Sniper worker node")
    parser.add_argument(
        "--master-host", required=True, help="Host address of the master node"
    )
    parser.add_argument(
        "--master-port", type=int, default=5000, help="Port of the master node"
    )
    parser.add_argument(
        "--worker-id", help="Unique ID for this worker (generated if not provided)"
    )
    parser.add_argument(
        "--protocol",
        default="rest",
        choices=["rest", "grpc", "ws"],
        help="Communication protocol to use",
    )
    parser.add_argument(
        "--capabilities",
        help="Comma-separated list of task types this worker can execute",
    )
    parser.add_argument(
        "--max-tasks", type=int, default=5, help="Maximum number of concurrent tasks"
    )
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Logging level",
    )
    
    args = parser.parse_args()
    
    # Call the start_worker function
    sys.exit(start_worker(args)) 