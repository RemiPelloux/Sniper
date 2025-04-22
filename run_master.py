#!/usr/bin/env python
"""
Simple script to run a Sniper master node
"""

import sys
from src.cli.distributed import start_master
import argparse

if __name__ == "__main__":
    # Create parser similar to the CLI distributed module
    parser = argparse.ArgumentParser(description="Start a Sniper master node")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host address to bind to"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to listen on"
    )
    parser.add_argument(
        "--protocol",
        default="rest",
        choices=["rest", "grpc", "ws"],
        help="Communication protocol to use",
    )
    parser.add_argument(
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
    parser.add_argument(
        "--worker-timeout",
        type=int,
        default=60,
        help="Seconds after which a worker is considered offline",
    )
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument(
        "--auto-scaling",
        action="store_true",
        help="Enable auto-scaling of worker nodes",
    )
    parser.add_argument(
        "--min-nodes", type=int, default=1, help="Minimum number of worker nodes"
    )
    parser.add_argument(
        "--max-nodes", type=int, default=10, help="Maximum number of worker nodes"
    )
    parser.add_argument(
        "--scaling-policy",
        default="queue_depth",
        choices=["queue_depth", "cpu_utilization", "task_type", "hybrid"],
        help="Auto-scaling policy",
    )
    parser.add_argument(
        "--scaling-provider",
        default="docker",
        choices=["local", "docker", "kubernetes", "aws", "azure", "gcp"],
        help="Provider for worker nodes",
    )
    parser.add_argument(
        "--provider-config", help="Path to provider configuration file"
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Logging level",
    )
    
    args = parser.parse_args()
    
    # Call the start_master function
    sys.exit(start_master(args)) 