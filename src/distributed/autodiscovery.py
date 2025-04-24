"""
Auto-discovery and Management System for Sniper's Distributed Architecture

This module provides automatic service discovery, worker provisioning, and task distribution
for the Sniper security tool's distributed scanning architecture. Key features include:

1. Auto-discovery of worker nodes using mDNS/DNS-SD or direct registration
2. Automatic worker provisioning based on demand and configured policies
3. Intelligent task scheduling and load balancing
4. Health monitoring and fault tolerance
5. Worker auto-scaling based on workload
"""

import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from src.core.config import get_config
from src.distributed.base import NodeStatus, TaskPriority
from src.distributed.master import MasterNodeServer
from src.distributed.worker import WorkerNodeClient

logger = logging.getLogger("sniper.distributed.autodiscovery")

# Default configuration
DEFAULT_CONFIG = {
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
    },
    "discovery": {
        "enabled": True,
        "method": "direct",  # Options: direct, mdns, kubernetes
        "auto_start": True,
        "network_scan_interval": 300,  # Seconds between network scans
    },
    "docker": {
        "worker_image": "sniper/worker:latest",
        "network": "sniper_network",
        "cpu_limit": "1",
        "memory_limit": "2g",
    },
    "kubernetes": {
        "namespace": "sniper",
        "worker_image": "sniper/worker:latest",
        "cpu_request": "500m",
        "memory_request": "1Gi",
        "cpu_limit": "1",
        "memory_limit": "2Gi",
    },
}


class DiscoveryManager:
    """
    Manages the discovery and registration of worker nodes in the distributed system.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the discovery manager.

        Args:
            config_path: Path to the configuration file
        """
        # Load configuration
        self.config = DEFAULT_CONFIG.copy()
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    user_config = json.load(f)
                    # Update config with user settings, preserving defaults for missing values
                    self._update_nested_dict(self.config, user_config)
            except Exception as e:
                logger.error(f"Error loading config from {config_path}: {e}")

        # Initialize properties
        self.master_server: Optional[MasterNodeServer] = None
        self.registered_workers: Dict[str, Dict[str, Any]] = {}
        self.worker_processes: Dict[str, subprocess.Popen] = {}
        self.auto_start = self.config["discovery"]["auto_start"]
        self.discovery_method = self.config["discovery"]["method"]
        self.running = False
        self.discovery_thread = None

    def _update_nested_dict(self, d: Dict, u: Dict) -> Dict:
        """Recursively update a nested dictionary with another dictionary."""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v
        return d

    def start(self) -> bool:
        """
        Start the discovery manager and master node.

        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("Discovery manager already running")
            return True

        try:
            # Start master node
            logger.info("Starting master node...")
            master_config = self.config["master"]

            self.master_server = MasterNodeServer(
                host=master_config["host"],
                port=master_config["port"],
                protocol_type=master_config["protocol"],
                distribution_strategy=master_config["distribution_strategy"],
                worker_timeout=master_config["worker_timeout"],
                auto_scaling=master_config["auto_scaling"],
                min_nodes=master_config["min_nodes"],
                max_nodes=master_config["max_nodes"],
                scaling_policy=master_config["scaling_policy"],
                scaling_provider=master_config["scaling_provider"],
            )

            self.master_server.start()

            # Start discovery thread
            if self.config["discovery"]["enabled"]:
                self.running = True
                self.discovery_thread = threading.Thread(
                    target=self._discovery_loop, daemon=True
                )
                self.discovery_thread.start()
                logger.info(
                    f"Discovery manager started with method: {self.discovery_method}"
                )

            # If auto-start is enabled, deploy initial worker nodes
            if self.auto_start:
                min_nodes = master_config["min_nodes"]
                logger.info(f"Auto-starting {min_nodes} worker node(s)...")
                self._auto_start_workers(min_nodes)

            return True

        except Exception as e:
            logger.error(f"Failed to start discovery manager: {str(e)}", exc_info=True)
            self.running = False
            return False

    def stop(self) -> bool:
        """
        Stop the discovery manager and all managed components.

        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("Discovery manager not running")
            return True

        try:
            # Stop discovery thread
            self.running = False
            if self.discovery_thread and self.discovery_thread.is_alive():
                self.discovery_thread.join(timeout=5)

            # Stop all worker processes
            for worker_id, process in list(self.worker_processes.items()):
                logger.info(f"Stopping worker process: {worker_id}")
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception as e:
                    logger.warning(f"Error stopping worker {worker_id}: {e}")
                    try:
                        process.kill()
                    except:
                        pass

                self.worker_processes.pop(worker_id, None)

            # Stop master server
            if self.master_server:
                logger.info("Stopping master server...")
                self.master_server.stop()
                self.master_server = None

            logger.info("Discovery manager stopped")
            return True

        except Exception as e:
            logger.error(f"Error stopping discovery manager: {str(e)}", exc_info=True)
            return False

    def _discovery_loop(self) -> None:
        """Background thread that performs periodic discovery of worker nodes."""
        interval = self.config["discovery"]["network_scan_interval"]

        while self.running:
            try:
                # Perform discovery based on configured method
                if self.discovery_method == "direct":
                    self._direct_discovery()
                elif self.discovery_method == "mdns":
                    self._mdns_discovery()
                elif self.discovery_method == "kubernetes":
                    self._kubernetes_discovery()

                # Check if we need to scale worker nodes
                self._check_scaling()

                # Wait for next discovery cycle
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in discovery loop: {str(e)}", exc_info=True)
                time.sleep(60)  # Wait a minute before retrying

    def _direct_discovery(self) -> None:
        """Perform direct discovery of worker nodes (manual registration approach)."""
        # In direct discovery, workers register themselves so we just check health
        workers = self.master_server.get_active_workers() if self.master_server else []

        # Log current worker status
        logger.info(f"Direct discovery found {len(workers)} active worker(s)")

        # Update our registry with currently active workers
        self.registered_workers = {
            w.id: {
                "id": w.id,
                "address": w.address,
                "port": w.port,
                "capabilities": w.capabilities,
                "status": w.status.name,
                "last_seen": datetime.now(),
            }
            for w in workers
        }

    def _mdns_discovery(self) -> None:
        """Discover worker nodes using mDNS/DNS-SD."""
        try:
            # This would use zeroconf or similar library to discover workers
            logger.info("mDNS discovery not fully implemented yet")
            # Placeholder for actual mDNS discovery logic
        except Exception as e:
            logger.error(f"Error in mDNS discovery: {str(e)}")

    def _kubernetes_discovery(self) -> None:
        """Discover worker nodes within a Kubernetes cluster."""
        try:
            # This would use the Kubernetes API to discover worker pods
            logger.info("Kubernetes discovery not fully implemented yet")
            # Placeholder for actual Kubernetes API discovery logic
        except Exception as e:
            logger.error(f"Error in Kubernetes discovery: {str(e)}")

    def _check_scaling(self) -> None:
        """Check if we need to scale worker nodes up or down."""
        if not self.master_server or not self.auto_start:
            return

        # Get current active workers count
        active_workers = len(self.master_server.get_active_workers())
        min_nodes = self.config["master"]["min_nodes"]
        max_nodes = self.config["master"]["max_nodes"]

        # Simple scaling logic: ensure minimum number of workers
        if active_workers < min_nodes:
            nodes_to_add = min_nodes - active_workers
            logger.info(f"Scaling up: adding {nodes_to_add} worker(s)")
            self._auto_start_workers(nodes_to_add)

        # More sophisticated scaling could be added here based on metrics like:
        # - Queue depth
        # - CPU utilization
        # - Task type distribution
        # - Time of day patterns

    def _auto_start_workers(self, count: int) -> None:
        """
        Auto-start the specified number of worker nodes.

        Args:
            count: Number of worker nodes to start
        """
        if count <= 0:
            return

        # Determine the platform and method to start workers
        is_local = True  # Local process by default

        for i in range(count):
            try:
                # Generate a unique worker ID
                worker_id = f"worker-{int(time.time())}-{i}"

                if is_local:
                    # Start worker as a local process
                    self._start_local_worker(worker_id)
                else:
                    # Could implement Docker, Kubernetes, or cloud provider startup here
                    logger.warning("Non-local worker deployment not fully implemented")

            except Exception as e:
                logger.error(f"Failed to auto-start worker {i+1}/{count}: {str(e)}")

    def _start_local_worker(self, worker_id: str) -> bool:
        """
        Start a worker node as a local process.

        Args:
            worker_id: Unique ID for the worker

        Returns:
            True if started successfully, False otherwise
        """
        try:
            # Get the Python executable path
            python_exe = sys.executable

            # Build command to run worker
            cmd = [
                python_exe,
                "-m",
                "src.cli.distributed",
                "worker",
                "--master-host",
                (
                    "localhost"
                    if self.config["master"]["host"] == "0.0.0.0"
                    else self.config["master"]["host"]
                ),
                "--master-port",
                str(self.config["master"]["port"]),
                "--worker-id",
                worker_id,
                "--protocol",
                self.config["master"]["protocol"],
                "--capabilities",
                ",".join(self.config["worker"]["capabilities"]),
                "--max-tasks",
                str(self.config["worker"]["max_tasks"]),
            ]

            # Start the worker process
            logger.info(f"Starting local worker process: {worker_id}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                # Create new process group to avoid signals from parent
                start_new_session=True,
            )

            # Store the process
            self.worker_processes[worker_id] = process

            # Start a thread to monitor the process output
            threading.Thread(
                target=self._monitor_worker_output,
                args=(worker_id, process),
                daemon=True,
            ).start()

            logger.info(f"Started local worker: {worker_id}")
            return True

        except Exception as e:
            logger.error(
                f"Failed to start local worker {worker_id}: {str(e)}", exc_info=True
            )
            return False

    def _monitor_worker_output(self, worker_id: str, process: subprocess.Popen) -> None:
        """
        Monitor and log the output from a worker process.

        Args:
            worker_id: ID of the worker
            process: Subprocess object for the worker
        """
        try:
            # Read and log stdout
            if process.stdout:
                for line in process.stdout:
                    logger.debug(f"Worker {worker_id} stdout: {line.strip()}")

            # Check process status
            exit_code = process.wait()
            logger.info(f"Worker {worker_id} exited with code: {exit_code}")

            # Remove from active processes
            self.worker_processes.pop(worker_id, None)

            # If discovery is still running, check if we need to replace this worker
            if self.running and self.auto_start:
                self._check_scaling()

        except Exception as e:
            logger.error(f"Error monitoring worker {worker_id}: {str(e)}")
            # Clean up the process entry
            self.worker_processes.pop(worker_id, None)


# Singleton instance
_discovery_manager = None


def get_discovery_manager(config_path: Optional[str] = None) -> DiscoveryManager:
    """
    Get the global discovery manager instance.

    Args:
        config_path: Optional path to configuration file

    Returns:
        DiscoveryManager instance
    """
    global _discovery_manager

    if _discovery_manager is None:
        _discovery_manager = DiscoveryManager(config_path)

    return _discovery_manager
