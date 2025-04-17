"""
Node Manager Module for Sniper Security Tool Distributed Scanning Architecture.

This module provides the NodeManager class which is responsible for starting,
stopping, and managing distributed scanning nodes. It handles node registration,
heartbeat monitoring, and recovery strategies.
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

from .base import BaseNode, MasterNode, NodeInfo, NodeRole, NodeStatus, WorkerNode
from .protocol import ProtocolBase, create_protocol

logger = logging.getLogger(__name__)


class NodeManager:
    """Manager class for distributed scanning nodes."""

    def __init__(self, config_path: str = "~/.sniper/distributed/config.json"):
        """Initialize the node manager.

        Args:
            config_path: Path to the configuration file.
        """
        self.config_path = config_path
        self.nodes: Dict[str, NodeInfo] = {}
        self.local_node: Optional[BaseNode] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.monitoring_thread: Optional[threading.Thread] = None
        self.should_stop = threading.Event()
        self.protocol: Optional[ProtocolBase] = None

    def start_master_node(
        self, address: str, port: int, capabilities: List[str]
    ) -> str:
        """Start a master node.

        Args:
            address: IP address to bind to.
            port: Port to listen on.
            capabilities: List of capabilities this node supports.

        Returns:
            Node ID of the started master node.
        """
        if self.local_node:
            logger.warning("Local node already running, stopping it first")
            self.stop_local_node()

        # Create protocol for communication
        self.protocol = create_protocol("rest")

        # Create and start master node
        self.local_node = MasterNode(
            address=address, port=port, capabilities=capabilities
        )
        node_id = self.local_node.node_info.node_id

        # Start the node
        self.local_node.start()
        logger.info(f"Started master node with ID {node_id}")

        # Start monitoring thread
        self._start_monitoring()

        return node_id

    def start_worker_node(
        self,
        master_address: str,
        master_port: int,
        address: str,
        port: int,
        capabilities: List[str],
    ) -> str:
        """Start a worker node.

        Args:
            master_address: IP address of the master node.
            master_port: Port of the master node.
            address: IP address to bind to.
            port: Port to listen on.
            capabilities: List of capabilities this node supports.

        Returns:
            Node ID of the started worker node.
        """
        if self.local_node:
            logger.warning("Local node already running, stopping it first")
            self.stop_local_node()

        # Create protocol for communication
        self.protocol = create_protocol("rest")

        # Create and start worker node
        self.local_node = WorkerNode(
            address=address,
            port=port,
            capabilities=capabilities,
            master_address=master_address,
            master_port=master_port,
        )
        node_id = self.local_node.node_info.node_id

        # Start the node
        self.local_node.start()
        logger.info(f"Started worker node with ID {node_id}")

        # Start heartbeat thread
        self._start_heartbeat()

        return node_id

    def stop_local_node(self) -> None:
        """Stop the local node."""
        if not self.local_node:
            logger.warning("No local node running")
            return

        # Set stop event and wait for threads to finish
        self.should_stop.set()

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)

        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)

        # Stop the node
        self.local_node.stop()
        logger.info(f"Stopped node with ID {self.local_node.node_info.node_id}")

        # Reset state
        self.local_node = None
        self.heartbeat_thread = None
        self.monitoring_thread = None
        self.should_stop.clear()

    def register_node(self, node_info: NodeInfo) -> bool:
        """Register a node with the manager.

        Args:
            node_info: Information about the node to register.

        Returns:
            True if registration was successful, False otherwise.
        """
        if not self.local_node or self.local_node.node_info.role != NodeRole.MASTER:
            logger.error("Cannot register node: local node is not a master")
            return False

        # Check if node already exists
        if node_info.node_id in self.nodes:
            logger.warning(
                f"Node {node_info.node_id} already registered, updating info"
            )

        # Register the node
        self.nodes[node_info.node_id] = node_info
        logger.info(f"Registered node {node_info.node_id} ({node_info.role.name})")

        return True

    def unregister_node(self, node_id: str) -> bool:
        """Unregister a node from the manager.

        Args:
            node_id: ID of the node to unregister.

        Returns:
            True if unregistration was successful, False otherwise.
        """
        if not self.local_node or self.local_node.node_info.role != NodeRole.MASTER:
            logger.error("Cannot unregister node: local node is not a master")
            return False

        # Check if node exists
        if node_id not in self.nodes:
            logger.warning(f"Node {node_id} not registered")
            return False

        # Unregister the node
        del self.nodes[node_id]
        logger.info(f"Unregistered node {node_id}")

        return True

    def get_nodes(
        self, status: Optional[NodeStatus] = None, role: Optional[NodeRole] = None
    ) -> List[NodeInfo]:
        """Get list of registered nodes, optionally filtered by status and role.

        Args:
            status: Filter nodes by status.
            role: Filter nodes by role.

        Returns:
            List of node info objects matching the filters.
        """
        result = []

        for node in self.nodes.values():
            if status and node.status != status:
                continue

            if role and node.role != role:
                continue

            result.append(node)

        return result

    def _start_heartbeat(self) -> None:
        """Start the heartbeat thread for worker nodes."""
        if not self.local_node or self.local_node.node_info.role != NodeRole.WORKER:
            logger.error("Cannot start heartbeat: local node is not a worker")
            return

        def heartbeat_loop():
            while not self.should_stop.is_set():
                try:
                    self.local_node.update_heartbeat()
                    logger.debug(
                        f"Sent heartbeat for node {self.local_node.node_info.node_id}"
                    )
                except Exception as e:
                    logger.error(f"Error sending heartbeat: {str(e)}")

                # Sleep until next heartbeat
                time.sleep(30)  # Send heartbeat every 30 seconds

        self.heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        logger.info("Started heartbeat thread")

    def _start_monitoring(self) -> None:
        """Start the monitoring thread for master nodes."""
        if not self.local_node or self.local_node.node_info.role != NodeRole.MASTER:
            logger.error("Cannot start monitoring: local node is not a master")
            return

        def monitoring_loop():
            while not self.should_stop.is_set():
                try:
                    # Check all nodes for heartbeat timeout
                    current_time = time.time()
                    nodes_to_mark_down = []

                    for node_id, node in self.nodes.items():
                        # Skip if node is already marked as down
                        if node.status == NodeStatus.DOWN:
                            continue

                        # Convert heartbeat to epoch time for comparison
                        heartbeat_epoch = node.heartbeat.timestamp()

                        # Check if heartbeat is too old (> 2 minutes)
                        if current_time - heartbeat_epoch > 120:
                            nodes_to_mark_down.append(node_id)

                    # Mark nodes as down
                    for node_id in nodes_to_mark_down:
                        logger.warning(
                            f"Node {node_id} heartbeat timed out, marking as DOWN"
                        )
                        self.nodes[node_id].status = NodeStatus.DOWN

                        # TODO: Implement recovery strategy for node failure
                        # - Reassign tasks from failed node
                        # - Notify administrator

                except Exception as e:
                    logger.error(f"Error in node monitoring: {str(e)}")

                # Sleep until next monitoring cycle
                time.sleep(60)  # Check node health every minute

        self.monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Started node monitoring thread")
