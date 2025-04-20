"""
Base classes for distributed scanning architecture

This module provides the foundational classes for implementing a distributed scanning
architecture, including abstract base classes for master and worker nodes, as well as
interfaces for communication protocols and work distribution algorithms.
"""

import abc
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

if TYPE_CHECKING:
    from .protocol import ProtocolMessage  # For type checking only

# Create module logger
logger = logging.getLogger(__name__)


class NodeRole(Enum):
    """Enum defining possible roles for a node in the distributed architecture."""

    MASTER = "master"
    WORKER = "worker"
    HYBRID = "hybrid"  # Can act as both master and worker


class NodeStatus(Enum):
    """Enum defining possible status values for a node."""

    IDLE = "idle"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    OFFLINE = "offline"
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"


class TaskPriority(Enum):
    """Enum defining possible priority levels for tasks."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TaskStatus(Enum):
    """Enumeration of possible task statuses."""

    PENDING = "PENDING"
    ASSIGNED = "ASSIGNED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"  # Corrected case
    REJECTED = "REJECTED"  # Corrected case
    ACCEPTED = "ACCEPTED"  # Corrected case
    CANCELLED = "CANCELLED"  # Corrected case and removed duplicate 'CANCELED'
    UNKNOWN = "UNKNOWN"  # Corrected case


class DistributedTask:
    """Represents a task to be executed by a worker node."""

    def __init__(
        self,
        task_type: str,
        target: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        timeout: int = 3600,  # Default timeout of 1 hour
        dependencies: Optional[List[str]] = None,
        task_id: Optional[str] = None,  # Allow passing ID
    ):
        """
        Initialize a new distributed task.

        Args:
            task_type: Type of task (e.g., "port_scan", "web_scan")
            target: Target information dictionary
            parameters: Additional parameters for the task
            priority: Priority level for this task
            timeout: Timeout in seconds
            dependencies: List of task IDs that must complete before this task
            task_id: Optional specific task ID to use.
        """
        self.id = task_id or str(uuid.uuid4())
        self.task_type = task_type
        self.target = target
        self.parameters = parameters or {}
        self.priority = priority
        self.timeout = timeout
        self.dependencies = dependencies or []
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.updated_at: Optional[datetime] = self.created_at  # Added
        self.started_at: Optional[datetime] = None  # Added
        self.assigned_at: Optional[datetime] = None  # Added
        self.completed_at: Optional[datetime] = None  # Added
        self.assigned_node: Optional[str] = None  # Added
        self.result: Optional[Any] = None  # Added
        self.error: Optional[str] = None  # Added
        self.failure_reason: Optional[str] = None  # Added
        self.retries: int = 0  # Added

    def to_dict(self) -> Dict[str, Any]:
        """Convert the task to a dictionary for serialization."""
        return {
            "id": self.id,
            "task_type": self.task_type,
            "target": self.target,
            "parameters": self.parameters,
            "priority": self.priority.value,
            "timeout": self.timeout,
            "dependencies": self.dependencies,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": (
                self.updated_at.isoformat() if self.updated_at else None
            ),  # Added
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "assigned_at": (
                self.assigned_at.isoformat() if self.assigned_at else None
            ),  # Added
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "assigned_node": self.assigned_node,
            "result": self.result,
            "error": self.error,
            "failure_reason": self.failure_reason,  # Added
            "retries": self.retries,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DistributedTask":
        """Create a task from a dictionary."""
        task = cls(
            task_id=data["id"],  # Use task_id param
            task_type=data["task_type"],
            target=data["target"],
            parameters=data.get("parameters", {}),  # Use get for optional
            priority=TaskPriority(
                data.get("priority", TaskPriority.MEDIUM.value)
            ),  # Use get, default
            timeout=data.get("timeout", 3600),  # Use get, default
            dependencies=data.get("dependencies", []),  # Use get, default
        )
        # task.id is set in __init__
        task.status = TaskStatus(
            data.get("status", TaskStatus.PENDING.value)
        )  # Use get, default
        task.created_at = datetime.fromisoformat(data["created_at"])
        task.updated_at = (
            datetime.fromisoformat(data["updated_at"])
            if data.get("updated_at")
            else task.created_at
        )  # Added
        task.started_at = (
            datetime.fromisoformat(data["started_at"])
            if data.get("started_at")
            else None
        )
        task.assigned_at = (
            datetime.fromisoformat(data["assigned_at"])
            if data.get("assigned_at")
            else None
        )  # Added
        task.completed_at = (
            datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None
        )
        task.assigned_node = data.get("assigned_node")  # Use get
        task.result = data.get("result")  # Use get
        task.error = data.get("error")  # Use get
        task.failure_reason = data.get("failure_reason")  # Added
        task.retries = data.get("retries", 0)
        return task


class NodeInfo:
    """Information about a node in the distributed architecture."""

    def __init__(
        self,
        node_id: str,
        role: NodeRole,
        hostname: str,
        address: str,
        port: int,
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize node information.

        Args:
            node_id: Unique identifier for the node
            role: Role of the node (master, worker, hybrid)
            hostname: Hostname of the node
            address: IP address of the node
            port: Port the node is listening on
            capabilities: List of capabilities this node supports
        """
        self.id = node_id
        self.role = role
        self.hostname = hostname
        self.address = address
        self.port = port
        self.capabilities = capabilities or []
        self.status = NodeStatus.IDLE
        self.heartbeat = datetime.now(timezone.utc)
        self.last_updated: Optional[datetime] = self.heartbeat  # Added
        self.stats = {
            "cpu": 0.0,
            "memory": 0.0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "uptime": 0,
            "current_load": 0.0,  # Renamed from "load" for clarity
        }
        self.current_tasks: List[str] = []  # Type hint added

    def to_dict(self) -> Dict[str, Any]:
        """Convert the node info to a dictionary for serialization."""
        return {
            "id": self.id,
            "role": self.role.value,
            "hostname": self.hostname,
            "address": self.address,
            "port": self.port,
            "capabilities": self.capabilities,
            "status": self.status.value,
            "heartbeat": self.heartbeat.isoformat(),
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),  # Added
            "stats": self.stats,
            "current_tasks": self.current_tasks,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NodeInfo":
        """Create a node info from a dictionary."""
        node = cls(
            node_id=data["id"],
            role=NodeRole(data["role"]),
            hostname=data["hostname"],
            address=data["address"],
            port=data["port"],
            capabilities=data.get("capabilities", []),  # Use get
        )
        node.status = NodeStatus(data.get("status", NodeStatus.IDLE.value))  # Use get
        node.heartbeat = datetime.fromisoformat(data["heartbeat"])
        node.last_updated = (
            datetime.fromisoformat(data["last_updated"])
            if data.get("last_updated")
            else node.heartbeat
        )  # Added
        node.stats = data.get("stats", {})  # Use get
        node.current_tasks = data.get("current_tasks", [])  # Use get
        return node


class WorkerMetrics:
    """Metrics specific to worker performance."""

    def __init__(
        self,
        node_id: str,
        capabilities: List[str],
        current_load: float = 0.0,
        task_count: int = 0,
        success_rate: float = 1.0,
        response_time: float = 0.0,  # Average response time
        last_heartbeat: float = 0.0,  # Use timestamp float for easier comparison
        total_assigned: int = 0,  # Added
        total_execution_time: float = 0.0,  # Added
        penalty_score: int = 0,  # Added
    ):
        self.node_id = node_id
        self.capabilities = capabilities
        self.current_load = current_load
        self.task_count = task_count
        self.success_rate = success_rate
        self.response_time = response_time
        self.last_heartbeat = last_heartbeat
        self.total_assigned = total_assigned
        self.total_execution_time = total_execution_time
        self.penalty_score = penalty_score

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkerMetrics":
        return cls(**data)


class BaseNode(abc.ABC):
    """Base class for both master and worker nodes."""

    def __init__(
        self,
        node_id: Optional[str] = None,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: int = 5000,
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize the base node.

        Args:
            node_id: Unique identifier for the node (auto-generated if None)
            hostname: Hostname of the node (auto-detected if None)
            address: IP address of the node (auto-detected if None)
            port: Port to listen on
            capabilities: List of capabilities this node supports
        """
        import socket

        self.id = node_id or str(uuid.uuid4())
        self.hostname = hostname or socket.gethostname()

        # Try to resolve hostname, default to 127.0.0.1 if it fails
        if address:
            self.address = address
        else:
            try:
                self.address = socket.gethostbyname(self.hostname)
            except socket.gaierror:
                self.address = "127.0.0.1"

        self.port = port
        self.start_time = datetime.now(timezone.utc)
        self.status = NodeStatus.INITIALIZING
        self.capabilities = capabilities or []

    @abc.abstractmethod
    def start(self) -> bool:
        """Start the node."""
        pass

    @abc.abstractmethod
    def stop(self) -> bool:
        """Stop the node."""
        pass

    @abc.abstractmethod
    def status_update(self) -> Dict[str, Any]:
        """Get status information about the node."""
        pass

    def uptime(self) -> int:
        """Get the uptime of the node in seconds."""
        return int((datetime.now(timezone.utc) - self.start_time).total_seconds())


class MasterNode(BaseNode):
    """Master node that coordinates tasks across worker nodes."""

    def __init__(
        self,
        node_id: Optional[str] = None,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: int = 5000,
        capabilities: Optional[List[str]] = None,
    ):
        """Initialize the master node."""
        super().__init__(node_id, hostname, address, port, capabilities)
        self.role = NodeRole.MASTER
        self.workers: Dict[str, NodeInfo] = {}  # Map of worker IDs to NodeInfo objects
        self.tasks: List["DistributedTask"] = []  # All tasks
        self.task_queue: List["DistributedTask"] = []  # List of pending tasks
        self.active_tasks: Dict[str, str] = {}  # Map of task IDs to assigned worker IDs
        self.completed_tasks: Dict[str, Any] = {}  # Map of task IDs to results
        self.failed_tasks: Dict[str, str] = {}  # Map of task IDs to error messages

    @abc.abstractmethod
    def register_worker(self, worker_info: NodeInfo) -> bool:
        """
        Register a worker node with the master.

        Args:
            worker_info: Information about the worker node

        Returns:
            Whether the registration was successful
        """
        pass

    @abc.abstractmethod
    def unregister_worker(self, worker_id: str) -> bool:
        """
        Unregister a worker node from the master.

        Args:
            worker_id: ID of the worker to unregister

        Returns:
            Whether the unregistration was successful
        """
        pass

    @abc.abstractmethod
    def add_task(self, task: DistributedTask) -> str:
        """
        Add a task to the queue.

        Args:
            task: Task to add

        Returns:
            ID of the added task
        """
        pass

    @abc.abstractmethod
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.

        Args:
            task_id: ID of the task to cancel

        Returns:
            Whether the cancellation was successful
        """
        pass

    @abc.abstractmethod
    def distribute_tasks(self) -> int:
        """
        Distribute pending tasks to available workers.

        Returns:
            Number of tasks distributed
        """
        pass

    @abc.abstractmethod
    def process_result(self, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Process a result received from a worker.

        Args:
            task_id: ID of the completed task
            result: Result data

        Returns:
            Whether the result was processed successfully
        """
        pass

    @abc.abstractmethod
    def aggregate_results(self, task_ids: List[str]) -> Dict[str, Any]:
        """
        Aggregate results from multiple tasks.

        Args:
            task_ids: List of task IDs to aggregate

        Returns:
            Aggregated results
        """
        pass

    def _handle_register(self, message: "ProtocolMessage") -> Dict[str, Any]:
        """
        Handle a registration message from a worker.
        Internal method used by protocol handlers.

        Args:
            message: Registration message

        Returns:
            Registration response data
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default _handle_register called - this should be overridden")
        return {"node_id": message.sender_id}

    def _handle_heartbeat(self, message: "ProtocolMessage") -> Dict[str, Any]:
        """
        Handle a heartbeat message from a worker.
        Internal method used by protocol handlers.

        Args:
            message: Heartbeat message

        Returns:
            Heartbeat response data
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default _handle_heartbeat called - this should be overridden")
        return {}

    def _handle_task_status(self, message: "ProtocolMessage") -> Dict[str, Any]:
        """
        Handle a task status message from a worker.
        Internal method used by protocol handlers.

        Args:
            message: Task status message

        Returns:
            Task status response data
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default _handle_task_status called - this should be overridden")
        return {}

    def _handle_task_result(self, message: "ProtocolMessage") -> Dict[str, Any]:
        """
        Handle a task result message from a worker.
        Internal method used by protocol handlers.

        Args:
            message: Task result message

        Returns:
            Task result response data
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default _handle_task_result called - this should be overridden")
        return {}

    def _handle_node_status(self, message: "ProtocolMessage") -> Dict[str, Any]:
        """
        Handle a node status message from a worker.
        Internal method used by protocol handlers.

        Args:
            message: Node status message

        Returns:
            Node status response data
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default _handle_node_status called - this should be overridden")
        return {}

    def get_task_for_worker(self, worker_id: str) -> Optional["DistributedTask"]:
        """
        Find a suitable task for a worker.

        Args:
            worker_id: ID of the worker requesting a task

        Returns:
            Task to assign to the worker, or None if no suitable task is found
        """
        # Default implementation - should be overridden by concrete classes
        logger.warning("Default get_task_for_worker called - this should be overridden")
        return None


class WorkerNode(BaseNode):
    """Worker node that executes tasks assigned by the master."""

    def __init__(
        self,
        master_address: str,
        master_port: int,
        node_id: Optional[str] = None,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: int = 5001,
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize the worker node.

        Args:
            master_address: Address of the master node
            master_port: Port of the master node
            node_id: Unique identifier for this worker (auto-generated if None)
            hostname: Hostname of this worker (auto-detected if None)
            address: IP address of this worker (auto-detected if None)
            port: Port to listen on
            capabilities: List of task types this worker can execute
        """
        super().__init__(node_id, hostname, address, port, capabilities)
        self.role = NodeRole.WORKER
        self.master_address = master_address
        self.master_port = master_port
        self.current_task: Optional["DistributedTask"] = None
        self.task_history: List[str] = []
        self.active_tasks = 0
        self.task_count = 0
        self.success_count = 0
        self.failure_count = 0

    @abc.abstractmethod
    def register_with_master(self) -> bool:
        """
        Register this worker with the master node.

        Returns:
            Whether the registration was successful
        """
        pass

    @abc.abstractmethod
    def get_task(self) -> Optional[DistributedTask]:
        """
        Request a task from the master.

        Returns:
            Task to execute, or None if no tasks are available
        """
        pass

    @abc.abstractmethod
    def execute_task(self, task: DistributedTask) -> Dict[str, Any]:
        """
        Execute a task.

        Args:
            task: Task to execute

        Returns:
            Result of the task execution
        """
        pass

    @abc.abstractmethod
    def send_result(self, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Send a task result back to the master.

        Args:
            task_id: ID of the completed task
            result: Result data

        Returns:
            Whether the result was sent successfully
        """
        pass

    @abc.abstractmethod
    def send_heartbeat(self) -> bool:
        """
        Send a heartbeat to the master.

        Returns:
            Whether the heartbeat was sent successfully
        """
        pass

    def update_heartbeat(self) -> bool:
        """
        Update and send a heartbeat to the master.
        This is a convenience method that calls send_heartbeat.

        Returns:
            Whether the heartbeat was sent successfully
        """
        return self.send_heartbeat()

    def get_resource_usage(self) -> Dict[str, float]:
        """
        Get the current resource usage of the worker.

        Returns:
            Dictionary containing CPU and memory usage percentages
        """
        # Default implementation - real implementations should provide actual metrics
        return {"cpu": 0.0, "memory": 0.0, "disk": 0.0, "network": 0.0}

    def handle_task(self, task_data: Dict[str, Any]) -> bool:
        """
        Handle a task received from the master.

        Args:
            task_data: Task data from master

        Returns:
            True if the task was accepted, False otherwise
        """
        # Default implementation that should be overridden
        logger.warning("Default handle_task called - this should be overridden")
        return False

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task that is currently being executed.

        Args:
            task_id: ID of the task to cancel

        Returns:
            True if the task was cancelled, False otherwise
        """
        # Default implementation that should be overridden
        logger.warning("Default cancel_task called - this should be overridden")
        return False


class HybridNode(MasterNode, WorkerNode):
    """
    Hybrid node that can act as both master and worker.
    Useful for hierarchical distributed architectures.
    """

    def __init__(
        self,
        parent_master_address: Optional[str] = None,
        parent_master_port: Optional[int] = None,
        node_id: Optional[str] = None,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: int = 5000,
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize the hybrid node.

        Args:
            parent_master_address: Address of the parent master node (None if this is the top-level master)
            parent_master_port: Port of the parent master node
            node_id: Unique identifier for this node (auto-generated if None)
            hostname: Hostname of this node (auto-detected if None)
            address: IP address of this node (auto-detected if None)
            port: Port to listen on
            capabilities: List of task types this node can execute
        """
        BaseNode.__init__(self, node_id, hostname, address, port, capabilities)
        self.role = NodeRole.HYBRID

        # Master components
        self.workers: Dict[str, NodeInfo] = {}
        self.tasks: List["DistributedTask"] = []
        self.task_queue: List["DistributedTask"] = []
        self.active_tasks: Dict[str, str] = {}
        self.completed_tasks: Dict[str, Any] = {}
        self.failed_tasks: Dict[str, str] = {}

        # Worker components
        self.parent_master_address = parent_master_address
        self.parent_master_port = parent_master_port
        self.current_task: Optional["DistributedTask"] = None
        self.task_history: List[str] = []

    def is_top_level(self) -> bool:
        """Check if this hybrid node is the top-level master."""
        return self.parent_master_address is None

    def check_heartbeats(self):
        """Check the heartbeat of all nodes and mark them as OFFLINE if they haven't sent a heartbeat in the last 2 minutes."""
        current_time = datetime.now(timezone.utc).timestamp()
        nodes_to_mark_down = []

        for node_id, node in self.workers.items():
            # Skip if node is already marked as down
            if node.status == NodeStatus.OFFLINE:
                continue

            # Convert heartbeat to epoch time for comparison
            heartbeat_epoch = node.heartbeat.timestamp()

            # Check if heartbeat is too old (> 2 minutes)
            if current_time - heartbeat_epoch > 120:
                nodes_to_mark_down.append(node_id)

        # Mark nodes as down
        for node_id in nodes_to_mark_down:
            logger.warning(f"Node {node_id} heartbeat timed out, marking as OFFLINE")
            self.workers[node_id].status = NodeStatus.OFFLINE
