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
from typing import Any, Dict, List, Optional, Tuple, Union

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
    """Enum defining possible status values for tasks."""

    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class DistributedTask:
    """Represents a task to be executed by a worker node."""

    def __init__(
        self,
        task_type: str,
        target: Dict[str, Any],
        parameters: Dict[str, Any] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        timeout: int = 3600,  # Default timeout of 1 hour
        dependencies: List[str] = None,
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
        """
        self.id = str(uuid.uuid4())
        self.task_type = task_type
        self.target = target
        self.parameters = parameters or {}
        self.priority = priority
        self.timeout = timeout
        self.dependencies = dependencies or []
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.started_at = None
        self.completed_at = None
        self.assigned_node = None
        self.result = None
        self.error = None

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
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "assigned_node": self.assigned_node,
            "result": self.result,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DistributedTask":
        """Create a task from a dictionary."""
        task = cls(
            task_type=data["task_type"],
            target=data["target"],
            parameters=data["parameters"],
            priority=TaskPriority(data["priority"]),
            timeout=data["timeout"],
            dependencies=data["dependencies"],
        )
        task.id = data["id"]
        task.status = TaskStatus(data["status"])
        task.created_at = datetime.fromisoformat(data["created_at"])
        if data["started_at"]:
            task.started_at = datetime.fromisoformat(data["started_at"])
        if data["completed_at"]:
            task.completed_at = datetime.fromisoformat(data["completed_at"])
        task.assigned_node = data["assigned_node"]
        task.result = data["result"]
        task.error = data["error"]
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
        capabilities: List[str] = None,
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
        self.stats = {
            "cpu": 0.0,
            "memory": 0.0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "uptime": 0,
        }
        self.current_tasks = []

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
            capabilities=data["capabilities"],
        )
        node.status = NodeStatus(data["status"])
        node.heartbeat = datetime.fromisoformat(data["heartbeat"])
        node.stats = data["stats"]
        node.current_tasks = data["current_tasks"]
        return node


class BaseNode(abc.ABC):
    """Base class for both master and worker nodes."""

    def __init__(
        self,
        node_id: Optional[str] = None,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: int = 5000,
    ):
        """
        Initialize the base node.

        Args:
            node_id: Unique identifier for the node (auto-generated if None)
            hostname: Hostname of the node (auto-detected if None)
            address: IP address of the node (auto-detected if None)
            port: Port to listen on
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
    ):
        """Initialize the master node."""
        super().__init__(node_id, hostname, address, port)
        self.role = NodeRole.MASTER
        self.workers = {}  # Map of worker IDs to NodeInfo objects
        self.task_queue = []  # List of pending tasks
        self.active_tasks = {}  # Map of task IDs to assigned worker IDs
        self.completed_tasks = {}  # Map of task IDs to results
        self.failed_tasks = {}  # Map of task IDs to error messages

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
        capabilities: List[str] = None,
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
        super().__init__(node_id, hostname, address, port)
        self.role = NodeRole.WORKER
        self.master_address = master_address
        self.master_port = master_port
        self.capabilities = capabilities or ["port_scan", "web_scan", "subdomain_scan"]
        self.current_task = None
        self.task_history = []

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
        capabilities: List[str] = None,
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
        BaseNode.__init__(self, node_id, hostname, address, port)
        self.role = NodeRole.HYBRID
        self.capabilities = capabilities or ["port_scan", "web_scan", "subdomain_scan"]

        # Master components
        self.workers = {}
        self.task_queue = []
        self.active_tasks = {}
        self.completed_tasks = {}
        self.failed_tasks = {}

        # Worker components
        self.parent_master_address = parent_master_address
        self.parent_master_port = parent_master_port
        self.current_task = None
        self.task_history = []

    def is_top_level(self) -> bool:
        """Check if this hybrid node is the top-level master."""
        return self.parent_master_address is None
