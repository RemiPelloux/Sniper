"""
Worker Node Implementation for Sniper Security Tool

This module implements the worker node component of the distributed scanning architecture.
The worker node is responsible for:
1. Registering with master nodes
2. Executing scanning tasks assigned by master nodes
3. Reporting task status and results back to master nodes
4. Sending regular heartbeats to master nodes
5. Managing local resources and scan execution
"""

import asyncio
import json
import logging
import os
import platform
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import psutil

from src.core.logging import setup_logging
from src.distributed.base import (
    DistributedTask,
    NodeInfo,
    NodeStatus,
    TaskPriority,
    TaskStatus,
    WorkerNode,
)
from src.distributed.protocol import (
    HeartbeatMessage,
    MessageType,
    ProtocolBase,
    ProtocolMessage,
    RegisterMessage,
    TaskResultMessage,
    TaskStatusMessage,
    create_protocol,
)

logger = logging.getLogger("sniper.distributed.worker")


class SniperWorkerNode(WorkerNode):
    """
    Worker Node implementation for the Sniper Security Tool's distributed scanning architecture.

    Responsible for executing scanning tasks and reporting results to master nodes.
    """

    def __init__(
        self,
        master_host: str,
        master_port: int,
        worker_id: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 0,  # 0 means auto-assign
        protocol_type: str = "rest",
        capabilities: Optional[List[str]] = None,
        heartbeat_interval: int = 15,
        max_concurrent_tasks: int = 5,
        task_execution_timeout: int = 3600,  # 1 hour default timeout
    ):
        """
        Initialize the Sniper Worker Node.

        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            worker_id: Unique ID for this worker (auto-generated if not provided)
            host: Host address to bind this worker's server
            port: Port to listen on (0 for auto-assignment)
            protocol_type: Communication protocol type ('rest', 'grpc', etc.)
            capabilities: List of scan types/capabilities this worker supports
            heartbeat_interval: Interval in seconds for sending heartbeats to master
            max_concurrent_tasks: Maximum number of tasks to execute concurrently
            task_execution_timeout: Maximum execution time for a task in seconds
        """
        # Call the parent class constructor with the required parameters
        super().__init__(
            master_address=master_host,
            master_port=master_port,
            node_id=worker_id,
            hostname=host,
            address=host,
            port=port,
            capabilities=capabilities or ["nmap", "basic"],
        )

        # Protocol
        self.protocol_type = protocol_type
        self.protocol = create_protocol(protocol_type, master_host, master_port)

        # Task execution
        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_execution_timeout = task_execution_timeout
        self.task_executors: Dict[str, Callable] = {
            "nmap_scan": self._execute_nmap_scan,
            "vulnerability_scan": self._execute_vulnerability_scan,
            "web_scan": self._execute_web_scan,
            "port_scan": self._execute_port_scan,
            "default": self._execute_default_task,
        }

        # Task management
        self.tasks: Dict[str, DistributedTask] = {}
        self.task_lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_tasks)
        self.future_tasks: Dict[str, asyncio.Future] = {}

        # Heartbeat and monitoring
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_thread = None
        self.running = False

        # Server for receiving task assignments
        self.server = None
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageType.CANCEL_TASK: self._handle_cancel_task,
            MessageType.SHUTDOWN: self._handle_shutdown,
        }

        # Override the attributes from the parent class
        self.master_address = master_host  # Renamed in our implementation

    def register_with_master(self) -> bool:
        """
        Register this worker with the master node.

        Returns:
            True if registration was successful, False otherwise
        """
        return self._register_with_master()

    def get_task(self) -> Optional[DistributedTask]:
        """
        Request a task from the master.

        Returns:
            Task to execute, or None if no tasks are available
        """
        # In our implementation, tasks are pushed to workers
        # rather than pulled by workers, so this is a placeholder
        logger.debug("get_task is not implemented as we use a push model")
        return None

    def execute_task(self, task: DistributedTask) -> Dict[str, Any]:
        """
        Execute a task.

        Args:
            task: Task to execute

        Returns:
            Result of the task execution
        """
        # Get the appropriate executor for the task type
        executor = self.task_executors.get(
            task.task_type, self.task_executors["default"]
        )

        # Execute the task
        result = executor(task)
        return result

    def send_result(self, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Send a task result back to the master.

        Args:
            task_id: ID of the completed task
            result: Result data

        Returns:
            Whether the result was successfully sent
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot send result for unknown task {task_id}")
                return False

            task = self.tasks[task_id]

        # Send the result to the master
        self._send_task_result(task_id, TaskStatus.COMPLETED, result)
        return True

    def send_heartbeat(self) -> bool:
        """
        Send a heartbeat message to the master.

        Returns:
            Whether the heartbeat was successfully sent
        """
        self._send_heartbeat()
        return True

    def status_update(self) -> Dict[str, Any]:
        """
        Get status information about the node.

        Returns:
            Dictionary with current status information
        """
        with self.task_lock:
            current_tasks = sum(
                1 for task in self.tasks.values() if task.status == TaskStatus.RUNNING
            )

        # Get current system metrics
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent

        return {
            "id": self.id,
            "status": self.status.value,
            "running_tasks": current_tasks,
            "max_tasks": self.max_concurrent_tasks,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "uptime": self.uptime(),
        }

    def start(self):
        """Start the worker node, connect to master, and begin processing tasks."""
        if self.running:
            logger.warning("Worker node is already running")
            return

        logger.info(f"Starting Sniper Worker Node {self.id}")
        self.running = True

        # Register with master
        success = self.register_with_master()
        if not success:
            logger.error("Failed to register with master node")
            self.running = False
            return False

        # Start heartbeat thread
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True
        )
        self.heartbeat_thread.start()

        # Start the server based on protocol type
        try:
            if self.protocol_type == "rest":
                self._start_rest_server()
            else:
                raise NotImplementedError(
                    f"Protocol {self.protocol_type} not implemented yet"
                )

            logger.info(f"Worker node {self.id} started successfully")
            return True
        except Exception as e:
            self.running = False
            logger.error(f"Failed to start worker node: {e}")
            return False

    def stop(self):
        """Stop the worker node and cleanup resources."""
        if not self.running:
            logger.warning("Worker node is not running")
            return

        logger.info(f"Stopping worker node {self.id}")
        self.running = False

        # Cancel any running tasks
        with self.task_lock:
            for task_id, task in list(self.tasks.items()):
                if task.status == TaskStatus.RUNNING:
                    self._cancel_task(task_id)

        # Stop the server
        if self.server:
            self._stop_server()

        # Wait for heartbeat thread to finish
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)

        # Shutdown executor
        self.executor.shutdown(wait=False)

        logger.info(f"Worker node {self.id} stopped")

    def _register_with_master(self) -> bool:
        """
        Register this worker with the master node.

        Returns:
            True if registration was successful, False otherwise
        """
        logger.info(
            f"Registering with master node at {self.master_address}:{self.master_port}"
        )

        # System info for registration
        system_info = {
            "platform": platform.system(),
            "processor": platform.processor(),
            "memory": psutil.virtual_memory().total,
            "cores": os.cpu_count(),
        }

        # Build registration message
        payload = {
            "host": self.address,
            "port": self.port,
            "capabilities": self.capabilities,
            "system_info": system_info,
        }

        register_msg = RegisterMessage(
            sender_id=self.id, receiver_id="master", payload=payload
        )

        # In a real implementation, this would use the protocol to send
        # the registration message to the master
        # For now, we'll just assume it worked

        logger.info(f"Registered with master node as worker {self.id}")
        self.status = NodeStatus.ACTIVE
        return True

    def _start_rest_server(self):
        """Start the REST server for the worker node."""
        # This would be implemented with a web framework like FastAPI or Flask
        # For now, we'll use a placeholder method
        logger.info(f"Starting REST server on {self.address}:{self.port}")

        # Placeholder for actual server implementation
        self.server = {"status": "running", "type": "rest"}

        # In a real implementation, this would be:
        # from src.distributed.rest import create_worker_app
        # app = create_worker_app(self)
        # self.server = uvicorn.run(app, host=self.address, port=self.port)

    def _stop_server(self):
        """Stop the server."""
        logger.info("Stopping server")
        # Placeholder for actual server stop implementation
        self.server = None

    def _heartbeat_loop(self):
        """Background thread for sending periodic heartbeats to the master."""
        logger.info("Starting heartbeat loop")
        while self.running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")

            time.sleep(self.heartbeat_interval)

    def _send_heartbeat(self):
        """Send a heartbeat message to the master node."""
        # Get current system metrics
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent

        # Count current tasks
        with self.task_lock:
            current_tasks = sum(
                1 for task in self.tasks.values() if task.status == TaskStatus.RUNNING
            )

        # Build heartbeat message
        payload = {
            "current_load": (cpu_percent + memory_percent)
            / 2,  # Simple load calculation
            "current_tasks": current_tasks,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
        }

        heartbeat_msg = HeartbeatMessage(
            sender_id=self.id, receiver_id="master", payload=payload
        )

        # In a real implementation, this would use the protocol to send
        # the heartbeat message to the master
        # For now, we'll just log it
        logger.debug(
            f"Sent heartbeat to master: load={payload['current_load']:.1f}%, tasks={current_tasks}"
        )

    def _handle_message(self, message: ProtocolMessage):
        """
        Handle incoming messages from the master node.

        Args:
            message: The received message
        """
        if message.message_type in self._message_handlers:
            handler = self._message_handlers[message.message_type]
            handler(message)
        else:
            logger.warning(f"No handler for message type {message.message_type}")

    def _handle_task_assignment(self, message: ProtocolMessage):
        """Handle task assignment message from master."""
        task_data = message.payload.get("task")
        if not task_data:
            logger.warning("Received task assignment without task data")
            return

        try:
            # Create task object from message payload
            task_id = task_data.get("id")
            task_type = task_data.get("task_type")

            # Check if we have the required capability
            if task_type not in self.capabilities:
                logger.warning(
                    f"Received task of type {task_type} but worker doesn't have this capability"
                )
                self._send_task_status(
                    task_id, TaskStatus.FAILED, f"Worker doesn't support {task_type}"
                )
                return

            # Check if we're at capacity
            with self.task_lock:
                if len(self.tasks) >= self.max_concurrent_tasks:
                    logger.warning("Rejecting task assignment - worker at capacity")
                    self._send_task_status(
                        task_id, TaskStatus.FAILED, "Worker at capacity"
                    )
                    return

            # Parse priority (default to MEDIUM if not specified)
            priority_value = task_data.get("priority", TaskPriority.MEDIUM.value)
            priority = TaskPriority(priority_value)

            # Extract target information
            target = task_data.get("target", {})
            if isinstance(target, str):
                # Convert string target to dictionary format
                target = {"host": target}

            # Create the task
            task = DistributedTask(
                task_type=task_type,
                target=target,
                parameters=task_data.get("parameters", {}),
                priority=priority,
            )

            # Set the task ID if provided
            if task_id:
                task.id = task_id

            # Update task status
            task.status = TaskStatus.ASSIGNED
            task.assigned_node = self.id

            # Add task to our task list
            with self.task_lock:
                self.tasks[task.id] = task

            # Send acceptance back to master
            self._send_task_status(task.id, TaskStatus.ASSIGNED)

            # Start task execution
            self._execute_task(task.id)

        except Exception as e:
            logger.error(f"Error processing task assignment: {str(e)}")
            if task_data and "id" in task_data:
                self._send_task_status(
                    task_data["id"], TaskStatus.FAILED, f"Error: {str(e)}"
                )

    def _handle_cancel_task(self, message: ProtocolMessage):
        """Handle task cancellation message from master."""
        task_id = message.payload.get("task_id")
        if not task_id:
            logger.warning("Received cancel task without task_id")
            return

        logger.info(f"Received cancellation request for task {task_id}")

        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot cancel unknown task {task_id}")
                return

            self._cancel_task(task_id)

    def _handle_shutdown(self, message: ProtocolMessage):
        """Handle shutdown message from master."""
        logger.info("Received shutdown request from master")
        grace_period = message.payload.get("grace_period", 30)

        # Graceful shutdown
        threading.Thread(
            target=self._graceful_shutdown, args=(grace_period,), daemon=True
        ).start()

    def _graceful_shutdown(self, grace_period: int):
        """
        Perform a graceful shutdown after finishing current tasks.

        Args:
            grace_period: Grace period in seconds before forced shutdown
        """
        logger.info(f"Initiating graceful shutdown with {grace_period}s grace period")

        # Stop accepting new tasks
        self.status = NodeStatus.DRAINING

        # Set shutdown timer
        shutdown_time = time.time() + grace_period

        # Wait for running tasks to complete
        while time.time() < shutdown_time:
            with self.task_lock:
                running_tasks = sum(
                    1
                    for task in self.tasks.values()
                    if task.status == TaskStatus.RUNNING
                )

            if running_tasks == 0:
                logger.info("All tasks completed, shutting down")
                break

            logger.info(
                f"Waiting for {running_tasks} tasks to complete before shutdown"
            )
            time.sleep(5)

        # Stop the worker
        self.stop()

    def _execute_task(self, task_id: str):
        """
        Execute a task asynchronously.

        Args:
            task_id: ID of the task to execute
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot execute unknown task {task_id}")
                return

            task = self.tasks[task_id]
            task.status = TaskStatus.RUNNING
            task.start_time = datetime.now(timezone.utc)

            logger.info(
                f"Starting execution of task {task_id} (type: {task.task_type})"
            )

            # Send status update to master
            self._send_task_status(task_id, TaskStatus.RUNNING)

            # Submit task to thread pool
            future = self.executor.submit(self._task_worker, task_id)
            self.future_tasks[task_id] = future

    def _task_worker(self, task_id: str):
        """
        Worker function that executes a task.

        Args:
            task_id: ID of the task to execute
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Task {task_id} no longer exists")
                return

            task = self.tasks[task_id]

        result = None
        error = None
        status = TaskStatus.COMPLETED

        try:
            # Get the appropriate executor for the task type
            executor = self.task_executors.get(
                task.task_type, self.task_executors["default"]
            )

            # Execute the task with timeout
            result = executor(task)

            logger.info(f"Task {task_id} completed successfully")
        except asyncio.TimeoutError:
            error = "Task execution timed out"
            status = TaskStatus.FAILED
            logger.error(
                f"Task {task_id} timed out after {self.task_execution_timeout} seconds"
            )
        except Exception as e:
            error = str(e)
            status = TaskStatus.FAILED
            logger.error(f"Error executing task {task_id}: {e}")

        # Update task status
        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = status
                task.result = result
                task.error = error
                task.end_time = datetime.now(timezone.utc)

                # Remove the future
                self.future_tasks.pop(task_id, None)

                # Send result to master
                self._send_task_result(task_id, status, result, error)

                # Remove the task
                del self.tasks[task_id]

    def _cancel_task(self, task_id: str):
        """
        Cancel a running task.

        Args:
            task_id: ID of the task to cancel
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot cancel unknown task {task_id}")
                return

            task = self.tasks[task_id]

            # Cancel the future if it exists
            future = self.future_tasks.pop(task_id, None)
            if future and not future.done():
                future.cancel()
                logger.info(f"Cancelled task {task_id}")

            # Update task status
            task.status = TaskStatus.CANCELED

            # Remove the task
            self.tasks.pop(task_id, None)

            # Send task status update to master
            self._send_task_status(
                task_id, TaskStatus.CANCELED, "Task cancelled by worker"
            )

    def _send_task_status(self, task_id: str, status: TaskStatus, message: str = ""):
        """
        Send a task status update to the master.

        Args:
            task_id: ID of the task
            status: New status of the task
            message: Optional status message
        """
        payload = {"task_id": task_id, "status": status.value, "message": message}

        status_msg = TaskStatusMessage(
            sender_id=self.id, receiver_id="master", payload=payload
        )

        # In a real implementation, this would use the protocol to send
        # the status message to the master
        # For now, we'll just log it
        logger.debug(f"Sent status update for task {task_id}: {status.name}")

    def _send_task_result(
        self, task_id: str, status: TaskStatus, result=None, error=None
    ):
        """
        Send task result to the master.

        Args:
            task_id: ID of the task
            status: Final status of the task
            result: Task execution result
            error: Error message if task failed
        """
        payload = {
            "task_id": task_id,
            "status": status.value,
            "result": result,
            "error": error,
        }

        result_msg = TaskResultMessage(
            sender_id=self.id, receiver_id="master", payload=payload
        )

        # In a real implementation, this would use the protocol to send
        # the result message to the master
        # For now, we'll just log it
        logger.info(f"Sent result for task {task_id}: status={status.name}")

    # Task execution methods
    def _execute_default_task(self, task: DistributedTask):
        """Default task executor for unknown task types."""
        logger.warning(f"Using default executor for task type: {task.task_type}")
        time.sleep(1)  # Simulate work
        return {"status": "completed", "message": f"Executed {task.task_type} task"}

    def _execute_nmap_scan(self, task: DistributedTask):
        """Execute an nmap scan task."""
        logger.info(f"Executing nmap scan: {task.parameters}")
        target = task.parameters.get("target", "")
        scan_type = task.parameters.get("scan_type", "basic")

        # Simulate nmap scan
        time.sleep(2)  # Simulate work

        # Return simulated results
        return {
            "target": target,
            "scan_type": scan_type,
            "ports": [22, 80, 443] if scan_type != "quick" else [80],
            "open_services": (
                {"22": "ssh", "80": "http", "443": "https"}
                if scan_type != "quick"
                else {"80": "http"}
            ),
        }

    def _execute_vulnerability_scan(self, task: DistributedTask):
        """Execute a vulnerability scan task."""
        logger.info(f"Executing vulnerability scan: {task.parameters}")
        target = task.parameters.get("target", "")
        depth = task.parameters.get("depth", "normal")

        # Simulate vulnerability scan
        scan_time = 5 if depth == "deep" else 2
        time.sleep(scan_time)  # Simulate work

        # Return simulated results
        return {
            "target": target,
            "depth": depth,
            "vulnerabilities": (
                [
                    {
                        "id": "CVE-2023-1234",
                        "severity": "high",
                        "description": "Remote code execution vulnerability",
                    },
                    {
                        "id": "CVE-2023-5678",
                        "severity": "medium",
                        "description": "Information disclosure vulnerability",
                    },
                ]
                if depth == "deep"
                else [
                    {
                        "id": "CVE-2023-1234",
                        "severity": "high",
                        "description": "Remote code execution vulnerability",
                    }
                ]
            ),
        }

    def _execute_web_scan(self, task: DistributedTask):
        """Execute a web scan task."""
        logger.info(f"Executing web scan: {task.parameters}")
        target = task.parameters.get("target", "")
        scan_depth = task.parameters.get("scan_depth", 1)

        # Simulate web scan
        time.sleep(scan_depth * 2)  # Simulate work

        # Return simulated results
        return {
            "target": target,
            "scan_depth": scan_depth,
            "findings": (
                [
                    {
                        "type": "xss",
                        "severity": "high",
                        "path": "/search",
                        "description": "Reflected XSS vulnerability",
                    },
                    {
                        "type": "sqli",
                        "severity": "critical",
                        "path": "/login",
                        "description": "SQL injection vulnerability",
                    },
                ]
                if scan_depth > 1
                else [
                    {
                        "type": "xss",
                        "severity": "high",
                        "path": "/search",
                        "description": "Reflected XSS vulnerability",
                    }
                ]
            ),
        }

    def _execute_port_scan(self, task: DistributedTask):
        """Execute a port scan task."""
        logger.info(f"Executing port scan: {task.parameters}")
        target = task.parameters.get("target", "")
        port_range = task.parameters.get("port_range", "1-1000")

        # Simulate port scan
        time.sleep(1)  # Simulate work

        # Parse port range
        try:
            start, end = port_range.split("-")
            start, end = int(start), int(end)
        except ValueError:
            start, end = 1, 1000

        # Return simulated results
        return {
            "target": target,
            "port_range": port_range,
            "open_ports": [22, 80, 443, 3306] if end > 3000 else [22, 80, 443],
        }


class WorkerNodeClient:
    """
    Client wrapper for the Sniper Worker Node, handling configuration and startup.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        master_host: str = "localhost",
        master_port: int = 5555,
        worker_id: Optional[str] = None,
        protocol_type: str = "rest",
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize the worker node client with configuration.

        Args:
            config_path: Optional path to configuration file
            master_host: Host address of the master node
            master_port: Port of the master node
            worker_id: Unique ID for this worker
            protocol_type: Communication protocol type
            capabilities: List of scan types/capabilities this worker supports
        """
        # Set up logging
        setup_logging()

        # Load configuration from file if provided
        if config_path:
            # In a real implementation, this would load config from file
            pass

        # Determine worker capabilities
        if capabilities is None:
            capabilities = self._detect_capabilities()

        # Create the worker node
        self.worker_node = SniperWorkerNode(
            master_host=master_host,
            master_port=master_port,
            worker_id=worker_id,
            protocol_type=protocol_type,
            capabilities=capabilities,
        )

    def _detect_capabilities(self) -> List[str]:
        """
        Detect the capabilities of this worker based on installed tools.

        Returns:
            List of supported scan types/capabilities
        """
        capabilities = ["basic"]

        # In a real implementation, this would detect installed tools
        # For now, we'll return a default set
        return ["nmap", "port_scan", "basic"]

    def start(self) -> bool:
        """
        Start the worker node.

        Returns:
            True if started successfully, False otherwise
        """
        return self.worker_node.start()

    def stop(self):
        """Stop the worker node."""
        self.worker_node.stop()
