"""
Master Node Implementation for Sniper Security Tool

This module implements the master node component of the distributed scanning architecture.
The master node is responsible for:
1. Managing worker node connections and capabilities
2. Distributing scanning tasks to appropriate workers
3. Aggregating and processing scan results
4. Monitoring worker node health
5. Implementing fault tolerance mechanisms
6. Optimizing resource utilization across the distributed system
"""

import asyncio
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Union

from src.core.logging import setup_logger
from src.distributed.base import (
    DistributedTask,
    MasterNode,
    NodeInfo,
    NodeStatus,
    TaskPriority,
    TaskStatus,
)
from src.distributed.distribution import (
    CapabilityBasedDistribution,
    DistributionAlgorithm,
    DistributionStrategy,
    LoadBalancedDistribution,
    PriorityBasedDistribution,
    RoundRobinDistribution,
    SmartDistribution,
    WorkerMetrics,
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

logger = logging.getLogger("sniper.distributed.master")


class SniperMasterNode(MasterNode):
    """
    Master Node implementation for the Sniper Security Tool's distributed scanning architecture.

    Responsible for managing worker nodes, distributing tasks, and aggregating results.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5555,
        protocol_type: str = "rest",
        distribution_strategy: DistributionStrategy = DistributionStrategy.SMART,
        worker_timeout: int = 60,
        cleanup_interval: int = 30,
        task_retry_limit: int = 3,
        result_callback=None,
    ):
        """
        Initialize the Sniper Master Node.

        Args:
            host: Host address to bind the master node server
            port: Port to listen on
            protocol_type: Communication protocol type ('rest', 'grpc', etc.)
            distribution_strategy: Strategy for distributing tasks to workers
            worker_timeout: Seconds after which a worker is considered offline if no heartbeat
            cleanup_interval: Interval in seconds for cleaning up dead workers and stale tasks
            task_retry_limit: Maximum number of retries for failed tasks
            result_callback: Optional callback function to process task results
        """
        super().__init__(host, port)
        self.protocol_type = protocol_type
        self.protocol = create_protocol(protocol_type)

        # Worker management
        self.workers: Dict[str, NodeInfo] = {}
        self.worker_metrics: Dict[str, WorkerMetrics] = {}
        self.worker_lock = threading.RLock()
        self.worker_timeout = worker_timeout

        # Task management
        self.tasks: Dict[str, DistributedTask] = {}
        self.pending_tasks: List[DistributedTask] = []
        self.completed_tasks: Dict[str, DistributedTask] = {}
        self.task_lock = threading.RLock()
        self.task_retry_limit = task_retry_limit

        # Distribution algorithm
        self.distribution_strategy = distribution_strategy
        self.distribution_algorithm = self._create_distribution_algorithm(
            distribution_strategy
        )

        # Cleanup and maintenance
        self.cleanup_interval = cleanup_interval
        self.running = False
        self.cleanup_thread = None

        # Result handling
        self.result_callback = result_callback
        self.executor = ThreadPoolExecutor(max_workers=10)

        # Server and handlers
        self.server = None
        self._message_handlers = {
            MessageType.REGISTER: self._handle_register,
            MessageType.HEARTBEAT: self._handle_heartbeat,
            MessageType.TASK_STATUS: self._handle_task_status,
            MessageType.TASK_RESULT: self._handle_task_result,
        }

    def _create_distribution_algorithm(
        self, strategy: DistributionStrategy
    ) -> DistributionAlgorithm:
        """Create the distribution algorithm based on the specified strategy."""
        if strategy == DistributionStrategy.ROUND_ROBIN:
            return RoundRobinDistribution()
        elif strategy == DistributionStrategy.PRIORITY_BASED:
            return PriorityBasedDistribution()
        elif strategy == DistributionStrategy.CAPABILITY_BASED:
            return CapabilityBasedDistribution()
        elif strategy == DistributionStrategy.LOAD_BALANCED:
            return LoadBalancedDistribution()
        elif strategy == DistributionStrategy.SMART:
            return SmartDistribution()
        else:
            logger.warning(
                f"Unknown distribution strategy: {strategy}, using SMART as default"
            )
            return SmartDistribution()

    def start(self):
        """Start the master node server and maintenance threads."""
        if self.running:
            logger.warning("Master node is already running")
            return

        logger.info(f"Starting Sniper Master Node on {self.host}:{self.port}")
        self.running = True

        # Start the cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        # Start the server based on protocol type
        try:
            if self.protocol_type == "rest":
                self._start_rest_server()
            else:
                raise NotImplementedError(
                    f"Protocol {self.protocol_type} not implemented yet"
                )
        except Exception as e:
            self.running = False
            logger.error(f"Failed to start master node: {e}")
            raise

    def stop(self):
        """Stop the master node server and cleanup resources."""
        if not self.running:
            logger.warning("Master node is not running")
            return

        logger.info("Stopping Sniper Master Node")
        self.running = False

        # Stop the server
        if self.server:
            self._stop_server()

        # Wait for cleanup thread to finish
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)

        # Shutdown executor
        self.executor.shutdown(wait=False)

        logger.info("Master node stopped")

    def _start_rest_server(self):
        """Start the REST server for the master node."""
        # This would be implemented with a web framework like FastAPI or Flask
        # For now, we'll use a placeholder method
        logger.info(f"Starting REST server on {self.host}:{self.port}")

        # Placeholder for actual server implementation
        self.server = {"status": "running", "type": "rest"}

        # In a real implementation, this would be:
        # from src.distributed.rest import create_master_app
        # app = create_master_app(self)
        # self.server = uvicorn.run(app, host=self.host, port=self.port)

    def _stop_server(self):
        """Stop the server."""
        logger.info("Stopping server")
        # Placeholder for actual server stop implementation
        self.server = None

    def _cleanup_loop(self):
        """Background thread for cleaning up stale workers and tasks."""
        logger.info("Starting worker and task cleanup loop")
        while self.running:
            try:
                self._cleanup_workers()
                self._cleanup_tasks()
                self._distribute_pending_tasks()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

            time.sleep(self.cleanup_interval)

    def _cleanup_workers(self):
        """Remove workers that haven't sent a heartbeat within the timeout period."""
        with self.worker_lock:
            current_time = time.time()
            stale_workers = []

            for worker_id, worker_info in self.workers.items():
                if worker_info.status == NodeStatus.ACTIVE:
                    last_heartbeat = self.worker_metrics[worker_id].last_heartbeat
                    if current_time - last_heartbeat > self.worker_timeout:
                        logger.warning(
                            f"Worker {worker_id} timed out (last heartbeat: {datetime.fromtimestamp(last_heartbeat)})"
                        )
                        worker_info.status = NodeStatus.OFFLINE
                        stale_workers.append(worker_id)

            # Handle tasks assigned to stale workers
            for worker_id in stale_workers:
                self._handle_worker_failure(worker_id)

    def _handle_worker_failure(self, worker_id: str):
        """Handle tasks assigned to a failed worker."""
        with self.task_lock:
            reassigned_tasks = 0
            for task_id, task in list(self.tasks.items()):
                if task.assigned_node == worker_id:
                    logger.info(
                        f"Reassigning task {task_id} from failed worker {worker_id}"
                    )
                    task.assigned_node = None
                    task.status = TaskStatus.PENDING
                    task.retries += 1

                    if task.retries <= self.task_retry_limit:
                        self.pending_tasks.append(task)
                        reassigned_tasks += 1
                    else:
                        logger.warning(
                            f"Task {task_id} exceeded retry limit, marking as failed"
                        )
                        task.status = TaskStatus.FAILED
                        task.end_time = datetime.now(timezone.utc)
                        self.completed_tasks[task_id] = task
                        del self.tasks[task_id]

            if reassigned_tasks > 0:
                logger.info(
                    f"Reassigned {reassigned_tasks} tasks from failed worker {worker_id}"
                )

    def _cleanup_tasks(self):
        """Clean up stale tasks that have been running too long."""
        with self.task_lock:
            current_time = datetime.now(timezone.utc)
            for task_id, task in list(self.tasks.items()):
                # If a task has been running for more than 30 minutes, consider it stale
                if (
                    task.status == TaskStatus.RUNNING
                    and task.start_time
                    and (current_time - task.start_time).total_seconds() > 1800
                ):
                    logger.warning(
                        f"Task {task_id} has been running too long, marking for retry"
                    )
                    task.assigned_node = None
                    task.status = TaskStatus.PENDING
                    task.retries += 1

                    if task.retries <= self.task_retry_limit:
                        self.pending_tasks.append(task)
                    else:
                        logger.warning(
                            f"Task {task_id} exceeded retry limit, marking as failed"
                        )
                        task.status = TaskStatus.FAILED
                        task.end_time = datetime.now(timezone.utc)
                        self.completed_tasks[task_id] = task
                        del self.tasks[task_id]

    def _distribute_pending_tasks(self):
        """Distribute pending tasks to available workers."""
        with self.task_lock, self.worker_lock:
            if not self.pending_tasks:
                return

            if not any(w.status == NodeStatus.ACTIVE for w in self.workers.values()):
                logger.warning("No active workers available for task distribution")
                return

            logger.info(f"Distributing {len(self.pending_tasks)} pending tasks")

            # Prepare worker metrics
            worker_metrics = {
                worker_id: self.worker_metrics[worker_id]
                for worker_id, worker_info in self.workers.items()
                if worker_info.status == NodeStatus.ACTIVE
            }

            # Distribute tasks
            distribution_results = self.distribution_algorithm.distribute(
                self.pending_tasks, self.workers, worker_metrics
            )

            # Process distribution results
            distributed_count = 0
            for task_id, worker_id in distribution_results.items():
                task = next((t for t in self.pending_tasks if t.id == task_id), None)
                if task and worker_id:
                    distributed_count += 1
                    task.assigned_node = worker_id
                    task.status = TaskStatus.ASSIGNED
                    self._send_task_to_worker(task, worker_id)

            # Remove distributed tasks from pending list
            self.pending_tasks = [
                task
                for task in self.pending_tasks
                if task.id not in distribution_results
                or distribution_results[task.id] is None
            ]

            logger.info(f"Distributed {distributed_count} tasks to workers")

    def _send_task_to_worker(self, task: DistributedTask, worker_id: str):
        """Send a task to a worker node."""
        worker_info = self.workers.get(worker_id)
        if not worker_info:
            logger.error(f"Worker {worker_id} not found")
            return False

        logger.info(
            f"Sending task {task.id} to worker {worker_id} ({worker_info.host}:{worker_info.port})"
        )

        # In a real implementation, this would use the actual protocol
        # to send the task to the worker
        # For now, we'll just log it and update our local state
        task.status = TaskStatus.ASSIGNED

        # Update metrics
        with self.worker_lock:
            metrics = self.worker_metrics.get(worker_id)
            if metrics:
                metrics.current_tasks += 1
                metrics.total_assigned += 1

        return True

    def add_task(self, task: DistributedTask) -> str:
        """
        Add a new task to be distributed among workers.

        Args:
            task: The task to be distributed

        Returns:
            The task ID
        """
        if not task.id:
            task.id = str(uuid.uuid4())

        with self.task_lock:
            task.status = TaskStatus.PENDING
            self.tasks[task.id] = task
            self.pending_tasks.append(task)
            logger.info(
                f"Added new task {task.id} of type {task.task_type} with priority {task.priority}"
            )

        return task.id

    def add_tasks(self, tasks: List[DistributedTask]) -> List[str]:
        """
        Add multiple tasks to be distributed.

        Args:
            tasks: List of tasks to be distributed

        Returns:
            List of task IDs
        """
        task_ids = []
        with self.task_lock:
            for task in tasks:
                if not task.id:
                    task.id = str(uuid.uuid4())

                task.status = TaskStatus.PENDING
                self.tasks[task.id] = task
                self.pending_tasks.append(task)
                task_ids.append(task.id)

            logger.info(f"Added {len(tasks)} new tasks")

        return task_ids

    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """
        Get the current status of a task.

        Args:
            task_id: The ID of the task

        Returns:
            The task status or None if task not found
        """
        with self.task_lock:
            if task_id in self.tasks:
                return self.tasks[task_id].status
            elif task_id in self.completed_tasks:
                return self.completed_tasks[task_id].status
            else:
                return None

    def get_active_workers(self) -> List[NodeInfo]:
        """
        Get a list of currently active worker nodes.

        Returns:
            List of active worker node information
        """
        with self.worker_lock:
            return [
                worker_info
                for worker_info in self.workers.values()
                if worker_info.status == NodeStatus.ACTIVE
            ]

    def get_worker_metrics(self) -> Dict[str, WorkerMetrics]:
        """
        Get metrics for all workers.

        Returns:
            Dictionary mapping worker IDs to their metrics
        """
        with self.worker_lock:
            return self.worker_metrics.copy()

    def _handle_message(self, message: ProtocolMessage):
        """
        Handle incoming messages from worker nodes.

        Args:
            message: The received message
        """
        handler = self._message_handlers.get(message.message_type)
        if handler:
            handler(message)
        else:
            logger.warning(f"No handler for message type {message.message_type}")

    def _handle_register(self, message: RegisterMessage):
        """Handle worker registration message."""
        worker_id = message.sender_id
        capabilities = message.payload.get("capabilities", [])
        host = message.payload.get("host")
        port = message.payload.get("port")

        with self.worker_lock:
            if worker_id in self.workers:
                logger.info(
                    f"Worker {worker_id} re-registered with capabilities: {capabilities}"
                )
                self.workers[worker_id].status = NodeStatus.ACTIVE
                self.workers[worker_id].capabilities = capabilities
                self.workers[worker_id].last_updated = datetime.now(timezone.utc)
            else:
                logger.info(
                    f"New worker {worker_id} registered with capabilities: {capabilities}"
                )
                worker_info = NodeInfo(
                    id=worker_id,
                    host=host,
                    port=port,
                    status=NodeStatus.ACTIVE,
                    capabilities=capabilities,
                    created_at=datetime.now(timezone.utc),
                    last_updated=datetime.now(timezone.utc),
                )
                self.workers[worker_id] = worker_info

                # Initialize metrics for the new worker
                self.worker_metrics[worker_id] = WorkerMetrics(
                    current_tasks=0,
                    total_assigned=0,
                    success_count=0,
                    failure_count=0,
                    total_execution_time=0,
                    avg_response_time=0,
                    last_heartbeat=time.time(),
                )

    def _handle_heartbeat(self, message: HeartbeatMessage):
        """Handle worker heartbeat message."""
        worker_id = message.sender_id
        current_load = message.payload.get("current_load", 0)
        current_tasks = message.payload.get("current_tasks", 0)

        with self.worker_lock:
            if worker_id in self.workers:
                worker_info = self.workers[worker_id]
                worker_info.status = NodeStatus.ACTIVE
                worker_info.last_updated = datetime.now(timezone.utc)

                # Update metrics
                if worker_id in self.worker_metrics:
                    metrics = self.worker_metrics[worker_id]
                    metrics.current_load = current_load
                    metrics.current_tasks = current_tasks
                    metrics.last_heartbeat = time.time()

                    logger.debug(
                        f"Received heartbeat from worker {worker_id}, load: {current_load}, tasks: {current_tasks}"
                    )
            else:
                logger.warning(f"Received heartbeat from unknown worker {worker_id}")

    def _handle_task_status(self, message: TaskStatusMessage):
        """Handle task status update message."""
        worker_id = message.sender_id
        task_id = message.payload.get("task_id")
        status = message.payload.get("status")

        if not task_id or not status:
            logger.warning(
                f"Invalid task status message from {worker_id}: missing task_id or status"
            )
            return

        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = TaskStatus(status)
                task.last_updated = datetime.now(timezone.utc)

                if status == TaskStatus.RUNNING.value:
                    if not task.start_time:
                        task.start_time = datetime.now(timezone.utc)
                        logger.info(f"Task {task_id} started by worker {worker_id}")
                elif status in (TaskStatus.COMPLETED.value, TaskStatus.FAILED.value):
                    task.end_time = datetime.now(timezone.utc)

                    # Update worker metrics
                    with self.worker_lock:
                        if worker_id in self.worker_metrics:
                            metrics = self.worker_metrics[worker_id]
                            metrics.current_tasks = max(0, metrics.current_tasks - 1)

                            if status == TaskStatus.COMPLETED.value:
                                metrics.success_count += 1
                            else:
                                metrics.failure_count += 1

                            if task.start_time and task.end_time:
                                execution_time = (
                                    task.end_time - task.start_time
                                ).total_seconds()
                                metrics.total_execution_time += execution_time
                                # Update average response time
                                total_tasks = (
                                    metrics.success_count + metrics.failure_count
                                )
                                if total_tasks > 0:
                                    metrics.avg_response_time = (
                                        metrics.total_execution_time / total_tasks
                                    )
            else:
                logger.warning(
                    f"Status update for unknown task {task_id} from worker {worker_id}"
                )

    def _handle_task_result(self, message: TaskResultMessage):
        """Handle task result message."""
        worker_id = message.sender_id
        task_id = message.payload.get("task_id")
        status = message.payload.get("status")
        result = message.payload.get("result")
        error = message.payload.get("error")

        if not task_id:
            logger.warning(
                f"Invalid task result message from {worker_id}: missing task_id"
            )
            return

        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = TaskStatus(status) if status else TaskStatus.COMPLETED
                task.result = result
                task.error = error
                task.end_time = datetime.now(timezone.utc)

                # Move to completed tasks
                self.completed_tasks[task_id] = task
                del self.tasks[task_id]

                logger.info(
                    f"Task {task_id} completed by worker {worker_id} with status {task.status}"
                )

                # Process result with callback if provided
                if self.result_callback and not error:
                    self.executor.submit(self._process_result, task_id, result)
            else:
                logger.warning(
                    f"Result for unknown task {task_id} from worker {worker_id}"
                )

    def _process_result(self, task_id: str, result):
        """Process a task result using the callback function."""
        try:
            if self.result_callback:
                self.result_callback(task_id, result)
        except Exception as e:
            logger.error(f"Error processing result for task {task_id}: {e}")


class MasterNodeServer:
    """
    Server wrapper for the Sniper Master Node, handling configuration and startup.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 5555,
        protocol_type: str = "rest",
        distribution_strategy: str = "smart",
        worker_timeout: int = 60,
        result_callback=None,
    ):
        """
        Initialize the master node server with configuration.

        Args:
            config_path: Optional path to configuration file
            host: Host address to bind the master node server
            port: Port to listen on
            protocol_type: Communication protocol type
            distribution_strategy: Strategy for distributing tasks
            worker_timeout: Seconds after which a worker is considered offline
            result_callback: Optional callback function to process task results
        """
        # Set up logging
        setup_logger("sniper.distributed", log_level=logging.INFO)

        # Load configuration from file if provided
        if config_path:
            # In a real implementation, this would load config from file
            pass

        # Create the distribution strategy enum
        try:
            dist_strategy = DistributionStrategy[distribution_strategy.upper()]
        except (KeyError, AttributeError):
            logger.warning(
                f"Invalid distribution strategy: {distribution_strategy}, using SMART as default"
            )
            dist_strategy = DistributionStrategy.SMART

        # Create the master node
        self.master_node = SniperMasterNode(
            host=host,
            port=port,
            protocol_type=protocol_type,
            distribution_strategy=dist_strategy,
            worker_timeout=worker_timeout,
            result_callback=result_callback,
        )

    def start(self):
        """Start the master node server."""
        self.master_node.start()

    def stop(self):
        """Stop the master node server."""
        self.master_node.stop()
