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
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from src.core.logging import setup_logging
from src.distributed.base import (
    DistributedTask,
    MasterNode,
    NodeInfo,
    NodeRole,
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
    NodeStatusMessage,
    ProtocolBase,
    ProtocolMessage,
    RegisterMessage,
    TaskAssignmentMessage,
    TaskCancelMessage,
    TaskResultMessage,
    TaskStatusMessage,
    create_protocol,
)
from src.ml.autonomous_tester import VulnerabilityType

logger = logging.getLogger("sniper.distributed.master")


class TaskDistributionStrategy(str, Enum):
    """Strategy to use for distributing tasks to worker nodes."""

    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CAPABILITY_BASED = "capability_based"
    RANDOM = "random"


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
        distribution_strategy: TaskDistributionStrategy = TaskDistributionStrategy.CAPABILITY_BASED,
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
        super().__init__(node_id=None, hostname=None, address=host, port=port)
        self.host = host
        self.port = port
        self.protocol_type = protocol_type
        self.protocol = create_protocol(protocol_type, self)

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
            MessageType.NODE_STATUS: self._handle_node_status,
        }

    def _create_distribution_algorithm(
        self, strategy: TaskDistributionStrategy
    ) -> DistributionAlgorithm:
        """Create the distribution algorithm based on the specified strategy."""
        if strategy == TaskDistributionStrategy.ROUND_ROBIN:
            return RoundRobinDistribution()
        elif strategy == TaskDistributionStrategy.LEAST_LOADED:
            return LeastLoadedDistribution()
        elif strategy == TaskDistributionStrategy.CAPABILITY_BASED:
            return CapabilityBasedDistribution()
        elif strategy == TaskDistributionStrategy.RANDOM:
            return RandomDistribution()
        else:
            logger.warning(
                f"Unknown distribution strategy: {strategy}, using CAPABILITY_BASED as default"
            )
            return CapabilityBasedDistribution()

    def initialize_auto_scaling(
        self,
        min_nodes: int = 1,
        max_nodes: int = 10,
        scaling_policy: str = "queue_depth",
        provider: str = "docker",
        provider_config: Dict[str, Any] = None,
    ):
        """
        Initialize the auto-scaling system for worker nodes.

        Args:
            min_nodes: Minimum number of worker nodes to maintain
            max_nodes: Maximum number of worker nodes allowed
            scaling_policy: Policy to use for scaling decisions
            provider: Provider to use for creating worker nodes
            provider_config: Configuration for the provider

        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            # Import auto-scaling module
            from src.distributed.auto_scaling import (
                AutoScaler,
                ScalingConfig,
                ScalingPolicy,
                WorkerProvider,
            )

            # Create scaling configuration
            config = ScalingConfig(
                min_nodes=min_nodes,
                max_nodes=max_nodes,
                scaling_policy=ScalingPolicy(scaling_policy),
                provider=WorkerProvider(provider),
                check_interval=60,  # Check every minute
            )

            # Create auto-scaler
            self.auto_scaler = AutoScaler(
                master_node=self, config=config, provider_config=provider_config or {}
            )

            logger.info(
                f"Auto-scaling initialized with {provider} provider, {min_nodes}-{max_nodes} nodes"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to initialize auto-scaling: {e}", exc_info=True)
            return False

    def start(self):
        """
        Start the master node server and maintenance threads.

        Returns:
            True if startup was successful, False otherwise
        """
        if self.running:
            logger.warning("Master node is already running")
            return True

        logger.info(f"Starting Sniper Master Node on {self.host}:{self.port}")
        self.running = True

        # Submit cleanup loop to the executor instead of direct threading
        self.executor.submit(self._cleanup_loop)

        # Start the server based on protocol type
        try:
            if self.protocol_type == "rest":
                self._start_rest_server()
            else:
                raise NotImplementedError(
                    f"Protocol {self.protocol_type} not implemented yet"
                )
            logger.info(
                f"Master node server started successfully on {self.host}:{self.port}"
            )
            self.status = NodeStatus.ACTIVE

            # Start auto-scaler if configured
            if hasattr(self, "auto_scaler"):
                logger.info("Starting auto-scaler")
                self.auto_scaler.start()

            return True
        except Exception as e:
            self.running = False
            logger.error(f"Failed to start master node: {e}", exc_info=True)
            raise

    def stop(self):
        """
        Stop the master node server and cleanup resources.

        Returns:
            True if shutdown was successful, False otherwise
        """
        if not self.running:
            logger.warning("Master node is not running")
            return False

        logger.info("Stopping Sniper Master Node")
        self.running = False

        # Stop auto-scaler if running
        if hasattr(self, "auto_scaler"):
            logger.info("Stopping auto-scaler")
            self.auto_scaler.stop()

        # Stop the server
        if self.server:
            self._stop_server()

        # Shutdown executor with wait=True as expected by the test
        self.executor.shutdown(wait=True)

        # Set node status to offline
        self.status = NodeStatus.OFFLINE

        logger.info("Master node stopped")
        return True

    def _start_rest_server(self):
        """Start a REST server for the master node."""
        logger.info(f"Starting REST server for master node on {self.host}:{self.port}")

        # Import here to avoid circular imports
        from src.distributed.rest import create_master_app, run_app

        try:
            # Start the protocol server first
            if not self.protocol.start_server(self.host, self.port, self._handle_message):
                raise RuntimeError("Failed to start protocol server")

            logger.info(f"REST server started at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start REST server: {e}")
            raise

    def _stop_server(self):
        """Stop the REST server for the master node."""
        if self.server and self.server.get("status") == "running":
            logger.info("Stopping REST server")

            # Stop the protocol server
            self.protocol.stop_server()

            # If we have a rest server with a thread
            if self.server.get("type") == "rest" and self.server.get("thread"):
                # Import here to avoid circular imports
                from src.distributed.rest import shutdown_app

                # Shutdown the application
                if self.server.get("app"):
                    shutdown_app(self.server["app"])

                # Wait for the thread to finish
                if self.server["thread"].is_alive():
                    self.server["thread"].join(timeout=5)

            # Update server status
            self.server["status"] = "stopped"
            logger.info("REST server stopped")

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
            stale_workers = []
            now = datetime.now(timezone.utc)
            current_time = time.time()

            for worker_id, worker_info in list(self.workers.items()):
                is_stale = False

                # Check using NodeInfo heartbeat timestamp
                time_diff_seconds = (now - worker_info.heartbeat).total_seconds()
                if time_diff_seconds > self.worker_timeout:
                    is_stale = True
                    logger.warning(
                        f"Worker {worker_id} timed out (last heartbeat: {worker_info.heartbeat})"
                    )

                # Also check using worker metrics if available
                elif worker_id in self.worker_metrics:
                    metrics_last_heartbeat = self.worker_metrics[
                        worker_id
                    ].last_heartbeat
                    if current_time - metrics_last_heartbeat > self.worker_timeout:
                        is_stale = True
                        logger.warning(
                            f"Worker {worker_id} timed out (last metrics heartbeat: {datetime.fromtimestamp(metrics_last_heartbeat)})"
                        )

                if is_stale:
                    worker_info.status = NodeStatus.OFFLINE
                    stale_workers.append(worker_id)

            # Handle tasks assigned to stale workers
            for worker_id in stale_workers:
                # Reassign tasks from the stale worker
                self._handle_worker_failure(worker_id)

                # Remove the worker from collections
                if worker_id in self.workers:
                    del self.workers[worker_id]

                if worker_id in self.worker_metrics:
                    del self.worker_metrics[worker_id]

                logger.info(f"Removed stale worker {worker_id}")

    def _handle_worker_failure(self, worker_id: str):
        """
        Handle tasks assigned to a failed worker.

        This method implements robust fault tolerance for worker node failures by:
        1. Identifying all tasks assigned to the failed worker
        2. Reassigning tasks based on their priority and retry count
        3. Implementing recovery strategies for different failure scenarios
        4. Providing detailed logging for all recovery actions
        5. Tracking failure statistics for future optimization
        """
        with self.task_lock:
            reassigned_tasks = 0
            failed_tasks = 0
            logger.warning(f"Handling worker failure for worker {worker_id}")

            # Track failure statistics
            failure_time = datetime.now(timezone.utc)
            failed_task_ids = []

            # Process all tasks assigned to the failed worker
            for task_id, task in list(self.tasks.items()):
                if task.assigned_node == worker_id:
                    # Log the task that was impacted
                    logger.info(
                        f"Task {task_id} affected by worker {worker_id} failure"
                    )
                    failed_task_ids.append(task_id)

                    # Clear worker assignment and update status
                    task.assigned_node = None
                    task.status = TaskStatus.PENDING
                    task.retries += 1

                    # Track partial results if any exist
                    if hasattr(task, "partial_results") and task.partial_results:
                        logger.info(
                            f"Task {task_id} has partial results that will be merged on completion"
                        )

                    # Determine if we should retry or fail the task
                    if task.retries <= self.task_retry_limit:
                        # High priority tasks get immediately requeued at the front
                        if task.priority == TaskPriority.HIGH:
                            self.pending_tasks.insert(0, task)
                        else:
                            self.pending_tasks.append(task)

                        logger.info(
                            f"Requeued task {task_id} for retry (attempt {task.retries}/{self.task_retry_limit})"
                        )
                        reassigned_tasks += 1
                    else:
                        # Task has exceeded retry limit
                        logger.warning(
                            f"Task {task_id} exceeded retry limit ({self.task_retry_limit}), marking as failed"
                        )
                        task.status = TaskStatus.FAILED
                        task.completed_at = datetime.now(timezone.utc)
                        task.failure_reason = (
                            f"Exceeded retry limit after worker {worker_id} failure"
                        )

                        # Store in completed_tasks for tracking
                        self.completed_tasks[task_id] = task
                        del self.tasks[task_id]
                        failed_tasks += 1

            # Log overall recovery statistics
            if reassigned_tasks > 0 or failed_tasks > 0:
                logger.info(
                    f"Worker {worker_id} failure recovery: reassigned {reassigned_tasks} tasks, failed {failed_tasks} tasks"
                )

                # Record failure for analysis
                worker_failures = getattr(self, "worker_failures", {})
                if worker_id not in worker_failures:
                    worker_failures[worker_id] = []

                worker_failures[worker_id].append(
                    {
                        "time": failure_time,
                        "affected_tasks": len(failed_task_ids),
                        "reassigned_tasks": reassigned_tasks,
                        "failed_tasks": failed_tasks,
                        "task_ids": failed_task_ids,
                    }
                )

                # Update failure stats
                self.worker_failures = worker_failures

            # Check if we need to initiate auto-scaling to compensate for the lost worker
            if reassigned_tasks > 0 and hasattr(self, "auto_scaler"):
                logger.info(f"Notifying auto-scaler about worker {worker_id} failure")
                if hasattr(self.auto_scaler, "handle_worker_failure"):
                    self.auto_scaler.handle_worker_failure(worker_id, reassigned_tasks)

    def _cleanup_tasks(self):
        """
        Clean up stale tasks that have been running too long or are stuck in an inconsistent state.

        This method implements comprehensive task monitoring and recovery by:
        1. Detecting and recovering from tasks that have been running too long
        2. Identifying tasks stuck in transitional states
        3. Implementing escalating recovery strategies based on task priority and retry count
        4. Providing detailed logs for all recovery actions
        """
        with self.task_lock:
            current_time = datetime.now(timezone.utc)
            recovered_tasks = 0

            # Process all active tasks
            for task_id, task in list(self.tasks.items()):
                # Case 1: Running tasks that have exceeded their time limit
                if (
                    task.status == TaskStatus.RUNNING
                    and task.start_time
                    and (current_time - task.start_time).total_seconds() > task.timeout
                ):

                    logger.warning(
                        f"Task {task_id} timed out after running for {(current_time - task.start_time).total_seconds():.1f} seconds (limit: {task.timeout}s)"
                    )

                    # Track the worker that was handling this task
                    problem_worker_id = task.assigned_node

                    # Reset task for retry
                    task.assigned_node = None
                    task.status = TaskStatus.PENDING
                    task.retries += 1

                    # Determine next steps based on retry count
                    if task.retries <= self.task_retry_limit:
                        # Re-queue with priority based on retries
                        if task.retries > self.task_retry_limit / 2:
                            # For tasks that have been retried multiple times,
                            # place them at the front of the queue
                            self.pending_tasks.insert(0, task)
                            logger.info(
                                f"Task {task_id} prioritized for immediate retry (attempt {task.retries})"
                            )
                        else:
                            self.pending_tasks.append(task)
                            logger.info(
                                f"Task {task_id} queued for retry (attempt {task.retries})"
                            )

                        recovered_tasks += 1

                        # Record worker performance issue
                        if problem_worker_id:
                            self._record_worker_issue(
                                problem_worker_id, "task_timeout", task_id
                            )
                    else:
                        # Task exceeded retry limit
                        logger.warning(
                            f"Task {task_id} exceeded retry limit, marking as failed"
                        )
                        task.status = TaskStatus.FAILED
                        task.completed_at = current_time
                        task.failure_reason = "Exceeded timeout and retry limits"

                        # Move to completed (failed) tasks
                        self.completed_tasks[task_id] = task
                        del self.tasks[task_id]

                # Case 2: Tasks stuck in ASSIGNED state for too long
                elif (
                    task.status == TaskStatus.ASSIGNED
                    and task.assigned_at
                    and (current_time - task.assigned_at).total_seconds() > 300
                ):  # 5 minute limit

                    logger.warning(
                        f"Task {task_id} stuck in ASSIGNED state for {(current_time - task.assigned_at).total_seconds():.1f} seconds"
                    )

                    # Record the problematic worker
                    problem_worker_id = task.assigned_node

                    # Reset and requeue
                    task.assigned_node = None
                    task.status = TaskStatus.PENDING
                    task.retries += 1

                    if task.retries <= self.task_retry_limit:
                        self.pending_tasks.append(task)
                        logger.info(
                            f"Requeued task {task_id} that was stuck in ASSIGNED state"
                        )
                        recovered_tasks += 1

                        # Record worker issue
                        if problem_worker_id:
                            self._record_worker_issue(
                                problem_worker_id, "task_stuck", task_id
                            )
                    else:
                        # Handle exceeded retry limit
                        logger.warning(
                            f"Task {task_id} exceeded retry limit after being stuck, marking as failed"
                        )
                        task.status = TaskStatus.FAILED
                        task.completed_at = current_time
                        task.failure_reason = (
                            "Exceeded retry limit after being stuck in ASSIGNED state"
                        )

                        self.completed_tasks[task_id] = task
                        del self.tasks[task_id]

            # Log recovery statistics
            if recovered_tasks > 0:
                logger.info(f"Task cleanup recovered {recovered_tasks} tasks")

    def _record_worker_issue(self, worker_id: str, issue_type: str, task_id: str):
        """
        Record worker issues for tracking and possible worker penalties.

        Args:
            worker_id: ID of the problematic worker
            issue_type: Type of issue (e.g., 'task_timeout', 'task_stuck')
            task_id: ID of the affected task
        """
        # Initialize worker issues tracking if it doesn't exist
        worker_issues = getattr(self, "worker_issues", {})
        if worker_id not in worker_issues:
            worker_issues[worker_id] = []

        # Record the issue
        worker_issues[worker_id].append(
            {
                "time": datetime.now(timezone.utc),
                "issue_type": issue_type,
                "task_id": task_id,
            }
        )

        # Update worker issues
        self.worker_issues = worker_issues

        # Check if worker has too many issues and should be penalized
        if len(worker_issues[worker_id]) >= 3:
            recent_issues = [
                i
                for i in worker_issues[worker_id]
                if (datetime.now(timezone.utc) - i["time"]).total_seconds() < 1800
            ]  # last 30 minutes

            if len(recent_issues) >= 3:
                logger.warning(
                    f"Worker {worker_id} has {len(recent_issues)} issues in the last 30 minutes, considering penalization"
                )

                # Penalize by reducing priority in task distribution
                if worker_id in self.worker_metrics:
                    self.worker_metrics[worker_id].penalty_score = len(recent_issues)
                    logger.info(
                        f"Applied penalty score of {len(recent_issues)} to worker {worker_id}"
                    )

    def register_worker(self, worker_info: NodeInfo) -> bool:
        """
        Register a worker node with the master.

        Args:
            worker_info: Information about the worker node

        Returns:
            Whether the registration was successful
        """
        with self.worker_lock:
            worker_id = worker_info.node_id
            self.workers[worker_id] = worker_info

            # Initialize metrics if not exists
            if worker_id not in self.worker_metrics:
                self.worker_metrics[worker_id] = WorkerMetrics(
                    current_load=0.0,
                    task_count=0,
                    success_rate=1.0,
                    response_time=0.0,
                    last_heartbeat=time.time(),
                )

            logger.info(
                f"Worker {worker_id} registered with capabilities: {worker_info.capabilities}"
            )
            return True

    def unregister_worker(self, worker_id: str) -> bool:
        """
        Unregister a worker node from the master.

        Args:
            worker_id: ID of the worker to unregister

        Returns:
            Whether the unregistration was successful
        """
        with self.worker_lock:
            if worker_id not in self.workers:
                logger.warning(f"Cannot unregister worker {worker_id}: not found")
                return False

            # Handle any assigned tasks
            self._handle_worker_failure(worker_id)

            # Remove the worker
            del self.workers[worker_id]
            if worker_id in self.worker_metrics:
                del self.worker_metrics[worker_id]

            logger.info(f"Worker {worker_id} unregistered")
            return True

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.

        Args:
            task_id: ID of the task to cancel

        Returns:
            Whether the cancellation was successful
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot cancel task {task_id}: not found")
                return False

            task = self.tasks[task_id]

            # If task is pending, just remove it
            if task.status == TaskStatus.PENDING:
                if task in self.pending_tasks:
                    self.pending_tasks.remove(task)
                task.status = TaskStatus.CANCELLED
                logger.info(f"Cancelled pending task {task_id}")
                return True

            # If task is assigned or running, we need to notify the worker
            if (
                task.status in [TaskStatus.ASSIGNED, TaskStatus.RUNNING]
                and task.assigned_worker
            ):
                worker_id = task.assigned_worker
                cancel_message = ProtocolMessage(
                    message_type=MessageType.TASK_CANCEL,
                    payload={"task_id": task_id},
                    receiver=worker_id,
                )

                try:
                    self.protocol.send_message(cancel_message)
                    task.status = TaskStatus.CANCELLED
                    logger.info(
                        f"Sent cancellation request for task {task_id} to worker {worker_id}"
                    )
                    return True
                except Exception as e:
                    logger.error(f"Failed to send cancellation request: {e}")
                    return False

            # If task is already completed or failed, it can't be cancelled
            logger.warning(f"Cannot cancel task {task_id} with status {task.status}")
            return False

    def distribute_tasks(self) -> int:
        """
        Distribute pending tasks to available workers.

        Returns:
            Number of tasks distributed
        """
        return self._distribute_pending_tasks()

    def _distribute_pending_tasks(self) -> int:
        """
        Distribute pending tasks to available workers based on the selected distribution algorithm.

        Returns:
            Number of tasks distributed
        """
        with self.task_lock, self.worker_lock:
            # Get available active workers
            active_workers = {
                worker_id: info
                for worker_id, info in self.workers.items()
                if info.status in [NodeStatus.ACTIVE, NodeStatus.IDLE]
            }

            if not active_workers:
                logger.warning("No active workers available for task distribution")
                return 0

            if not self.pending_tasks:
                logger.debug("No pending tasks to distribute")
                return 0

            # Use the distribution algorithm to assign tasks to workers
            task_distribution = self.distribution_algorithm.distribute(
                self.pending_tasks, active_workers, self.worker_metrics
            )

            total_assigned = 0

            # Send tasks to assigned workers
            for worker_id, tasks in task_distribution.items():
                for task in self.pending_tasks:
                    if task.id in tasks:
                        success = self._send_task_to_worker(task, worker_id)
                        if success:
                            total_assigned += 1

            # Remove assigned tasks from pending list
            self.pending_tasks = [
                task for task in self.pending_tasks if task.status == TaskStatus.PENDING
            ]

            logger.info(
                f"Distributed {total_assigned} tasks to {len(active_workers)} active workers"
            )
            return total_assigned

    def process_result(self, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Process a result received from a worker.

        Args:
            task_id: ID of the completed task
            result: Result data

        Returns:
            Whether the result was processed successfully
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Cannot process result for unknown task {task_id}")
                return False

            task = self.tasks[task_id]
            task.results = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)

            # Move to completed tasks
            self.completed_tasks[task_id] = task

            # If there's a callback, execute it
            if self.result_callback:
                try:
                    self.executor.submit(self.result_callback, task_id, result)
                except Exception as e:
                    logger.error(f"Error submitting result callback: {e}")

            logger.info(f"Processed result for task {task_id}")
            return True

    def aggregate_results(self, task_ids: List[str]) -> Dict[str, Any]:
        """
        Aggregate results from multiple tasks.

        Args:
            task_ids: List of task IDs to aggregate

        Returns:
            Aggregated results
        """
        results = {}
        with self.task_lock:
            for task_id in task_ids:
                if task_id in self.completed_tasks:
                    task = self.completed_tasks[task_id]
                    if task.results:
                        # Store results with task_id as key
                        results[task_id] = task.results
                else:
                    logger.warning(
                        f"Task {task_id} not found or not completed for aggregation"
                    )

        return {
            "task_count": len(results),
            "tasks": results,
            "summary": {
                "completed": len([t for t in task_ids if t in self.completed_tasks]),
                "missing": len([t for t in task_ids if t not in self.completed_tasks]),
            },
        }

    def status_update(self) -> Dict[str, Any]:
        """
        Get status information about the master node.

        Returns:
            Dictionary with status information
        """
        with self.worker_lock, self.task_lock:
            return {
                "node_id": self.id,
                "status": self.status.name,
                "uptime": self.uptime(),
                "workers": {
                    "total": len(self.workers),
                    "active": len(
                        [
                            w
                            for w in self.workers.values()
                            if w.status == NodeStatus.ACTIVE
                        ]
                    ),
                    "busy": len(
                        [
                            w
                            for w in self.workers.values()
                            if w.status == NodeStatus.BUSY
                        ]
                    ),
                    "offline": len(
                        [
                            w
                            for w in self.workers.values()
                            if w.status == NodeStatus.OFFLINE
                        ]
                    ),
                },
                "tasks": {
                    "total": len(self.tasks),
                    "pending": len(self.pending_tasks),
                    "completed": len(self.completed_tasks),
                    "distribution_strategy": self.distribution_strategy.value,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _send_task_to_worker(self, task: DistributedTask, worker_id: str):
        """Send a task to a worker node."""
        worker_info = self.workers.get(worker_id)
        if not worker_info:
            logger.error(f"Worker {worker_id} not found")
            return False

        logger.info(
            f"Sending task {task.id} to worker {worker_id} ({worker_info.address}:{worker_info.port})"
        )

        # In a real implementation, this would use the actual protocol
        # to send the task to the worker
        # For now, we'll just log it and update our local state
        task.status = TaskStatus.ASSIGNED
        task.assigned_node = worker_id

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
            task_id: The ID of the task to check

        Returns:
            The task status or result if completed/failed, or None if task doesn't exist
        """
        # Check completed tasks first for results
        if task_id in self.completed_tasks:
            task = self.completed_tasks[task_id]
            return (
                task.result
                if task.result
                else {"status": task.status.value, "error": task.error}
            )
        # Then check active/pending tasks for status
        elif task_id in self.tasks:
            task = self.tasks[task_id]
            return task.status  # Return status enum for non-completed tasks
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

    def _handle_register(self, payload: Dict[str, Any]):
        """Handle worker registration message payload."""
        worker_id = payload.get("id")
        if not worker_id:
            logger.error("Registration message missing worker id.")
            return {"status": "error", "message": "Missing worker id"}

        # Create NodeInfo ensuring all required fields are present or defaulted
        try:
            # Extract worker information from payload
            capabilities = payload.get("capabilities", [])
            address = payload.get("address")
            hostname = payload.get("hostname", "unknown")
            port = payload.get("port", 5000)

            # Create the NodeInfo with proper parameters
            worker_info = NodeInfo(
                node_id=worker_id,
                role=NodeRole.WORKER,
                hostname=hostname,
                address=address,
                port=port,
                capabilities=capabilities,
            )

            # Set status if present in payload
            status_str = payload.get("status")
            if status_str:
                try:
                    worker_info.status = NodeStatus(status_str)
                except ValueError:
                    worker_info.status = NodeStatus.ACTIVE
            else:
                worker_info.status = NodeStatus.ACTIVE

            # Set heartbeat from payload or current time
            heartbeat_str = payload.get("heartbeat")
            if heartbeat_str:
                try:
                    worker_info.heartbeat = datetime.fromisoformat(heartbeat_str)
                except ValueError:
                    worker_info.heartbeat = datetime.now(timezone.utc)

            # Store the worker
            self.workers[worker_id] = worker_info

            # Initialize metrics for the new worker
            self.worker_metrics[worker_id] = WorkerMetrics(
                node_id=worker_id,
                capabilities=worker_info.capabilities,
                current_load=0.0,
                task_count=0,
                success_rate=1.0,
                response_time=0.0,
                last_heartbeat=time.time(),
            )

            logger.info(
                f"Worker {worker_id} registered with capabilities: {capabilities}"
            )
            return {
                "status": "success",
                "message": f"Worker {worker_id} registered successfully",
                "master_id": self.id,
            }
        except Exception as e:
            logger.error(f"Error registering worker {worker_id}: {e}", exc_info=True)
            return {"status": "error", "message": f"Error registering worker: {e}"}

    def _handle_heartbeat(self, message: ProtocolMessage):
        """Handle worker heartbeat message."""
        worker_id = message.sender_id
        current_load = message.payload.get("load", 0)
        current_tasks = message.payload.get("task_count", 0)
        memory_usage = message.payload.get("memory_usage", 0)

        with self.worker_lock:
            if worker_id in self.workers:
                worker_info = self.workers[worker_id]
                worker_info.status = NodeStatus.ACTIVE

                # Update heartbeat timestamp from payload
                heartbeat_ts_str = message.payload.get("timestamp")
                if heartbeat_ts_str:
                    try:
                        worker_info.heartbeat = datetime.fromisoformat(heartbeat_ts_str)
                    except ValueError:
                        logger.warning(
                            f"Invalid timestamp format from worker {worker_id}: {heartbeat_ts_str}"
                        )
                        worker_info.heartbeat = datetime.now(timezone.utc)
                else:
                    worker_info.heartbeat = datetime.now(timezone.utc)

                # Update worker statistics
                worker_info.stats["load"] = current_load
                worker_info.stats["task_count"] = current_tasks
                worker_info.stats["memory_usage"] = memory_usage

                # Update metrics if using the metrics system
                if worker_id in self.worker_metrics:
                    metrics = self.worker_metrics[worker_id]
                    metrics.current_load = current_load
                    metrics.task_count = current_tasks
                    metrics.last_heartbeat = time.time()

                logger.debug(
                    f"Received heartbeat from worker {worker_id}, load: {current_load}, tasks: {current_tasks}"
                )
            else:
                logger.warning(f"Received heartbeat from unknown worker {worker_id}")

    def _handle_task_status(self, message: ProtocolMessage):
        """Handle task status update message."""
        payload = message.payload
        task_id = payload.get("task_id")
        new_status_val = payload.get("status")
        worker_id = message.sender_id

        if not task_id or not new_status_val:
            logger.error(
                f"Task status update from {worker_id} missing task_id or status."
            )
            return {"status": "error", "message": "Missing task_id or status"}

        # Find the task in the main tasks dictionary first
        task = self.tasks.get(task_id)

        if not task:
            # Check completed tasks as well, although status updates for completed are less common
            if task_id in self.completed_tasks:
                logger.warning(
                    f"Received status update for completed task {task_id} from {worker_id}."
                )
                task = self.completed_tasks[
                    task_id
                ]  # Update status on completed task if needed
            else:
                logger.warning(
                    f"Received status update for unknown task {task_id} from {worker_id}."
                )
                return {"status": "ignored", "message": f"Task {task_id} not found"}

        # Validate the worker reporting the status
        # Task should ideally be assigned to the reporting worker
        if task.assigned_node != worker_id:
            logger.warning(f"Task {task_id} is not assigned to worker {worker_id}.")
            return {
                "status": "ignored",
                "message": f"Task {task_id} is not assigned to worker {worker_id}.",
            }

        # Update the task status
        try:
            new_status_enum = TaskStatus(new_status_val)
            task.status = new_status_enum
            task.updated_at = datetime.now(timezone.utc)
        except ValueError:
            logger.error(
                f"Received invalid status '{new_status_val}' in task status update for {task_id} from {worker_id}. Ignoring."
            )
            return {
                "status": "error",
                "message": f"Invalid status value: {new_status_val}",
            }

        # Handle task state transitions if necessary
        if new_status_enum == TaskStatus.RUNNING and task.status in [
            TaskStatus.PENDING,
            TaskStatus.ASSIGNED,
        ]:  # Allow transition from ASSIGNED too
            if not task.started_at:
                task.started_at = (
                    task.updated_at
                )  # Set started_at on transition to RUNNING
        elif new_status_enum in [
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        ]:
            # If results are included in the payload, store them
            if "result" in payload:
                task.result = payload["result"]

            # If task transitions to a terminal state, move it to completed_tasks
            if task_id in self.tasks:
                # This removes from self.tasks and adds to self.completed_tasks
                self._handle_completed_task(task)

            logger.info(f"Task {task_id} completed successfully on {worker_id}.")

        return {
            "status": "success",
            "message": f"Task {task_id} status updated to {new_status_enum.value}",
        }

    def _handle_task_result(self, message: ProtocolMessage) -> Dict[str, Any]:
        """Handles completed task results from workers."""
        payload = message.payload
        task_id = payload.get("task_id")
        status_val = payload.get("status")
        results = payload.get("results")  # Can be None if failed
        worker_id = message.sender_id

        if not task_id or not status_val:
            logger.error(
                f"Task result message from {worker_id} missing task_id or status."
            )
            return {"status": "error", "message": "Missing task_id or status"}

        task = self.tasks.pop(
            task_id, None
        )  # Try removing from active tasks (self.tasks) first
        if not task:
            # Check if it was already completed (e.g., due to timeout or prior status update)
            if task_id in self.completed_tasks:
                logger.warning(
                    f"Received result for already completed task {task_id} from {worker_id}. Updating result."
                )
                task = self.completed_tasks[task_id]
            else:
                logger.warning(
                    f"Received result for unknown task {task_id} from {worker_id}. Ignoring."
                )
                return {"status": "ignored", "message": f"Task {task_id} not found"}

        try:
            status = TaskStatus(status_val)
            if status not in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                logger.warning(
                    f"Received task result for task {task_id} from {worker_id} with unexpected status {status.value}. Treating as FAILED."
                )
                status = TaskStatus.FAILED  # Default to FAILED if status isn't terminal
        except ValueError:
            logger.error(
                f"Received invalid status '{status_val}' in task result for {task_id} from {worker_id}. Treating as FAILED."
            )
            status = TaskStatus.FAILED

        logger.info(
            f"Received result for task {task_id} from worker {worker_id} with status {status.value}."
        )
        task.status = status
        task.completed_at = datetime.now(timezone.utc)
        task.result = results  # Store the results payload
        task.updated_at = task.completed_at

        # Ensure task is moved to completed tasks if it wasn't already (e.g., if it was found in self.tasks)
        if task_id not in self.completed_tasks:
            self.completed_tasks[task_id] = task
        # No need to explicitly remove from self.tasks again, pop already did that if it was there.

        # Update worker info (remove from current_tasks)
        worker = self.workers.get(worker_id)
        if worker and task_id in worker.current_tasks:
            try:
                worker.current_tasks.remove(task_id)
            except ValueError:
                logger.warning(
                    f"Attempted to remove task {task_id} from worker {worker_id}'s list upon completion, but it wasn't found."
                )

        # Aggregate results (optional, could be separate process)
        # try:
        #     self.result_aggregator.add_result(task)
        # except Exception as e:
        #     logger.error(f"Error adding result for task {task_id} to aggregator: {e}", exc_info=True)

        return {"status": "success", "message": f"Result for task {task_id} processed"}

    def _handle_completed_task(self, task: DistributedTask):
        """Handles completed task processing."""
        try:
            # Update worker metrics
            with self.worker_lock:
                if task.assigned_node and task.assigned_node in self.worker_metrics:
                    metrics = self.worker_metrics[task.assigned_node]
                    metrics.current_tasks = max(0, metrics.current_tasks - 1)
                    metrics.total_execution_time += (
                        task.completed_at - task.start_time
                    ).total_seconds()
                    total_tasks = metrics.success_count + metrics.failure_count
                    if total_tasks > 0:
                        metrics.avg_response_time = (
                            metrics.total_execution_time / total_tasks
                        )

            # Move to completed tasks
            self.completed_tasks[task.id] = task
            del self.tasks[task.id]

            logger.info(f"Task {task.id} completed successfully on master.")
        except ValueError:
            logger.warning(
                f"Attempted to remove task {task.id} from worker {task.assigned_node}'s list, but it wasn't found."
            )

    def _handle_node_status(self, message: NodeStatusMessage):
        """Handle node status update from worker node."""
        node_id = message.payload.get("node_id")
        status = message.payload.get("status")

        if node_id in self.workers:
            # Update node status
            self.workers[node_id].status = NodeStatus(status)
            self.workers[node_id].last_updated = datetime.now()

            logger.info(f"Node {node_id} status updated to {status}")

            return ProtocolMessage(
                message_id=f"ns-confirm-{int(time.time())}",
                message_type=MessageType.NODE_STATUS_CONFIRM,
                payload={"status": "received"},
            )
        else:
            return ProtocolMessage(
                message_id=f"ns-error-{int(time.time())}",
                message_type=MessageType.ERROR,
                payload={"error": "Node not registered", "action": "register"},
            )

    # Add methods to distribute autonomous testing tasks

    async def submit_autonomous_test(
        self,
        target_url: str,
        vulnerability_type: Optional[Union[str, VulnerabilityType]] = None,
        request_params: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        payload_count: int = 5,
        priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> str:
        """
        Submit an autonomous testing task to be distributed to worker nodes.

        Args:
            target_url: The URL to test
            vulnerability_type: Optional specific vulnerability type to test
            request_params: Optional parameters for the request
            headers: Optional HTTP headers
            cookies: Optional cookies
            payload_count: Number of payloads to test
            priority: Task priority

        Returns:
            The task ID of the submitted task
        """
        # Create a unique task ID
        task_id = f"autotest-{int(time.time())}-{random.randint(1000, 9999)}"

        # Convert vulnerability type enum to string if needed
        vuln_type_str = None
        if vulnerability_type:
            if isinstance(vulnerability_type, VulnerabilityType):
                vuln_type_str = vulnerability_type.value
            else:
                vuln_type_str = vulnerability_type

        # Prepare task parameters
        task_params = {
            "target_url": target_url,
            "vulnerability_type": vuln_type_str,
            "request_params": request_params or {},
            "headers": headers or {},
            "cookies": cookies or {},
            "payload_count": payload_count,
        }

        # Create the task
        task = DistributedTask(
            task_id=task_id,
            task_type="autonomous_test",
            parameters=task_params,
            status=TaskStatus.PENDING,
            priority=priority,
            created_at=datetime.now(),
            last_updated=datetime.now(),
        )

        # Store the task
        self.tasks[task_id] = task

        logger.info(f"Submitted autonomous testing task {task_id} for {target_url}")

        # Trigger task distribution
        asyncio.create_task(self._distribute_tasks())

        return task_id

    async def submit_comprehensive_scan(
        self,
        target_url: str,
        request_params: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> str:
        """
        Submit a comprehensive scan task that checks for multiple vulnerability types.

        Args:
            target_url: The URL to test
            request_params: Optional parameters for the request
            headers: Optional HTTP headers
            cookies: Optional cookies
            priority: Task priority

        Returns:
            The task ID of the submitted task
        """
        # This is similar to submit_autonomous_test but without specifying a vulnerability type
        return await self.submit_autonomous_test(
            target_url=target_url,
            vulnerability_type=None,  # None indicates comprehensive scan
            request_params=request_params,
            headers=headers,
            cookies=cookies,
            priority=priority,
        )

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the result of a completed task.

        Args:
            task_id: The task ID to get results for

        Returns:
            The task result or None if not available
        """
        if task_id in self.completed_tasks:
            return self.completed_tasks[task_id].results
        return None

    async def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """
        Get the status of a task.

        Args:
            task_id: The task ID to get status for

        Returns:
            The task status or None if task not found
        """
        if task_id in self.tasks:
            return self.tasks[task_id].status
        return None

    def _update_task_status(
        self, task_id: str, status: TaskStatus, result: Any = None
    ) -> Optional[DistributedTask]:
        """
        Update the status of a task and store its result if completed or failed.

        Args:
            task_id: The ID of the task to update.
            status: The new status of the task.
            result: The result of the task (if completed or failed).

        Returns:
            The updated task object if found, otherwise None.
        """
        with self.task_lock:
            if task_id not in self.tasks:
                logger.warning(f"Task {task_id} not found for status update")
                return None

            task = self.tasks[task_id]
            old_status = task.status
            task.status = status
            task.updated_at = datetime.now(timezone.utc)

            log_message = f"Task {task_id} status updated: {old_status} -> {status}"

            # Handle terminal states
            if status in [
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            ]:
                task.completed_at = task.updated_at  # Use completed_at
                task.result = result if result is not None else {}
                task.assigned_node = None  # Task is no longer assigned

                # Move to completed tasks
                self.completed_tasks[task_id] = task
                if task_id in self.tasks:
                    del self.tasks[task_id]  # Remove from active tasks

                # Remove from pending queue if it was there (e.g., cancellation)
                if task_id in self.pending_tasks:
                    self.pending_tasks.remove(task_id)

                if status == TaskStatus.COMPLETED:
                    log_message += f" (Completed at: {task.completed_at})"
                    # Trigger result callback if defined
                    if self.result_callback:
                        try:
                            # Consider running callback in executor if it's blocking
                            self.result_callback(task_id, task.result)
                        except Exception as e:
                            logger.error(
                                f"Error executing result callback for task {task_id}: {e}"
                            )
                elif status == TaskStatus.FAILED:
                    log_message += (
                        f" (Failed at: {task.completed_at}, Result: {result})"
                    )
                elif status == TaskStatus.CANCELLED:
                    log_message += f" (Cancelled at: {task.completed_at})"

            elif status == TaskStatus.RUNNING:
                task.started_at = task.updated_at  # Update started time
                log_message += f" (Started at: {task.started_at})"

            elif status == TaskStatus.PENDING:
                # Reset relevant fields if moving back to pending (e.g., retry)
                task.started_at = None
                task.completed_at = None
                task.assigned_node = None
                task.result = None

            logger.info(log_message)
            return task


class MasterNodeServer:
    """Command-line wrapper for the Sniper Master Node."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 5000,
        protocol_type: str = "rest",
        distribution_strategy: str = "smart",
        worker_timeout: int = 60,
        result_callback=None,
        auto_scaling: bool = False,
        min_nodes: int = 1,
        max_nodes: int = 10,
        scaling_policy: str = "queue_depth",
        scaling_provider: str = "docker",
        provider_config_path: Optional[str] = None,
    ):
        """
        Initialize the master node server.

        Args:
            config_path: Path to the master node configuration file
            host: Host address to bind the server to
            port: Port to listen on
            protocol_type: Protocol to use for communication
            distribution_strategy: Strategy for distributing tasks
            worker_timeout: Seconds after which a worker is considered offline
            result_callback: Optional callback function to process results
            auto_scaling: Whether to enable auto-scaling
            min_nodes: Minimum number of worker nodes when auto-scaling
            max_nodes: Maximum number of worker nodes when auto-scaling
            scaling_policy: Policy to use for scaling decisions
            scaling_provider: Provider to use for creating worker nodes
            provider_config_path: Path to provider configuration file
        """
        # Set up logging
        setup_logging()

        # Parse configuration
        config = {}
        if config_path:
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
            except Exception as e:
                logger.error(f"Error loading config from {config_path}: {e}")
                raise

        # Override with command-line arguments
        self.host = host or config.get("host", "0.0.0.0")
        self.port = port or config.get("port", 5000)
        self.protocol_type = protocol_type or config.get("protocol_type", "rest")
        self.distribution_strategy = distribution_strategy or config.get(
            "distribution_strategy", "smart"
        )
        self.worker_timeout = worker_timeout or config.get("worker_timeout", 60)

        # Auto-scaling configuration
        self.auto_scaling = auto_scaling or config.get("auto_scaling", False)
        self.min_nodes = min_nodes or config.get("min_nodes", 1)
        self.max_nodes = max_nodes or config.get("max_nodes", 10)
        self.scaling_policy = scaling_policy or config.get(
            "scaling_policy", "queue_depth"
        )
        self.scaling_provider = scaling_provider or config.get(
            "scaling_provider", "docker"
        )

        # Load provider configuration if specified
        self.provider_config = None
        if provider_config_path:
            try:
                with open(provider_config_path, "r") as f:
                    self.provider_config = json.load(f)
            except Exception as e:
                logger.error(
                    f"Error loading provider config from {provider_config_path}: {e}"
                )
                self.provider_config = {}
        else:
            self.provider_config = config.get("provider_config", {})

        # Create master node
        try:
            self.master_node = SniperMasterNode(
                host=self.host,
                port=self.port,
                protocol_type=self.protocol_type,
                distribution_strategy=self.distribution_strategy,
                worker_timeout=self.worker_timeout,
                result_callback=result_callback,
            )

            # Initialize auto-scaling if enabled
            if self.auto_scaling:
                logger.info(
                    f"Initializing auto-scaling with {self.scaling_provider} provider"
                )
                success = self.master_node.initialize_auto_scaling(
                    min_nodes=self.min_nodes,
                    max_nodes=self.max_nodes,
                    scaling_policy=self.scaling_policy,
                    provider=self.scaling_provider,
                    provider_config=self.provider_config,
                )

                if not success:
                    logger.warning(
                        "Failed to initialize auto-scaling, continuing without it"
                    )
                else:
                    logger.info(
                        f"Auto-scaling initialized with {self.min_nodes}-{self.max_nodes} nodes"
                    )

        except Exception as e:
            logger.error(f"Error creating master node: {e}")
            raise

    def start(self):
        """Start the master node server."""
        return self.master_node.start()

    def stop(self):
        """Stop the master node server."""
        return self.master_node.stop()
