"""
Worker Node Implementation for Sniper Security Tool's Distributed Scanning Architecture.

This module provides the implementation of worker nodes responsible for:
- Registering with master node
- Executing distributed scanning tasks
- Reporting results and status updates
- Health monitoring and heartbeat
"""

import asyncio
import json
import logging
import os
import platform
import queue
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import requests

from src.core.logging import setup_logging
from src.distributed.base import (
    BaseNode,
    DistributedTask,
    NodeInfo,
    NodeRole,
    NodeStatus,
    TaskPriority,
    TaskStatus,
)
from src.distributed.protocol import (
    HeartbeatMessage,
    MessageType,
    ProtocolBase,
    ProtocolMessage,
    TaskResultMessage,
    create_protocol,
)
from src.ml.autonomous_tester import AutonomousTester, VulnerabilityType

logger = logging.getLogger("sniper.distributed.worker")


class SniperWorkerNode(BaseNode):
    """
    Sniper Worker Node implementation for distributed scanning architecture.

    Handles task execution and reporting results back to the master node.
    """

    def __init__(
        self,
        master_host: str,
        master_port: int,
        protocol_type: str = "REST",
        capabilities: List[str] = None,
        max_concurrent_tasks: int = 5,
        heartbeat_interval: int = 30,
        node_id: Optional[str] = None,
    ):
        """
        Initialize the Sniper Worker Node.

        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            protocol_type: Communication protocol to use (default: "REST")
            capabilities: List of task types this worker can execute
            max_concurrent_tasks: Maximum number of concurrent tasks
            heartbeat_interval: Interval in seconds for sending heartbeats
            node_id: Optional ID for this worker (generated if not provided)
        """
        super().__init__(node_id=node_id or f"worker-{uuid.uuid4()}")
        self.master_host = master_host
        self.master_port = master_port
        self.protocol_type = protocol_type
        self.capabilities = capabilities or ["scan", "vuln", "recon"]
        self.max_concurrent_tasks = max_concurrent_tasks
        self.heartbeat_interval = heartbeat_interval

        # Protocol and client
        self.protocol: Optional[ProtocolBase] = None
        self.master_id: Optional[str] = None

        # Task management
        self.tasks: Dict[str, DistributedTask] = {}
        self.active_tasks = 0
        self.task_handlers: Dict[str, Callable] = {}

        # Thread management
        self.running = False
        self.heartbeat_thread = None
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_tasks + 2)

        # Status and metrics
        self.status = NodeStatus.INITIALIZING
        self.task_count = 0
        self.success_count = 0
        self.failure_count = 0

        self.task_semaphore: Optional[asyncio.Semaphore] = None

        # Initialize the autonomous tester for handling autonomous testing tasks
        self.autonomous_tester = AutonomousTester()

        # Register default task handlers
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default task handlers for common task types."""
        # Register autonomous testing handler
        self.register_task_handler("autonomous_test", self._handle_autonomous_test)
        self.register_task_handler(
            "vulnerability_scan", self._handle_vulnerability_scan
        )
        self.register_task_handler("recon", self._handle_recon_task)

    def register_task_handler(self, task_type: str, handler: Callable) -> None:
        """
        Register a handler function for a specific task type.

        Args:
            task_type: Type of task the handler can process
            handler: Function to handle the task execution
        """
        self.task_handlers[task_type] = handler
        logger.info(f"Registered handler for task type: {task_type}")

        # Add to capabilities if not already present
        if task_type not in self.capabilities:
            self.capabilities.append(task_type)

    async def start(self) -> bool:
        """Start the worker node client and connect to master."""
        if self.running:
            logger.warning("Worker node already running")
            return False

        try:
            # Set up protocol
            self.protocol = create_protocol(self.protocol_type, self)

            # Connect to master node
            logger.info(
                f"Connecting to master node at {self.master_host}:{self.master_port}"
            )
            if not await self._register_with_master():
                logger.error("Failed to register with master node")
                return False

            # Set status to active
            self.status = NodeStatus.ACTIVE
            self.running = True

            # Start heartbeat thread
            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, daemon=True
            )
            self.heartbeat_thread.start()

            self.task_semaphore = asyncio.Semaphore(self.max_concurrent_tasks)

            logger.info("Worker node started successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to start worker node: {str(e)}")
            self.running = False
            return False

    async def stop(self) -> bool:
        """Stop the worker node and disconnect from master."""
        if not self.running:
            logger.warning("Worker node not running")
            return False

        try:
            self.running = False
            self.status = NodeStatus.OFFLINE

            # Cancel active tasks
            for task_id, task in list(self.tasks.items()):
                if task.status == TaskStatus.RUNNING:
                    await self.cancel_task(task_id)

            # Disconnect from master
            if self.protocol:
                await self.protocol.disconnect()

            # Shutdown executor
            self.executor.shutdown(wait=False)

            logger.info("Worker node stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping worker node: {str(e)}")
            return False

    async def _register_with_master(self) -> bool:
        """Register this worker with the master node."""
        if not self.protocol:
            logger.error("Protocol not initialized")
            return False

        try:
            # Create worker info
            worker_info = NodeInfo(
                node_id=self.id,
                role=NodeRole.WORKER,
                hostname=self.hostname,
                address=self.address,
                port=self.port,
                capabilities=self.capabilities,
            )
            worker_info.status = NodeStatus.INITIALIZING

            # Create registration message using ProtocolMessage
            reg_message = ProtocolMessage(
                message_type=MessageType.REGISTER,
                sender_id=self.id,
                receiver_id="master",
                payload=worker_info.to_dict(),
            )

            # Log registration attempt
            logger.debug(f"Attempting to register with master node using protocol: {self.protocol_type}")
            logger.debug(f"Registration payload: {worker_info.to_dict()}")

            # Send registration message
            response_dict = await self.protocol.send_message(reg_message)
            
            # Log response
            logger.debug(f"Registration response: {response_dict}")

            # Process response (assuming send_message returns a dict or None)
            if (
                response_dict
                and response_dict.get("message_type")
                == MessageType.REGISTER_RESPONSE.name
            ):
                payload = response_dict.get("payload", {})
                if payload.get("status") == "success":
                    self.master_id = response_dict.get("sender_id")
                    self.status = NodeStatus.IDLE
                    logger.info(
                        f"Successfully registered with master node {self.master_id}"
                    )
                    return True
                else:
                    logger.error(
                        f"Master rejected registration: {payload.get('message')}"
                    )
                    return False
            else:
                logger.error(f"Unexpected or missing response from master node: {response_dict}")
                return False
        except Exception as e:
            logger.error(f"Error registering with master node: {str(e)}")
            return False

    def _heartbeat_loop(self) -> None:
        """Periodically send heartbeats to the master node."""

        # Run the async heartbeat function in a separate thread using asyncio
        async def heartbeat_task():
            while self.running:
                try:
                    await self._send_heartbeat()
                    await asyncio.sleep(self.heartbeat_interval)
                except Exception as e:
                    logger.error(f"Error in heartbeat loop: {str(e)}")
                    await asyncio.sleep(5)  # Retry after a short delay

        asyncio.run(heartbeat_task())

    async def _send_heartbeat(self) -> None:
        """Send a heartbeat message to the master node."""
        if not self.protocol or not self.master_id:
            logger.warning("Cannot send heartbeat: not connected to master")
            return

        try:
            payload = {
                "status": self.status.value,
                "load": (
                    self.active_tasks / self.max_concurrent_tasks
                    if self.max_concurrent_tasks > 0
                    else 0
                ),
                "capabilities": self.capabilities,
            }
            # Use ProtocolMessage for consistency
            message = ProtocolMessage(
                message_type=MessageType.HEARTBEAT,
                sender_id=self.id,
                receiver_id=self.master_id,
                payload=payload,
            )
            # Await the async send_message
            response_dict = await self.protocol.send_message(message)
            # Check response based on dict structure and HEARTBEAT_RESPONSE
            if (
                response_dict
                and response_dict.get("message_type")
                == MessageType.HEARTBEAT_RESPONSE.name
            ):
                logger.debug("Heartbeat acknowledged by master")
            else:
                logger.warning(
                    f"Heartbeat not acknowledged by master. Response: {response_dict}"
                )
        except Exception as e:
            logger.error(f"Error sending heartbeat: {str(e)}", exc_info=True)

    async def handle_message(
        self, message: ProtocolMessage
    ) -> Optional[ProtocolMessage]:
        """Handle incoming messages from the master node."""
        try:
            if message.message_type == MessageType.TASK_ASSIGNMENT:
                # Use await for async handler
                return await self._handle_task_assignment(message)
            elif message.message_type == MessageType.CANCEL_TASK:
                # Use CANCEL_TASK
                # Use await for async handler
                return await self._handle_task_cancel(message)
            else:
                logger.warning(f"Unknown message type: {message.message_type}")
                return None
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            return None

    async def _handle_task_assignment(
        self, message: ProtocolMessage
    ) -> Optional[ProtocolMessage]:
        """Handle task assignment messages from the master node."""
        try:
            # Parse task data
            task_data = message.payload
            if not isinstance(task_data, dict):
                logger.error(
                    f"Invalid task data format: {type(task_data)}. Expected dict."
                )
                # Send back a NACK or error response
                return ProtocolMessage(
                    message_type=MessageType.TASK_STATUS,
                    sender_id=self.id,
                    receiver_id=message.sender_id,
                    payload={
                        "task_id": (
                            task_data.get("id", "unknown")
                            if isinstance(task_data, dict)
                            else "unknown"
                        ),
                        "status": TaskStatus.FAILED.name,
                        "message": "Invalid task data format received by worker.",
                    },
                )

            task = DistributedTask.from_dict(task_data)

            logger.info(f"Received task assignment: {task.id} (Type: {task.task_type})")

            # Check if we can handle this task type
            if task.task_type not in self.capabilities:
                logger.warning(f"Cannot handle task type: {task.task_type}")
                return ProtocolMessage(
                    message_type=MessageType.TASK_STATUS,
                    sender_id=self.id,
                    receiver_id=message.sender_id,
                    payload={
                        "task_id": task.id,
                        "status": TaskStatus.REJECTED.name,
                        "message": f"Worker does not support task type: {task.task_type}",
                    },
                )

            # Check if we have capacity (use semaphore)
            if (
                self.task_semaphore.locked()
                and self.active_tasks >= self.max_concurrent_tasks
            ):
                logger.warning("Cannot accept task: at maximum capacity")
                return ProtocolMessage(
                    message_type=MessageType.TASK_STATUS,
                    sender_id=self.id,
                    receiver_id=message.sender_id,
                    payload={
                        "task_id": task.id,
                        "status": TaskStatus.REJECTED.name,
                        "message": "Worker at maximum capacity",
                    },
                )

            # Accept the task
            task.status = TaskStatus.ACCEPTED
            self.tasks[task.id] = task
            self.active_tasks += 1
            logger.info(f"Accepted task {task.id}. Active tasks: {self.active_tasks}")

            # Start task execution in the background
            asyncio.create_task(self._execute_task_wrapper(task))

            # Send acceptance confirmation
            return ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=message.sender_id,
                payload={
                    "task_id": task.id,
                    "status": TaskStatus.ACCEPTED.name,
                },
            )

        except Exception as e:
            logger.error(f"Error handling task assignment: {str(e)}", exc_info=True)
            task_id = (
                message.payload.get("id", "unknown")
                if isinstance(message.payload, dict)
                else "unknown"
            )
            # Send failure status back
            return ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=message.sender_id,
                payload={
                    "task_id": task_id,
                    "status": TaskStatus.FAILED.name,
                    "message": f"Error processing task assignment: {str(e)}",
                },
            )

    async def _handle_task_cancel(
        self, message: ProtocolMessage
    ) -> Optional[ProtocolMessage]:
        """Handle task cancellation messages from the master node."""
        try:
            task_id = message.payload.get("task_id")
            if not task_id:
                logger.warning("Received task cancellation request without task_id")
                return None

            logger.info(f"Received request to cancel task: {task_id}")

            # Attempt to cancel the task
            cancelled = await self.cancel_task(task_id)

            # Send cancellation status back to the master
            status = TaskStatus.CANCELLED if cancelled else TaskStatus.FAILED
            reason = (
                "Task cancelled by master."
                if cancelled
                else "Failed to cancel task (already completed or not found)."
            )

            return ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=message.sender_id,
                payload={
                    "task_id": task_id,
                    "status": status.name,
                    "message": reason,
                },
            )
        except Exception as e:
            logger.error(f"Error handling task cancellation: {str(e)}", exc_info=True)
            task_id = (
                message.payload.get("task_id", "unknown")
                if isinstance(message.payload, dict)
                else "unknown"
            )
            # Send failure status back
            return ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=message.sender_id,
                payload={
                    "task_id": task_id,
                    "status": TaskStatus.FAILED.name,
                    "message": f"Error processing task cancellation: {str(e)}",
                },
            )

    async def _execute_task_wrapper(self, task: DistributedTask):
        """Acquire semaphore, execute task, handle errors, and release semaphore."""
        async with self.task_semaphore:
            try:
                logger.info(f"Starting execution of task: {task.id}")
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now(timezone.utc)
                await self._report_task_status_to_master(task.id, TaskStatus.RUNNING)

                # Execute the actual task logic in the thread pool executor
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    self.executor, self.execute_task, task
                )

                # Check result format and status
                if isinstance(result, dict) and "status" in result:
                    task_status_str = result.get("status", TaskStatus.UNKNOWN.name)
                    try:
                        task.status = TaskStatus[task_status_str.upper()]
                    except KeyError:
                        logger.error(
                            f"Task {task.id} returned unknown status: {task_status_str}"
                        )
                        task.status = TaskStatus.FAILED
                        result["error"] = f"Unknown status returned: {task_status_str}"
                else:
                    # Assume success if status is not explicitly set but no error occurred
                    logger.warning(
                        f"Task {task.id} result dict missing 'status'. Assuming COMPLETED based on lack of errors."
                    )
                    task.status = TaskStatus.COMPLETED

                task.completed_at = datetime.now(timezone.utc)
                task.result = result.get("result")
                task.error = result.get("error")

                logger.info(f"Task {task.id} finished with status: {task.status.name}")

                # Send final result/status to master
                await self._send_task_result(
                    task.id, task.result, task.status, task.error
                )

            except Exception as e:
                logger.error(f"Error executing task {task.id}: {str(e)}", exc_info=True)
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                task.error = str(e)
                # Send failure status to master
                await self._send_task_result(task.id, None, TaskStatus.FAILED, str(e))

            finally:
                # Clean up task reference and decrement active count
                if task.id in self.tasks:
                    del self.tasks[task.id]
                self.active_tasks = max(0, self.active_tasks - 1)
                logger.debug(
                    f"Cleaned up task {task.id}. Active tasks: {self.active_tasks}"
                )
                # Semaphore is released automatically by 'async with'

    def execute_task(self, task: DistributedTask) -> Dict[str, Any]:
        """Execute a specific task based on its type."""
        logger.debug(
            f"Executing task {task.id} (Type: {task.task_type}) in executor thread."
        )
        handler = self.task_handlers.get(task.task_type)
        if not handler:
            logger.error(f"No handler registered for task type: {task.task_type}")
            return {
                "status": TaskStatus.FAILED.name,
                "error": f"No handler for task type {task.task_type}",
            }

        try:
            # Run the registered handler
            result_data = handler(task)
            logger.debug(f"Task handler for {task.id} completed.")

            # Ensure result is a dictionary, default to COMPLETED status if missing
            if isinstance(result_data, dict):
                status = result_data.get("status", TaskStatus.COMPLETED.name)
                return {
                    "status": status,
                    "result": result_data.get("result"),
                    "error": result_data.get("error"),
                }
            else:
                # If handler returns non-dict, wrap it as a result
                logger.warning(
                    f"Handler for task {task.id} returned non-dict type: {type(result_data)}. Wrapping."
                )
                return {
                    "status": TaskStatus.COMPLETED.name,
                    "result": result_data,
                    "error": None,
                }

        except Exception as e:
            logger.error(
                f"Exception in task handler for {task.id} (Type: {task.task_type}): {str(e)}",
                exc_info=True,
            )
            return {"status": TaskStatus.FAILED.name, "error": str(e)}

    async def _send_task_result(
        self,
        task_id: str,
        result: Optional[Any],
        status: TaskStatus,
        error: Optional[str] = None,
    ) -> None:
        """Send the result of a completed task to the master node."""
        if not self.protocol or not self.master_id:
            logger.error("Cannot send task result: protocol or master_id missing.")
            return

        try:
            # Construct payload
            payload = {
                "task_id": task_id,
                "status": status.name,
                "result": result,
                "error": error,
            }

            # Create message
            message = ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=self.master_id,
                payload=payload,
            )

            # Send the message
            await self.protocol.send_message(message)
            logger.info(f"Sent final status for task {task_id}: {status.name}")

        except Exception as e:
            logger.error(
                f"Error sending task result for {task_id}: {str(e)}", exc_info=True
            )

    async def _report_task_status_to_master(
        self, task_id: str, status: TaskStatus, message: str = ""
    ) -> None:
        """Send an intermediate status update for a task to the master node."""
        if not self.protocol or not self.master_id:
            logger.warning("Cannot send status update: protocol or master_id missing.")
            return

        # Avoid sending updates for terminal states here, use _send_task_result instead
        if status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            logger.debug(
                f"Skipping intermediate status update for terminal state {status.name} for task {task_id}"
            )
            return

        try:
            # Construct payload
            payload = {
                "task_id": task_id,
                "status": status.name,
                "message": message,
            }

            # Create message
            update_message = ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=self.id,
                receiver_id=self.master_id,
                payload=payload,
            )

            # Send the message
            await self.protocol.send_message(update_message)
            logger.debug(f"Sent status update for task {task_id}: {status.name}")

        except Exception as e:
            logger.error(
                f"Error sending status update for {task_id}: {str(e)}", exc_info=True
            )

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task."""
        logger.info(f"Attempting to cancel task: {task_id}")
        task = self.tasks.get(task_id)

        if not task:
            logger.warning(f"Cannot cancel task {task_id}: not found.")
            return False

        if task.status not in [
            TaskStatus.PENDING,
            TaskStatus.ACCEPTED,
            TaskStatus.RUNNING,
        ]:
            logger.warning(
                f"Cannot cancel task {task_id}: task is in terminal state {task.status.name}."
            )
            return False

        try:
            # Update status locally first
            original_status = task.status
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now(timezone.utc)
            task.error = "Task cancelled by master request."

            # If the task was running, attempt to cancel its future (if applicable)
            # Note: Standard thread pool executor doesn't directly support cancellation
            # of running tasks. This logic might need adjustment based on how tasks are run.
            # If using asyncio tasks directly, we could cancel them.
            # For now, we just mark it cancelled. The wrapper will eventually notice.
            logger.info(
                f"Marked task {task_id} as CANCELLED (was {original_status.name})."
            )

            # Send final cancellation status to master (handled by wrapper on completion/error)
            # We don't need to send a separate status update here because the wrapper will
            # send the final CANCELLED status via _send_task_result.
            # However, the _handle_task_cancel method WILL send a confirmation back immediately.

            # Clean up might happen in the wrapper's finally block
            # If the task was PENDING/ACCEPTED but not yet running, remove it here.
            if original_status in [TaskStatus.PENDING, TaskStatus.ACCEPTED]:
                if task_id in self.tasks:
                    del self.tasks[task_id]
                self.active_tasks = max(0, self.active_tasks - 1)
                logger.debug(
                    f"Removed non-running cancelled task {task_id}. Active tasks: {self.active_tasks}"
                )
                # Since it wasn't running, send the final status now
                await self._send_task_result(
                    task_id, None, TaskStatus.CANCELLED, task.error
                )

            return True
        except Exception as e:
            logger.error(f"Error cancelling task {task_id}: {str(e)}", exc_info=True)
            # Try to revert status if cancellation failed? Probably not necessary.
            return False

    def _handle_autonomous_test(self, task: DistributedTask) -> Dict[str, Any]:
        """
        Handle autonomous testing task using the AutonomousTester.

        Args:
            task: The task containing testing parameters

        Returns:
            Dictionary with test results
        """
        logger.info(f"Handling autonomous test task: {task.id}")

        try:
            # Extract testing parameters from task data
            params = task.parameters
            target_url = params.get("target_url")
            vuln_type_str = params.get("vulnerability_type")

            if not target_url:
                return {
                    "status": "error",
                    "message": "Missing required parameter: target_url",
                }

            # Convert vulnerability type string to enum
            try:
                vulnerability_type = (
                    VulnerabilityType(vuln_type_str) if vuln_type_str else None
                )
            except ValueError:
                vulnerability_type = None

            # Extract optional parameters
            request_params = params.get("request_params", {})
            headers = params.get("headers", {})
            cookies = params.get("cookies", {})

            # Perform comprehensive scan if no specific vulnerability type is provided
            if vulnerability_type:
                # Test for specific vulnerability
                results = self.autonomous_tester.test_vulnerability(
                    target_url=target_url,
                    vulnerability_type=vulnerability_type,
                    params=request_params,
                    headers=headers,
                    cookies=cookies,
                    count=params.get("payload_count", 5),
                )

                # Convert payload results to serializable format
                serialized_results = []
                for result in results:
                    serialized_results.append(
                        {
                            "payload": result.payload.value,
                            "vulnerability_type": result.payload.vulnerability_type.value,
                            "success": result.success,
                            "evidence": result.evidence,
                            "response_code": result.response_code,
                            "response_time": result.response_time,
                            "notes": result.notes,
                        }
                    )

                return {
                    "status": "completed",
                    "vulnerability_type": vulnerability_type.value,
                    "results": serialized_results,
                    "target_url": target_url,
                    "successful_payloads": sum(1 for r in results if r.success),
                }
            else:
                # Perform comprehensive scan
                scan_results = self.autonomous_tester.comprehensive_scan(
                    target_url=target_url,
                    params=request_params,
                    headers=headers,
                    cookies=cookies,
                )

                # Get summary of results
                summary = self.autonomous_tester.get_summary(scan_results)

                # Convert to serializable format
                serializable_results = {}
                for vuln_type, results_list in scan_results.items():
                    serializable_results[vuln_type] = []
                    for result in results_list:
                        serializable_results[vuln_type].append(
                            {
                                "payload": result.payload.value,
                                "success": result.success,
                                "evidence": result.evidence,
                                "response_code": result.response_code,
                            }
                        )

                return {
                    "status": "completed",
                    "comprehensive_scan": True,
                    "summary": summary,
                    "detailed_results": serializable_results,
                    "target_url": target_url,
                }

        except Exception as e:
            logger.error(f"Error in autonomous test task: {e}", exc_info=True)
            return {
                "status": "error",
                "message": str(e),
                "traceback": str(e.__traceback__),
            }

    def _handle_vulnerability_scan(self, task: DistributedTask) -> Dict[str, Any]:
        """Handle vulnerability scanning task."""
        logger.info(f"Handling vulnerability scan task: {task.id}")
        # Implementation for vulnerability scanning
        # This could use other components from the Sniper framework
        return {
            "status": "completed",
            "message": "Vulnerability scan completed",
            "results": [],  # Placeholder for actual scan results
        }

    def _handle_recon_task(self, task: DistributedTask) -> Dict[str, Any]:
        """Handle reconnaissance task."""
        logger.info(f"Handling recon task: {task.id}")
        # Implementation for reconnaissance tasks
        # This could use the SmartRecon component
        return {
            "status": "completed",
            "message": "Reconnaissance completed",
            "results": [],  # Placeholder for actual recon results
        }

    async def status_update(self) -> Dict[str, Any]:
        """Get status information about the worker node."""
        # This should return general node status, not task-specific status
        return {
            "node_id": self.id,
            "status": self.status.name,
            "load": (
                self.active_tasks / self.max_concurrent_tasks
                if self.max_concurrent_tasks > 0
                else 0
            ),
            "active_tasks": self.active_tasks,
            "capabilities": self.capabilities,
            "uptime": self.uptime(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class WorkerNodeClient:
    """
    Wrapper class for SniperWorkerNode to handle configuration and startup.
    """

    def __init__(
        self,
        master_host: str,
        master_port: int,
        worker_id: Optional[str] = None,
        protocol_type: str = "REST",
        capabilities: List[str] = None,
        max_tasks: int = 5,
        heartbeat_interval: int = 30,
        config_path: Optional[str] = None,
    ):
        """
        Initialize the worker node client.

        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            worker_id: Optional specific ID for this worker
            protocol_type: Communication protocol to use
            capabilities: List of task types this worker can execute
            max_tasks: Maximum number of concurrent tasks
            heartbeat_interval: Interval in seconds for sending heartbeats
            config_path: Optional path to configuration file
        """
        # Load config if provided
        config = {}
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                logger.error(f"Error loading config from {config_path}: {e}")
                
        # Use worker_id if provided, otherwise it will be generated by SniperWorkerNode
        self.worker_node = SniperWorkerNode(
            master_host=master_host,
            master_port=master_port,
            protocol_type=protocol_type,
            capabilities=capabilities,
            max_concurrent_tasks=max_tasks,
            heartbeat_interval=heartbeat_interval,
            node_id=worker_id,
        )

    def register_task_handler(self, task_type: str, handler: Callable) -> None:
        """
        Register a handler function for a specific task type.

        Args:
            task_type: Type of task the handler can process
            handler: Function to handle the task execution
        """
        self.worker_node.register_task_handler(task_type, handler)

    async def start(self) -> bool:
        """Start the worker node client."""
        return await self.worker_node.start()

    async def stop(self) -> bool:
        """Stop the worker node client."""
        return await self.worker_node.stop()
