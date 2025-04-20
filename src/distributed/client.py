"""
Client for the Sniper Distributed Scanning Architecture.

This module provides a client interface for interacting with the Sniper master node,
allowing applications to submit scanning tasks and retrieve results.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from src.ml.autonomous_tester import VulnerabilityType

from .base import TaskPriority, TaskStatus
from .protocol import MessageType, ProtocolMessage, create_protocol
from .worker import SniperWorkerNode, WorkerNodeClient

logger = logging.getLogger("sniper.distributed.client")


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Set up logging for the distributed client.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path to log to
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            *([] if not log_file else [logging.FileHandler(log_file)]),
        ],
    )

    # Set level for our loggers
    for logger_name in [
        "sniper.distributed",
        "sniper.distributed.client",
        "sniper.distributed.worker",
        "sniper.distributed.protocol",
    ]:
        logging.getLogger(logger_name).setLevel(numeric_level)


def create_worker_client(
    master_host: str,
    master_port: int,
    protocol_type: str = "REST",
    capabilities: Optional[List[str]] = None,
    max_concurrent_tasks: int = 5,
    heartbeat_interval: int = 30,
) -> WorkerNodeClient:
    """
    Create a new worker node client.

    Args:
        master_host: Host address of the master node
        master_port: Port of the master node
        protocol_type: Communication protocol to use
        capabilities: List of task types this worker can execute
        max_concurrent_tasks: Maximum concurrent tasks
        heartbeat_interval: Heartbeat interval in seconds

    Returns:
        WorkerNodeClient: Configured worker node client
    """
    client = WorkerNodeClient(
        master_host=master_host,
        master_port=master_port,
        protocol_type=protocol_type,
        capabilities=capabilities,
        max_concurrent_tasks=max_concurrent_tasks,
        heartbeat_interval=heartbeat_interval,
    )

    return client


def register_default_handlers(client: WorkerNodeClient) -> None:
    """
    Register default task handlers for common Sniper operations.

    Args:
        client: The worker node client to register handlers with
    """
    # Import task handlers from appropriate modules
    # TODO: Resolve potential circular imports if these modules use client
    # from ..analysis import analyzer
    # from ..scan import scanner
    # from ..smartrecon import recon

    # Define placeholder handlers for now
    def scan_handler(task) -> Dict[str, Any]:
        logger.info(f"Placeholder scan handler called for task: {task.id}")
        time.sleep(2)  # Simulate work
        return {
            "status": TaskStatus.COMPLETED.name,
            "result": "Scan placeholder result",
        }

    def recon_handler(task) -> Dict[str, Any]:
        logger.info(f"Placeholder recon handler called for task: {task.id}")
        time.sleep(3)  # Simulate work
        return {
            "status": TaskStatus.COMPLETED.name,
            "result": "Recon placeholder result",
        }

    def analysis_handler(task) -> Dict[str, Any]:
        logger.info(f"Placeholder analysis handler called for task: {task.id}")
        time.sleep(1)  # Simulate work
        return {
            "status": TaskStatus.COMPLETED.name,
            "result": "Analysis placeholder result",
        }

    # Register all handlers with the client
    client.register_task_handler("scan", scan_handler)
    client.register_task_handler("recon", recon_handler)
    client.register_task_handler("analysis", analysis_handler)

    logger.info("Registered placeholder task handlers for scan, recon, and analysis")


async def _run_worker_async(
    master_host: str,
    master_port: int,
    protocol_type: str = "REST",
    capabilities: Optional[List[str]] = None,
    max_concurrent_tasks: int = 5,
    heartbeat_interval: int = 30,
    register_defaults: bool = True,
    log_level: str = "INFO",
) -> None:
    """Async part of running a worker node client."""
    logger.info(
        f"Starting Sniper worker node (async), connecting to {master_host}:{master_port}"
    )

    # Create client
    client = create_worker_client(
        master_host=master_host,
        master_port=master_port,
        protocol_type=protocol_type,
        capabilities=capabilities,
        max_concurrent_tasks=max_concurrent_tasks,
        heartbeat_interval=heartbeat_interval,
    )

    # Register default handlers if requested
    if register_defaults:
        register_default_handlers(client)

    try:
        # Start the client
        if not await client.start():
            logger.error("Failed to start worker node client")
            raise RuntimeError("Worker client failed to start")

        logger.info("Worker node started successfully")

        # Keep running until interrupted (handled by asyncio loop)
        stop_event = asyncio.Event()
        await stop_event.wait()

    except asyncio.CancelledError:
        logger.info("Worker task cancelled, shutting down...")
    except Exception as e:
        logger.error(f"Error in worker node: {str(e)}", exc_info=True)
    finally:
        # Stop the client
        await client.stop()
        logger.info("Worker node stopped")


def run_worker(
    master_host: str,
    master_port: int,
    protocol_type: str = "REST",
    capabilities: Optional[List[str]] = None,
    max_concurrent_tasks: int = 5,
    heartbeat_interval: int = 30,
    register_defaults: bool = True,
    log_level: str = "INFO",
) -> None:
    """
    Run a worker node client (blocking). Sets up logging and runs the async loop.

    Args:
        master_host: Host address of the master node
        master_port: Port number of the master node
        protocol_type: Communication protocol to use
        capabilities: List of supported task types
        max_concurrent_tasks: Maximum number of concurrent tasks
        heartbeat_interval: Heartbeat interval in seconds
        register_defaults: Whether to register default task handlers
        log_level: Logging level
    """
    # Set up logging
    setup_logging(log_level)

    try:
        asyncio.run(
            _run_worker_async(
                master_host=master_host,
                master_port=master_port,
                protocol_type=protocol_type,
                capabilities=capabilities,
                max_concurrent_tasks=max_concurrent_tasks,
                heartbeat_interval=heartbeat_interval,
                register_defaults=register_defaults,
                log_level=log_level,
            )
        )
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down event loop...")
    except RuntimeError as e:
        logger.error(f"Worker runtime error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unhandled exception in run_worker: {e}", exc_info=True)
        sys.exit(1)


class SniperClient:
    """
    Client for interacting with the Sniper Security Tool's distributed scanning architecture.

    Provides methods to submit tasks, check task status, and retrieve results.
    """

    def __init__(self, master_host: str, master_port: int, protocol_type: str = "REST"):
        """
        Initialize the Sniper client.

        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            protocol_type: Communication protocol to use
        """
        self.master_host = master_host
        self.master_port = master_port
        self.protocol_type = protocol_type.upper()
        self.protocol = create_protocol(self.protocol_type)
        self.client_id = f"client-{int(time.time())}"

        # Connection management
        self.connected = False
        self.heartbeat_interval: Optional[int] = None
        self.listen_task: Optional[asyncio.Task] = None
        self.heartbeat_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """
        Connect to the master node.

        Returns:
            True if connection was successful, False otherwise
        """
        if self.connected:
            logger.warning("Already connected.")
            return True
        try:
            self.connected = await self.protocol.connect(
                self.master_host, self.master_port
            )
            if self.connected:
                logger.info(
                    f"Connected to master at {self.master_host}:{self.master_port}"
                )
            else:
                logger.error("Failed to connect to master.")
            return self.connected
        except Exception as e:
            logger.error(f"Error connecting to master: {str(e)}", exc_info=True)
            self.connected = False
            return False

    async def disconnect(self) -> bool:
        """
        Disconnect from the master node.

        Returns:
            True if disconnection was successful, False otherwise
        """
        if not self.connected:
            logger.warning("Not connected.")
            return True

        try:
            disconnected = await self.protocol.disconnect()
            if disconnected:
                logger.info("Disconnected from master.")
                self.connected = False
                return True
            else:
                logger.warning("Failed to disconnect cleanly.")
                return False
        except Exception as e:
            logger.error(f"Error disconnecting from master: {str(e)}", exc_info=True)
            return False

    async def _send_message(
        self, message: ProtocolMessage
    ) -> Optional[ProtocolMessage]:
        """
        Send a message to the master node and return the response.

        Args:
            message: The ProtocolMessage to send.

        Returns:
            The response ProtocolMessage, or None if failed.
        """
        if not self.connected:
            logger.error("Cannot send message: not connected.")
            return None
        try:
            response = await self.protocol.send_message(message)
            return response
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}", exc_info=True)
            return None

    async def submit_autonomous_test(
        self,
        target_url: str,
        vulnerability_type: Optional[Union[str, VulnerabilityType]] = None,
        request_params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        payload_count: int = 5,
        priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> Optional[str]:
        """
        Submit an autonomous testing task to the master node.

        Args:
            target_url: The URL to test.
            vulnerability_type: Specific vulnerability type to test (enum or string).
                                If None, performs a comprehensive scan.
            request_params: Dictionary of request parameters.
            headers: Dictionary of request headers.
            cookies: Dictionary of request cookies.
            payload_count: Number of payloads to test for specific vulnerability type.
            priority: Task priority.

        Returns:
            The task ID if submission was successful, None otherwise.
        """
        if not self.connected:
            logger.error("Cannot submit task: not connected.")
            return None

        task_type = "autonomous_test"
        params: Dict[str, Any] = {
            "target_url": target_url,
            "request_params": request_params or {},
            "headers": headers or {},
            "cookies": cookies or {},
        }

        if vulnerability_type:
            if isinstance(vulnerability_type, VulnerabilityType):
                params["vulnerability_type"] = vulnerability_type.value
            else:
                params["vulnerability_type"] = vulnerability_type
            params["payload_count"] = payload_count
        else:
            pass

        message = ProtocolMessage(
            message_type=MessageType.SUBMIT_TASK,
            sender_id=self.client_id,
            payload={
                "task_type": task_type,
                "target": target_url,
                "parameters": params,
                "priority": priority.name,
            },
        )

        response = await self._send_message(message)

        if response and response.message_type == MessageType.TASK_SUBMITTED:
            task_id = response.payload.get("task_id")
            logger.info(f"Task submitted successfully. Task ID: {task_id}")
            return task_id
        else:
            error_msg = (
                response.payload.get("message")
                if response and response.payload
                else "Unknown error"
            )
            logger.error(f"Failed to submit task: {error_msg}")
            return None

    async def submit_comprehensive_scan(
        self,
        target_url: str,
        request_params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> Optional[str]:
        """
        Submit a comprehensive autonomous scan task (tests all known types).

        Args:
            target_url: The URL to test.
            request_params: Dictionary of request parameters.
            headers: Dictionary of request headers.
            cookies: Dictionary of request cookies.
            priority: Task priority.

        Returns:
            The task ID if submission was successful, None otherwise.
        """
        return await self.submit_autonomous_test(
            target_url=target_url,
            vulnerability_type=None,
            request_params=request_params,
            headers=headers,
            cookies=cookies,
            priority=priority,
        )

    async def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """
        Query the status of a specific task.

        Args:
            task_id: The ID of the task to query.

        Returns:
            The TaskStatus enum member, or None if failed.
        """
        if not self.connected:
            logger.error("Cannot get task status: not connected.")
            return None

        message = ProtocolMessage(
            message_type=MessageType.TASK_STATUS_REQUEST,
            sender_id=self.client_id,
            payload={"task_id": task_id},
        )

        response = await self._send_message(message)

        if response and response.message_type == MessageType.TASK_STATUS_RESPONSE:
            status_str = response.payload.get("status")
            try:
                status = TaskStatus[status_str.upper()]
                logger.debug(f"Task {task_id} status: {status.name}")
                return status
            except (KeyError, AttributeError):
                logger.error(
                    f"Received invalid status '{status_str}' for task {task_id}"
                )
                return None
        else:
            error_msg = (
                response.payload.get("message")
                if response and response.payload
                else "Unknown error"
            )
            logger.error(f"Failed to get task status for {task_id}: {error_msg}")
            return None

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the result of a completed task.

        Args:
            task_id: The ID of the task to retrieve results for.

        Returns:
            A dictionary containing the task result, or None if failed or not ready.
        """
        if not self.connected:
            logger.error("Cannot get task result: not connected.")
            return None

        message = ProtocolMessage(
            message_type=MessageType.TASK_RESULT_REQUEST,
            sender_id=self.client_id,
            receiver_id="master",
            payload={"task_id": task_id},
        )

        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_RESULT_RESPONSE:
            if response.payload.get("status") == "completed":
                return response.payload.get("result")
            else:
                logger.warning(
                    f"Task {task_id} is not completed yet. Status: {response.payload.get('status')}"
                )
                return None
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to get result for task {task_id}: {error_msg}")
            return None

    async def wait_for_task_completion(
        self, task_id: str, polling_interval: float = 5.0, timeout: float = 300.0
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for a task to complete and return the result.

        Args:
            task_id: Task ID to wait for
            polling_interval: Seconds between status checks
            timeout: Maximum seconds to wait

        Returns:
            Task result dictionary or None if timeout or error
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = await self.get_task_status(task_id)

            if status == TaskStatus.COMPLETED:
                return await self.get_task_result(task_id)
            elif status in [TaskStatus.FAILED, TaskStatus.CANCELLED]:
                logger.warning(f"Task {task_id} ended with status {status}")
                return await self.get_task_result(
                    task_id
                )  # Get result which may contain error info

            await asyncio.sleep(polling_interval)

        logger.error(f"Timeout waiting for task {task_id} to complete")
        return None

    async def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task.

        Args:
            task_id: Task ID to cancel

        Returns:
            True if cancel request was successful, False otherwise
        """
        message = ProtocolMessage(
            message_type=MessageType.CANCEL_TASK,
            sender_id=self.client_id,
            receiver_id="master",
            payload={"task_id": task_id},
        )

        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_CANCELED:
            logger.info(f"Successfully cancelled task {task_id}")
            return True
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to cancel task {task_id}: {error_msg}")
            return False

    async def get_master_status(self) -> Optional[Dict[str, Any]]:
        """
        Get status information from the master node.

        Returns:
            Status dictionary or None if error
        """
        message = ProtocolMessage(
            message_type=MessageType.STATUS_REQUEST,
            sender_id=self.client_id,
            receiver_id="master",
            payload={},
        )

        response = await self._send_message(message)
        if response and response.message_type == MessageType.STATUS_RESPONSE:
            return response.payload
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to get master status: {error_msg}")
            return None


async def run_autonomous_test(
    master_host: str,
    master_port: int,
    target_url: str,
    vulnerability_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function to run an autonomous test and wait for results.

    Args:
        master_host: Host address of the master node
        master_port: Port of the master node
        target_url: URL to test
        vulnerability_type: Specific vulnerability type to test, or None for comprehensive scan

    Returns:
        Test result dictionary or error information
    """
    client = SniperClient(master_host, master_port)

    try:
        # Connect to master
        if not await client.connect():
            return {"status": "error", "message": "Failed to connect to master node"}

        # Submit task
        task_id = await client.submit_autonomous_test(
            target_url=target_url, vulnerability_type=vulnerability_type
        )

        if not task_id:
            return {"status": "error", "message": "Failed to submit task"}

        # Wait for results
        result = await client.wait_for_task_completion(task_id)
        if not result:
            return {"status": "error", "message": "Task timed out or failed"}

        return result
    finally:
        # Always disconnect
        await client.disconnect()


if __name__ == "__main__":
    # Simple command-line handling when run directly
    import argparse

    parser = argparse.ArgumentParser(description="Sniper Distributed Worker Node")
    parser.add_argument("--host", default="localhost", help="Master node host")
    parser.add_argument("--port", type=int, default=5000, help="Master node port")
    parser.add_argument("--protocol", default="REST", help="Communication protocol")
    parser.add_argument("--max-tasks", type=int, default=5, help="Max concurrent tasks")
    parser.add_argument(
        "--heartbeat", type=int, default=30, help="Heartbeat interval (seconds)"
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument(
        "--capabilities",
        nargs="+",
        default=["scan", "vuln", "recon"],
        help="Supported task types",
    )

    args = parser.parse_args()

    run_worker(
        master_host=args.host,
        master_port=args.port,
        protocol_type=args.protocol,
        capabilities=args.capabilities,
        max_concurrent_tasks=args.max_tasks,
        heartbeat_interval=args.heartbeat,
        log_level=args.log_level,
    )
