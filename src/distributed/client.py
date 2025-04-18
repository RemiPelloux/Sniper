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
from typing import Dict, List, Callable, Any, Optional, Union

from .worker import WorkerNodeClient, SniperWorkerNode
from .base import TaskStatus, TaskPriority
from .protocol import create_protocol, ProtocolMessage
from src.ml.autonomous_tester import VulnerabilityType

logger = logging.getLogger("sniper.distributed.client")

def setup_logging(log_level: str = "INFO", log_file: str = None):
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
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            *([] if not log_file else [logging.FileHandler(log_file)])
        ]
    )
    
    # Set level for our loggers
    for logger_name in ["sniper.distributed", "sniper.distributed.client", 
                        "sniper.distributed.worker", "sniper.distributed.protocol"]:
        logging.getLogger(logger_name).setLevel(numeric_level)

def create_worker_client(master_host: str, master_port: int, 
                        protocol_type: str = "REST",
                        capabilities: List[str] = None,
                        max_concurrent_tasks: int = 5,
                        heartbeat_interval: int = 30) -> WorkerNodeClient:
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
        heartbeat_interval=heartbeat_interval
    )
    
    return client

def register_default_handlers(client: WorkerNodeClient) -> None:
    """
    Register default task handlers for common Sniper operations.
    
    Args:
        client: The worker node client to register handlers with
    """
    # Import task handlers from appropriate modules
    from ..scan import scanner
    from ..smartrecon import recon
    from ..analysis import analyzer
    
    # Register scan handler
    def scan_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for scan tasks"""
        try:
            scan_type = kwargs.get("scan_type", "default")
            options = kwargs.get("options", {})
            
            logger.info(f"Running {scan_type} scan on {target}")
            result = scanner.run_scan(target, scan_type, options)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in scan handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register recon handler
    def recon_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for reconnaissance tasks"""
        try:
            recon_type = kwargs.get("recon_type", "default")
            depth = kwargs.get("depth", 1)
            
            logger.info(f"Running {recon_type} recon on {target} with depth {depth}")
            result = recon.run_recon(target, recon_type, depth)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in recon handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register analysis handler
    def analysis_handler(target: str, **kwargs) -> Dict[str, Any]:
        """Handler for analysis tasks"""
        try:
            analysis_type = kwargs.get("analysis_type", "default")
            data = kwargs.get("data", {})
            
            logger.info(f"Running {analysis_type} analysis on {target}")
            result = analyzer.analyze(target, analysis_type, data)
            return {"status": "success", "findings": result}
        except Exception as e:
            logger.error(f"Error in analysis handler: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # Register all handlers with the client
    client.register_task_handler("scan", scan_handler)
    client.register_task_handler("recon", recon_handler)
    client.register_task_handler("analysis", analysis_handler)
    
    logger.info("Registered default task handlers for scan, recon, and analysis")

def run_worker(master_host: str, master_port: int, 
               protocol_type: str = "REST",
               capabilities: List[str] = None,
               max_concurrent_tasks: int = 5,
               heartbeat_interval: int = 30,
               register_defaults: bool = True,
               log_level: str = "INFO") -> None:
    """
    Run a worker node client (blocking).
    
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
    
    logger.info(f"Starting Sniper worker node, connecting to {master_host}:{master_port}")
    
    # Create client
    client = create_worker_client(
        master_host=master_host,
        master_port=master_port,
        protocol_type=protocol_type,
        capabilities=capabilities,
        max_concurrent_tasks=max_concurrent_tasks,
        heartbeat_interval=heartbeat_interval
    )
    
    # Register default handlers if requested
    if register_defaults:
        register_default_handlers(client)
    
    try:
        # Start the client
        if not client.start():
            logger.error("Failed to start worker node client")
            sys.exit(1)
        
        logger.info("Worker node started successfully")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Error in worker node: {str(e)}")
    finally:
        # Stop the client
        client.stop()
        logger.info("Worker node stopped")

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
        self.protocol = create_protocol(protocol_type)
        self.client_id = f"client-{int(time.time())}"
        
        # Connection management
        self.connected = False
    
    async def connect(self) -> bool:
        """
        Connect to the master node.
        
        Returns:
            True if connection was successful, False otherwise
        """
        if self.connected:
            logger.warning("Already connected to master node")
            return True
        
        try:
            await self.protocol.connect(self.master_host, self.master_port)
            self.connected = True
            logger.info(f"Connected to master node at {self.master_host}:{self.master_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to master node: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """
        Disconnect from the master node.
        
        Returns:
            True if disconnection was successful, False otherwise
        """
        if not self.connected:
            logger.warning("Not connected to master node")
            return True
        
        try:
            await self.protocol.disconnect()
            self.connected = False
            logger.info("Disconnected from master node")
            return True
        except Exception as e:
            logger.error(f"Error disconnecting from master node: {e}")
            return False
    
    async def _send_message(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """
        Send a message to the master node.
        
        Args:
            message: Protocol message to send
            
        Returns:
            Response message or None if error
        """
        if not self.connected:
            if not await self.connect():
                logger.error("Unable to connect to master node")
                return None
        
        try:
            response = await self.protocol.send_message(message)
            return response
        except Exception as e:
            logger.error(f"Error sending message to master node: {e}")
            return None
    
    async def submit_autonomous_test(self, 
                                    target_url: str, 
                                    vulnerability_type: Optional[Union[str, VulnerabilityType]] = None,
                                    request_params: Dict[str, Any] = None,
                                    headers: Dict[str, str] = None,
                                    cookies: Dict[str, str] = None,
                                    payload_count: int = 5,
                                    priority: TaskPriority = TaskPriority.MEDIUM) -> Optional[str]:
        """
        Submit an autonomous vulnerability testing task.
        
        Args:
            target_url: URL to test
            vulnerability_type: Specific vulnerability type to test, or None for comprehensive scan
            request_params: Optional HTTP request parameters
            headers: Optional HTTP headers
            cookies: Optional cookies
            payload_count: Number of payloads to test
            priority: Task priority
            
        Returns:
            Task ID if submission was successful, None otherwise
        """
        # Convert vulnerability type enum to string if needed
        vuln_type_str = None
        if vulnerability_type:
            if isinstance(vulnerability_type, VulnerabilityType):
                vuln_type_str = vulnerability_type.value
            else:
                vuln_type_str = vulnerability_type
        
        # Prepare task parameters
        params = {
            "target_url": target_url,
            "vulnerability_type": vuln_type_str,
            "request_params": request_params or {},
            "headers": headers or {},
            "cookies": cookies or {},
            "payload_count": payload_count,
            "priority": priority.value if isinstance(priority, TaskPriority) else priority
        }
        
        # Create message
        message = ProtocolMessage(
            message_type=MessageType.SUBMIT_TASK,
            sender_id=self.client_id,
            receiver_id="master",
            payload={
                "task_type": "autonomous_test",
                "parameters": params,
                "priority": priority.value if isinstance(priority, TaskPriority) else priority
            }
        )
        
        # Send message and process response
        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_SUBMITTED:
            task_id = response.payload.get("task_id")
            logger.info(f"Successfully submitted autonomous test task: {task_id}")
            return task_id
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to submit autonomous test task: {error_msg}")
            return None
    
    async def submit_comprehensive_scan(self, 
                                      target_url: str,
                                      request_params: Dict[str, Any] = None,
                                      headers: Dict[str, str] = None,
                                      cookies: Dict[str, str] = None,
                                      priority: TaskPriority = TaskPriority.HIGH) -> Optional[str]:
        """
        Submit a comprehensive vulnerability scan task.
        
        Args:
            target_url: URL to test
            request_params: Optional HTTP request parameters
            headers: Optional HTTP headers
            cookies: Optional cookies
            priority: Task priority
            
        Returns:
            Task ID if submission was successful, None otherwise
        """
        # This is essentially an autonomous test without a specific vulnerability type
        return await self.submit_autonomous_test(
            target_url=target_url,
            vulnerability_type=None,
            request_params=request_params,
            headers=headers,
            cookies=cookies,
            priority=priority
        )
    
    async def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """
        Get the status of a task.
        
        Args:
            task_id: Task ID to check
            
        Returns:
            Task status or None if error
        """
        message = ProtocolMessage(
            message_type=MessageType.TASK_STATUS_REQUEST,
            sender_id=self.client_id,
            receiver_id="master",
            payload={"task_id": task_id}
        )
        
        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_STATUS_RESPONSE:
            status_str = response.payload.get("status")
            try:
                return TaskStatus(status_str)
            except (ValueError, TypeError):
                logger.error(f"Invalid task status received: {status_str}")
                return None
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to get status for task {task_id}: {error_msg}")
            return None
    
    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the result of a completed task.
        
        Args:
            task_id: Task ID to get results for
            
        Returns:
            Task result dictionary or None if error or not completed
        """
        message = ProtocolMessage(
            message_type=MessageType.TASK_RESULT_REQUEST,
            sender_id=self.client_id,
            receiver_id="master",
            payload={"task_id": task_id}
        )
        
        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_RESULT_RESPONSE:
            if response.payload.get("status") == "completed":
                return response.payload.get("result")
            else:
                logger.warning(f"Task {task_id} is not completed yet. Status: {response.payload.get('status')}")
                return None
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to get result for task {task_id}: {error_msg}")
            return None
    
    async def wait_for_task_completion(self, task_id: str, polling_interval: float = 5.0, timeout: float = 300.0) -> Optional[Dict[str, Any]]:
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
            elif status in [TaskStatus.FAILED, TaskStatus.CANCELED]:
                logger.warning(f"Task {task_id} ended with status {status}")
                return await self.get_task_result(task_id)  # Get result which may contain error info
            
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
            payload={"task_id": task_id}
        )
        
        response = await self._send_message(message)
        if response and response.message_type == MessageType.TASK_CANCELED:
            logger.info(f"Successfully canceled task {task_id}")
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
            payload={}
        )
        
        response = await self._send_message(message)
        if response and response.message_type == MessageType.STATUS_RESPONSE:
            return response.payload
        else:
            error_msg = response.payload.get("error") if response else "Unknown error"
            logger.error(f"Failed to get master status: {error_msg}")
            return None

async def run_autonomous_test(master_host: str, master_port: int, target_url: str, 
                           vulnerability_type: Optional[str] = None) -> Dict[str, Any]:
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
            target_url=target_url,
            vulnerability_type=vulnerability_type
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
    parser.add_argument("--heartbeat", type=int, default=30, help="Heartbeat interval (seconds)")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--capabilities", nargs="+", default=["scan", "vuln", "recon"], 
                        help="Supported task types")
    
    args = parser.parse_args()
    
    run_worker(
        master_host=args.host,
        master_port=args.port,
        protocol_type=args.protocol,
        capabilities=args.capabilities,
        max_concurrent_tasks=args.max_tasks,
        heartbeat_interval=args.heartbeat,
        log_level=args.log_level
    ) 