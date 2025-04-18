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
import requests
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Callable
import traceback

from src.distributed.base import BaseNode, NodeStatus, DistributedTask, TaskStatus, TaskPriority, NodeInfo, NodeRole
from src.distributed.protocol import create_protocol, ProtocolMessage, MessageType, ProtocolBase
from src.distributed.protocol import HeartbeatMessage, TaskResultMessage
from src.core.logging import setup_logging
from src.ml.autonomous_tester import AutonomousTester, VulnerabilityType

logger = logging.getLogger("sniper.distributed.worker")

class SniperWorkerNode(BaseNode):
    """
    Sniper Worker Node implementation for distributed scanning architecture.
    
    Handles task execution and reporting results back to the master node.
    """
    
    def __init__(self, master_host: str, master_port: int, 
                 protocol_type: str = "REST",
                 capabilities: List[str] = None,
                 max_concurrent_tasks: int = 5,
                 heartbeat_interval: int = 30):
        """
        Initialize the Sniper Worker Node.
        
        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            protocol_type: Communication protocol to use (default: "REST")
            capabilities: List of task types this worker can execute
            max_concurrent_tasks: Maximum number of concurrent tasks
            heartbeat_interval: Interval in seconds for sending heartbeats
        """
        super().__init__(node_id=f"worker-{uuid.uuid4()}")
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
        self.register_task_handler("vulnerability_scan", self._handle_vulnerability_scan)
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
            logger.info(f"Connecting to master node at {self.master_host}:{self.master_port}")
            if not await self._register_with_master():
                logger.error("Failed to register with master node")
                return False
                
            # Set status to active
            self.status = NodeStatus.ACTIVE
            self.running = True
            
            # Start heartbeat thread
            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True
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
                 payload=worker_info.to_dict()
            )

            # Send registration message
            response_dict = await self.protocol.send_message(reg_message)

            # Process response (assuming send_message returns a dict or None)
            if response_dict and response_dict.get("message_type") == MessageType.REGISTER_RESPONSE.name:
                payload = response_dict.get("payload", {})
                if payload.get("status") == "success":
                    self.master_id = response_dict.get("sender_id")
                    self.status = NodeStatus.IDLE
                    logger.info(f"Successfully registered with master node {self.master_id}")
                    return True
                else:
                    logger.error(f"Master rejected registration: {payload.get('message')}")
                    return False
            else:
                logger.error(f"Failed to register with master node, invalid or no response: {response_dict}")
                return False
        except Exception as e:
            logger.error(f"Error registering with master node: {str(e)}")
            return False
    
    def _heartbeat_loop(self) -> None:
        """Periodically send heartbeats to the master node."""
        while self.running:
            try:
                self._send_heartbeat()
                time.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {str(e)}")
                time.sleep(5)  # Retry after a short delay
    
    def _send_heartbeat(self) -> None:
        """Send a heartbeat message to the master node."""
        if not self.protocol or not self.master_id:
            logger.warning("Cannot send heartbeat: not connected to master")
            return
            
        try:
            # Create heartbeat message with metrics
            metrics = {
                "load": self.active_tasks / self.max_concurrent_tasks if self.max_concurrent_tasks > 0 else 0,
                "task_count": self.task_count,
                "success_rate": self.success_count / self.task_count if self.task_count > 0 else 1.0,
                "active_tasks": self.active_tasks
            }
            
            heartbeat_msg = ProtocolMessage(
                message_type=MessageType.HEARTBEAT,
                sender_id=self.id,
                receiver_id=self.master_id,
                payload=metrics
            )
            
            # Send heartbeat
            response = self.protocol.send_message(heartbeat_msg)
            
            if response and response.message_type == MessageType.HEARTBEAT_ACK:
                logger.debug("Heartbeat acknowledged by master")
            else:
                logger.warning("Heartbeat not acknowledged by master")
        except Exception as e:
            logger.error(f"Error sending heartbeat: {str(e)}")
    
    def handle_message(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """Handle incoming messages from the master node."""
        try:
            if message.message_type == MessageType.TASK_ASSIGNMENT:
                return self._handle_task_assignment(message)
            elif message.message_type == MessageType.TASK_CANCEL:
                return self._handle_task_cancel(message)
            else:
                logger.warning(f"Unknown message type: {message.message_type}")
                return None
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            return None
    
    def _handle_task_assignment(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """Handle task assignment messages from the master node."""
        try:
            # Parse task data
            task_data = json.loads(message.data)
            task = DistributedTask.from_dict(task_data)
            
            logger.info(f"Received task assignment: {task.task_id} (Type: {task.task_type})")
            
            # Check if we can handle this task type
            if task.task_type not in self.capabilities:
                logger.warning(f"Cannot handle task type: {task.task_type}")
                return ProtocolMessage(
                    sender=self.node_id,
                    recipient=message.sender,
                    message_type=MessageType.TASK_STATUS,
                    data=json.dumps({
                        "task_id": task.task_id,
                        "status": TaskStatus.REJECTED.name,
                        "reason": f"Worker does not support task type: {task.task_type}"
                    })
                )
            
            # Check if we have capacity
            if self.active_tasks >= self.max_concurrent_tasks:
                logger.warning("Cannot accept task: at maximum capacity")
                return ProtocolMessage(
                    sender=self.node_id,
                    recipient=message.sender,
                    message_type=MessageType.TASK_STATUS,
                    data=json.dumps({
                        "task_id": task.task_id,
                        "status": TaskStatus.REJECTED.name,
                        "reason": "Worker at maximum capacity"
                    })
                )
            
            # Accept and store the task
            self.tasks[task.task_id] = task
            
            # Submit task for execution
            asyncio.create_task(self._execute_task_wrapper(task))
            
            # Send acceptance message
            return ProtocolMessage(
                sender=self.node_id,
                recipient=message.sender,
                message_type=MessageType.TASK_STATUS,
                data=json.dumps({
                    "task_id": task.task_id,
                    "status": TaskStatus.RUNNING.name
                })
            )
        except Exception as e:
            logger.error(f"Error handling task assignment: {str(e)}")
            return None
    
    def _handle_task_cancel(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """Handle task cancellation messages from the master node."""
        try:
            # Parse cancellation data
            cancel_data = json.loads(message.data)
            task_id = cancel_data.get("task_id")
            
            if not task_id or task_id not in self.tasks:
                logger.warning(f"Cannot cancel unknown task: {task_id}")
                return None
                
            logger.info(f"Received cancellation for task: {task_id}")
            
            # Cancel the task
            asyncio.create_task(self.cancel_task(task_id))
            
            # Send acknowledgment immediately (cancellation happens in background)
            return ProtocolMessage(
                sender=self.node_id,
                recipient=message.sender,
                message_type=MessageType.TASK_STATUS,
                data=json.dumps({
                    "task_id": task_id,
                    "status": TaskStatus.CANCELLED.name
                })
            )
        except Exception as e:
            logger.error(f"Error handling task cancellation: {str(e)}")
            return None
    
    async def _execute_task_wrapper(self, task: DistributedTask):
        """Acquires semaphore and wraps the actual task execution with error handling."""
        task_id = task.id # Get id early
        if not self.task_semaphore:
             logger.error(f"Task semaphore not initialized. Cannot execute task {task_id}.")
             # Mark task as failed immediately and notify master
             if task_id in self.tasks:
                 self.tasks[task_id].status = TaskStatus.FAILED
                 self.tasks[task_id].completed_at = datetime.now(timezone.utc)
             await self.status_update(task_id, TaskStatus.FAILED, message="Worker semaphore not initialized")
             return

        async with self.task_semaphore:
            self.active_tasks += 1
            logger.info(f"Starting execution for task {task_id}... Active tasks: {self.active_tasks}")
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(timezone.utc)
            await self.status_update(task_id, TaskStatus.RUNNING)

            result = None
            final_status = TaskStatus.FAILED # Default to failed

            try:
                handler = self.task_handlers.get(task.task_type)
                if not handler:
                    raise ValueError(f"No handler registered for task type: {task.task_type}")

                logger.debug(f"Executing task {task_id} ({task.task_type}) with handler {handler.__name__}")
                # Check if handler is async or sync
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(task.target, **task.parameters)
                else:
                    # Run sync handler in thread pool executor
                    loop = asyncio.get_running_loop()
                    result = await loop.run_in_executor(
                        self.executor, handler, task.target, *task.parameters.values()
                    )
                logger.info(f"Task {task_id} completed successfully by handler.")
                final_status = TaskStatus.COMPLETED

            except Exception as e:
                logger.error(f"Error executing task {task_id}: {e}", exc_info=True)
                # Status remains FAILED (or set explicitly)
                final_status = TaskStatus.FAILED
                # Store error information if needed
                # task.error_message = str(e)

            finally:
                self.active_tasks -= 1
                logger.info(f"Finished execution for task {task_id}. Final status: {final_status.value}. Active tasks: {self.active_tasks}")
                # Update task object in worker's memory
                if task_id in self.tasks:
                    task_ref = self.tasks[task_id]
                    task_ref.status = final_status
                    task_ref.completed_at = datetime.now(timezone.utc)
                    task_ref.result = result if final_status == TaskStatus.COMPLETED else None
                    # Optionally store error details if failed
                    # task_ref.error_message = str(e) if final_status == TaskStatus.FAILED else None
                else:
                     logger.warning(f"Task {task_id} not found in worker tasks during finally block.")

                # Send final status/result to master
                try:
                    # Send result only if completed successfully
                    await self._send_task_result(
                        task_id, result if final_status == TaskStatus.COMPLETED else None, final_status
                    )
                except Exception as send_error:
                    logger.error(f"Failed to send final status/result for task {task_id} to master: {send_error}", exc_info=True)

    def execute_task(self, task: DistributedTask) -> Dict[str, Any]:
        """
        Execute a distributed task.
        
        Args:
            task: The task to execute
            
        Returns:
            Dict[str, Any]: The result of the task execution
            
        Raises:
            ValueError: If the task type is not supported
        """
        task_type = task.task_type
        
        # Check if we have a handler for this task type
        if task_type not in self.task_handlers:
            raise ValueError(f"No handler registered for task type: {task_type}")
            
        # Get the handler function
        handler = self.task_handlers[task_type]
        
        # Execute the handler with task parameters
        logger.info(f"Executing task {task.task_id} (Type: {task_type})")
        result = handler(task.target, **task.parameters)
        
        return result
    
    async def _send_task_result(self, task_id: str, result: Dict[str, Any], status: TaskStatus) -> None:
        """
        Send task result to the master node.
        
        Args:
            task_id: ID of the completed task
            result: Result data from the task execution
            status: Final status of the task
        """
        if not self.protocol or not self.master_id:
            logger.warning("Cannot send result: not connected to master")
            return
            
        try:
            # Create result message
            result_payload = {
                "task_id": task_id,
                "status": status.value,
                "result": result
            }
            
            result_msg = ProtocolMessage(
                message_type=MessageType.TASK_RESULT,
                sender_id=self.id,
                receiver_id=self.master_id,
                payload=result_payload
            )
            
            # Send result to master using async executor
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                self.executor,
                self.protocol.send_message,
                result_msg
            )
            
            if response and response.get("message_type") == MessageType.TASK_RESULT_ACK.name:
                logger.info(f"Result for task {task_id} acknowledged by master")
            else:
                logger.warning(f"Result for task {task_id} not acknowledged by master")
        except Exception as e:
            logger.error(f"Error sending task result: {str(e)}", exc_info=True)
    
    async def status_update(self, task_id: str, status: TaskStatus, message: str = "") -> None:
        """
        Update the status of a task and notify the master node.
        
        Args:
            task_id: ID of the task to update
            status: New status for the task
            message: Optional message with additional information
        """
        if task_id not in self.tasks:
            logger.warning(f"Task {task_id} not found for status update")
            return
            
        # Update task status
        task = self.tasks[task_id]
        task.status = status
        
        # Send status update to master
        if self.protocol and self.master_id:
            try:
                # Create status update message using generic ProtocolMessage
                status_payload = {
                    "task_id": task_id,
                    "status": status.value,
                    "message": message
                }
                status_msg = ProtocolMessage(
                    message_type=MessageType.TASK_STATUS,
                    sender_id=self.id,
                    receiver_id=self.master_id,
                    payload=status_payload
                )

                # Send status update
                # Use asyncio to handle potential blocking calls
                loop = asyncio.get_running_loop()
                response_dict = await loop.run_in_executor(
                    self.executor, 
                    self.protocol.send_message,
                    status_msg
                )

                if response_dict and response_dict.get("message_type") == MessageType.TASK_STATUS_RESPONSE.name:
                    logger.debug(f"Status update for task {task_id} acknowledged by master")
                else:
                    logger.warning(f"Status update for task {task_id} not acknowledged by master: {response_dict}")
            except Exception as e:
                logger.error(f"Error sending status update: {str(e)}", exc_info=True)
    
    async def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.
        
        Args:
            task_id: ID of the task to cancel
            
        Returns:
            bool: True if cancellation successful, False otherwise
        """
        if task_id not in self.tasks:
            logger.warning(f"Task {task_id} not found for cancellation")
            return False
            
        task = self.tasks[task_id]
        
        # Update task status
        task.status = TaskStatus.CANCELLED
        task.completed_at = datetime.now(timezone.utc)
        
        # Notify master of cancellation
        await self.status_update(task_id, TaskStatus.CANCELLED)
        
        logger.info(f"Task {task_id} cancelled")
        return True

    def _handle_autonomous_test(self, task: DistributedTask) -> Dict[str, Any]:
        """
        Handle autonomous testing task using the AutonomousTester.
        
        Args:
            task: The task containing testing parameters
            
        Returns:
            Dictionary with test results
        """
        logger.info(f"Handling autonomous test task: {task.task_id}")
        
        try:
            # Extract testing parameters from task data
            params = task.parameters
            target_url = params.get("target_url")
            vuln_type_str = params.get("vulnerability_type")
            
            if not target_url:
                return {
                    "status": "error",
                    "message": "Missing required parameter: target_url"
                }
                
            # Convert vulnerability type string to enum
            try:
                vulnerability_type = VulnerabilityType(vuln_type_str) if vuln_type_str else None
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
                    count=params.get("payload_count", 5)
                )
                
                # Convert payload results to serializable format
                serialized_results = []
                for result in results:
                    serialized_results.append({
                        "payload": result.payload.value,
                        "vulnerability_type": result.payload.vulnerability_type.value,
                        "success": result.success,
                        "evidence": result.evidence,
                        "response_code": result.response_code,
                        "response_time": result.response_time,
                        "notes": result.notes
                    })
                
                return {
                    "status": "completed",
                    "vulnerability_type": vulnerability_type.value,
                    "results": serialized_results,
                    "target_url": target_url,
                    "successful_payloads": sum(1 for r in results if r.success)
                }
            else:
                # Perform comprehensive scan
                scan_results = self.autonomous_tester.comprehensive_scan(
                    target_url=target_url,
                    params=request_params,
                    headers=headers,
                    cookies=cookies
                )
                
                # Get summary of results
                summary = self.autonomous_tester.get_summary(scan_results)
                
                # Convert to serializable format
                serializable_results = {}
                for vuln_type, results_list in scan_results.items():
                    serializable_results[vuln_type] = []
                    for result in results_list:
                        serializable_results[vuln_type].append({
                            "payload": result.payload.value,
                            "success": result.success,
                            "evidence": result.evidence,
                            "response_code": result.response_code
                        })
                
                return {
                    "status": "completed",
                    "comprehensive_scan": True,
                    "summary": summary,
                    "detailed_results": serializable_results,
                    "target_url": target_url
                }
                
        except Exception as e:
            logger.error(f"Error in autonomous test task: {e}", exc_info=True)
            return {
                "status": "error",
                "message": str(e),
                "traceback": str(e.__traceback__)
            }
    
    def _handle_vulnerability_scan(self, task: DistributedTask) -> Dict[str, Any]:
        """Handle vulnerability scanning task."""
        logger.info(f"Handling vulnerability scan task: {task.task_id}")
        # Implementation for vulnerability scanning
        # This could use other components from the Sniper framework
        return {
            "status": "completed",
            "message": "Vulnerability scan completed",
            "results": []  # Placeholder for actual scan results
        }
    
    def _handle_recon_task(self, task: DistributedTask) -> Dict[str, Any]:
        """Handle reconnaissance task."""
        logger.info(f"Handling recon task: {task.task_id}")
        # Implementation for reconnaissance tasks
        # This could use the SmartRecon component
        return {
            "status": "completed",
            "message": "Reconnaissance completed",
            "results": []  # Placeholder for actual recon results
        }

class WorkerNodeClient:
    """
    Wrapper class for SniperWorkerNode to handle configuration and startup.
    """
    
    def __init__(self, master_host: str, master_port: int,
                 protocol_type: str = "REST",
                 capabilities: List[str] = None,
                 max_concurrent_tasks: int = 5,
                 heartbeat_interval: int = 30):
        """
        Initialize the worker node client.
        
        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
            protocol_type: Communication protocol to use
            capabilities: List of task types this worker can execute
            max_concurrent_tasks: Maximum number of concurrent tasks
            heartbeat_interval: Interval in seconds for sending heartbeats
        """
        self.worker_node = SniperWorkerNode(
            master_host=master_host,
            master_port=master_port,
            protocol_type=protocol_type,
            capabilities=capabilities,
            max_concurrent_tasks=max_concurrent_tasks,
            heartbeat_interval=heartbeat_interval
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
