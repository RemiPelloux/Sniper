"""
Simplified client implementation for the Typer-based distributed CLI.

This module provides simple client classes to interact with the master and worker nodes.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from src.distributed.base import TaskStatus
from src.distributed.client import SniperClient, create_worker_client
from src.distributed.worker import WorkerNodeClient

logger = logging.getLogger(__name__)


class MasterClient:
    """Simple client to interact with the master node."""
    
    def __init__(self, host: str = "localhost", port: int = 5000):
        """
        Initialize the master client.
        
        Args:
            host: Master node host
            port: Master node port
        """
        self.host = host
        self.port = port
        self._client = SniperClient(master_host=host, master_port=port)
        
    def stop(self) -> bool:
        """
        Stop the master node.
        
        Returns:
            True if successful, False otherwise
        """
        # This is a placeholder - in a real implementation, 
        # there would be a specific API call to stop the master
        logger.info(f"Stopping master node at {self.host}:{self.port}")
        return True
        
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the master node.
        
        Returns:
            Dictionary with status information
        """
        try:
            # In a real implementation, this would call the async method
            # and handle the event loop properly
            result = asyncio.run(self._client.get_master_status())
            if result:
                return result
            else:
                return {
                    "status": "UNKNOWN",
                    "error": "Could not connect to master node"
                }
        except Exception as e:
            logger.error(f"Error getting master status: {e}")
            return {
                "status": "ERROR",
                "error": str(e)
            }
    
    def get_workers(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of workers connected to the master node.
        
        Args:
            status: Optional status to filter workers by
            
        Returns:
            List of worker information dictionaries
        """
        # This is a placeholder - in a real implementation,
        # this would call the master node's API
        return [
            {
                "id": "worker-1",
                "hostname": "worker1.example.com",
                "address": "192.168.1.101",
                "status": "ACTIVE",
                "capabilities": ["port_scan", "web_scan"],
                "last_heartbeat": "2023-01-01T00:00:00Z",
            },
            {
                "id": "worker-2",
                "hostname": "worker2.example.com",
                "address": "192.168.1.102", 
                "status": "IDLE",
                "capabilities": ["web_scan", "vuln_scan"],
                "last_heartbeat": "2023-01-01T00:00:00Z",
            },
        ]
    
    def get_tasks(self, status: Optional[str] = None, task_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of tasks managed by the master node.
        
        Args:
            status: Optional status to filter tasks by
            task_type: Optional task type to filter by
            
        Returns:
            List of task information dictionaries
        """
        # This is a placeholder - in a real implementation,
        # this would call the master node's API
        return [
            {
                "id": "task-1",
                "type": "port_scan",
                "target": "example.com",
                "status": "COMPLETED",
                "assigned_worker": "worker-1",
                "created_at": "2023-01-01T00:00:00Z",
                "priority": "HIGH",
            },
            {
                "id": "task-2",
                "type": "web_scan",
                "target": "test.com",
                "status": "RUNNING",
                "assigned_worker": "worker-2",
                "created_at": "2023-01-01T00:00:00Z",
                "priority": "MEDIUM",
            },
        ]
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.
        
        Args:
            task_id: ID of the task to cancel
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # In a real implementation, this would call the async method
            # and handle the event loop properly
            result = asyncio.run(self._client.cancel_task(task_id))
            return result
        except Exception as e:
            logger.error(f"Error canceling task {task_id}: {e}")
            return False
    
    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a task.
        
        Args:
            task_id: ID of the task to get information for
            
        Returns:
            Dictionary with task information
        """
        try:
            # In a real implementation, this would call the async method
            # and handle the event loop properly
            result = asyncio.run(self._client.get_task_result(task_id))
            if result:
                return {
                    "id": task_id,
                    "type": "port_scan",
                    "target": "example.com",
                    "status": "COMPLETED",
                    "assigned_worker": "worker-1",
                    "created_at": "2023-01-01T00:00:00Z",
                    "completed_at": "2023-01-01T00:10:00Z",
                    "result": result
                }
            else:
                return None
        except Exception as e:
            logger.error(f"Error getting task info for {task_id}: {e}")
            return None


def create_master_client(host: str = "localhost", port: int = 5000) -> MasterClient:
    """
    Create a master client.
    
    Args:
        host: Master node host
        port: Master node port
        
    Returns:
        MasterClient instance
    """
    return MasterClient(host=host, port=port) 