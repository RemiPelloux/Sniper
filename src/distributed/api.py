"""
API Integration for Sniper's Distributed Scanning System

This module provides a simple API for submitting tasks to the distributed scanning
system and retrieving results without needing to directly interact with the master
node implementation details.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Union

import requests

from src.distributed.autodiscovery import get_discovery_manager
from src.distributed.base import DistributedTask, TaskPriority, TaskStatus
from src.ml.autonomous_tester import VulnerabilityType

logger = logging.getLogger(__name__)


class DistributedAPI:
    """High-level API for interacting with the distributed scanning system."""

    def __init__(self, master_host: str = "localhost", master_port: int = 5000):
        """
        Initialize the distributed API client.

        Args:
            master_host: Host address of the master node
            master_port: Port of the master node
        """
        self.master_host = master_host
        self.master_port = master_port
        self.base_url = f"http://{master_host}:{master_port}"

    async def submit_autonomous_test(
        self,
        target_url: str,
        vulnerability_type: Optional[Union[str, VulnerabilityType]] = None,
        request_params: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        payload_count: int = 5,
        priority: TaskPriority = TaskPriority.MEDIUM,
        wait_for_result: bool = False,
        timeout: int = 300,
    ) -> Union[str, Dict[str, Any]]:
        """
        Submit an autonomous testing task to the distributed system.

        Args:
            target_url: URL to test
            vulnerability_type: Type of vulnerability to test for (or None for auto-detect)
            request_params: Additional request parameters
            headers: HTTP headers to use
            cookies: Cookies to include
            payload_count: Number of payloads to test
            priority: Task priority
            wait_for_result: Whether to wait for the task to complete and return results
            timeout: Timeout in seconds when waiting for results

        Returns:
            If wait_for_result is True, returns the test results.
            Otherwise, returns the task ID.
        """
        # Convert vulnerability type to string if needed
        if isinstance(vulnerability_type, VulnerabilityType):
            vuln_type_str = vulnerability_type.value
        else:
            vuln_type_str = vulnerability_type

        # Create task parameters
        params = {
            "target_url": target_url,
            "vulnerability_type": vuln_type_str,
            "request_params": request_params or {},
            "headers": headers or {},
            "cookies": cookies or {},
            "payload_count": payload_count,
        }

        # Submit task
        task_id = await self._submit_task(
            task_type="autonomous_test",
            target={"url": target_url},
            parameters=params,
            priority=priority,
        )

        # Return task ID or wait for results
        if wait_for_result:
            return await self.wait_for_task_completion(task_id, timeout)
        return task_id

    async def submit_vulnerability_scan(
        self,
        target: Dict[str, Any],
        scan_type: str = "comprehensive",
        parameters: Dict[str, Any] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        wait_for_result: bool = False,
        timeout: int = 600,
    ) -> Union[str, Dict[str, Any]]:
        """
        Submit a vulnerability scanning task to the distributed system.

        Args:
            target: Target information (e.g., {"url": "https://example.com"} or {"host": "192.168.1.1"})
            scan_type: Type of scan to perform
            parameters: Additional scan parameters
            priority: Task priority
            wait_for_result: Whether to wait for the task to complete and return results
            timeout: Timeout in seconds when waiting for results

        Returns:
            If wait_for_result is True, returns the scan results.
            Otherwise, returns the task ID.
        """
        scan_params = parameters or {}
        scan_params["scan_type"] = scan_type

        # Submit task
        task_id = await self._submit_task(
            task_type="vulnerability_scan",
            target=target,
            parameters=scan_params,
            priority=priority,
        )

        # Return task ID or wait for results
        if wait_for_result:
            return await self.wait_for_task_completion(task_id, timeout)
        return task_id

    async def submit_recon_task(
        self,
        target: Dict[str, Any],
        recon_type: str = "comprehensive",
        parameters: Dict[str, Any] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        wait_for_result: bool = False,
        timeout: int = 900,
    ) -> Union[str, Dict[str, Any]]:
        """
        Submit a reconnaissance task to the distributed system.

        Args:
            target: Target information (e.g., {"domain": "example.com"} or {"ip_range": "192.168.1.0/24"})
            recon_type: Type of reconnaissance to perform
            parameters: Additional recon parameters
            priority: Task priority
            wait_for_result: Whether to wait for the task to complete and return results
            timeout: Timeout in seconds when waiting for results

        Returns:
            If wait_for_result is True, returns the recon results.
            Otherwise, returns the task ID.
        """
        recon_params = parameters or {}
        recon_params["recon_type"] = recon_type

        # Submit task
        task_id = await self._submit_task(
            task_type="recon",
            target=target,
            parameters=recon_params,
            priority=priority,
        )

        # Return task ID or wait for results
        if wait_for_result:
            return await self.wait_for_task_completion(task_id, timeout)
        return task_id

    async def check_task_status(self, task_id: str) -> Optional[str]:
        """
        Check the status of a task.

        Args:
            task_id: ID of the task to check

        Returns:
            Status string or None if task not found
        """
        url = f"{self.base_url}/api/tasks/{task_id}/status"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get("status")
            return None
        except Exception as e:
            logger.error(f"Error checking task status for {task_id}: {str(e)}")
            return None

    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the result of a completed task.

        Args:
            task_id: ID of the task to retrieve results for

        Returns:
            Task result or None if task not found or not completed
        """
        url = f"{self.base_url}/api/tasks/{task_id}/result"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting task result for {task_id}: {str(e)}")
            return None

    async def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task that is pending or in progress.

        Args:
            task_id: ID of the task to cancel

        Returns:
            True if task was cancelled, False otherwise
        """
        url = f"{self.base_url}/api/tasks/{task_id}/cancel"
        
        try:
            response = requests.post(url)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error cancelling task {task_id}: {str(e)}")
            return False

    async def get_active_workers(self) -> List[Dict[str, Any]]:
        """
        Get information about all active worker nodes.

        Returns:
            List of worker information dictionaries
        """
        url = f"{self.base_url}/api/workers"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error getting active workers: {str(e)}")
            return []

    async def get_pending_tasks(self) -> List[Dict[str, Any]]:
        """
        Get information about all pending tasks.

        Returns:
            List of pending task dictionaries
        """
        url = f"{self.base_url}/api/tasks/pending"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error getting pending tasks: {str(e)}")
            return []

    async def wait_for_task_completion(
        self, task_id: str, timeout: int = 300
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for a task to complete and return its result.

        Args:
            task_id: ID of the task to wait for
            timeout: Timeout in seconds

        Returns:
            Task result or None if timeout or error
        """
        start_time = time.time()
        poll_interval = 2  # seconds between status checks
        
        while time.time() - start_time < timeout:
            status = await self.check_task_status(task_id)
            
            if status in [TaskStatus.COMPLETED.name, TaskStatus.FAILED.name, TaskStatus.CANCELLED.name]:
                return await self.get_task_result(task_id)
                
            await asyncio.sleep(poll_interval)
            
            # Increase poll interval gradually to avoid hammering the server
            if poll_interval < 10:
                poll_interval += 0.5
                
        # Timeout reached
        logger.warning(f"Timeout waiting for task {task_id} to complete")
        return None

    async def _submit_task(
        self,
        task_type: str,
        target: Dict[str, Any],
        parameters: Dict[str, Any] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> str:
        """
        Submit a task to the distributed system.

        Args:
            task_type: Type of task to submit
            target: Target information
            parameters: Task parameters
            priority: Task priority

        Returns:
            Task ID

        Raises:
            RuntimeError: If task submission fails
        """
        url = f"{self.base_url}/api/tasks"
        
        task_data = {
            "task_type": task_type,
            "target": target,
            "parameters": parameters or {},
            "priority": priority.value,
        }
        
        try:
            response = requests.post(url, json=task_data)
            
            if response.status_code == 200 or response.status_code == 201:
                result = response.json()
                return result.get("task_id")
            else:
                error_msg = f"Failed to submit task: HTTP {response.status_code}"
                if response.text:
                    error_msg += f" - {response.text}"
                raise RuntimeError(error_msg)
                
        except Exception as e:
            raise RuntimeError(f"Error submitting task: {str(e)}")


# Create a singleton instance for simpler imports
_distributed_api = None


def get_distributed_api(
    master_host: str = "localhost", master_port: int = 5000
) -> DistributedAPI:
    """
    Get or create the global DistributedAPI instance.

    Args:
        master_host: Host address of the master node
        master_port: Port of the master node

    Returns:
        DistributedAPI instance
    """
    global _distributed_api
    
    if _distributed_api is None:
        _distributed_api = DistributedAPI(master_host, master_port)
        
    return _distributed_api


async def submit_task(
    task_type: str,
    target: Dict[str, Any],
    parameters: Dict[str, Any] = None,
    priority: TaskPriority = TaskPriority.MEDIUM,
    wait_for_result: bool = False,
    timeout: int = 600,
) -> Union[str, Dict[str, Any]]:
    """
    Convenience function to submit a task to the distributed system.

    Args:
        task_type: Type of task to submit
        target: Target information
        parameters: Task parameters
        priority: Task priority
        wait_for_result: Whether to wait for results
        timeout: Timeout when waiting for results

    Returns:
        Task ID or results if wait_for_result is True
    """
    api = get_distributed_api()
    
    task_id = await api._submit_task(
        task_type=task_type,
        target=target,
        parameters=parameters,
        priority=priority,
    )
    
    if wait_for_result:
        return await api.wait_for_task_completion(task_id, timeout)
    
    return task_id 