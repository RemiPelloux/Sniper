#!/usr/bin/env python3
"""
Task Submitter for Sniper's Distributed Scanning Architecture.

This module provides a simple interface for submitting tasks to the master node
without having to manage workers directly. The master node will automatically
distribute tasks to available workers based on their capabilities and load.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.config import settings
from src.core.validation import validate_target_url
from src.distributed.base import TaskPriority
from src.distributed.client import SniperClient
from src.ml.autonomous_tester import VulnerabilityType

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.environ.get("SNIPER_LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("sniper.task_submitter")

# FastAPI app
app = FastAPI(
    title="Sniper Task Submitter",
    description="Submit tasks to Sniper's distributed scanning system",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global client for interaction with master node
sniper_client = None


# Data models for API
class TaskSubmission(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    task_type: str = Field(
        ..., description="Type of task (e.g., vulnerability_scan, recon)"
    )
    priority: str = Field("medium", description="Task priority (low, medium, high)")
    options: Dict[str, Any] = Field(
        default_factory=dict, description="Additional task options"
    )


class TaskResponse(BaseModel):
    task_id: str = Field(..., description="ID of the submitted task")
    status: str = Field(..., description="Status of task submission")
    message: str = Field(..., description="Informational message")


class VulnScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    vulnerability_type: Optional[str] = Field(
        None, description="Specific vulnerability type to test"
    )
    priority: str = Field("high", description="Task priority (low, medium, high)")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Scan parameters"
    )


class ReconRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")
    depth: int = Field(3, description="Reconnaissance depth (1-5)")
    techniques: List[str] = Field(
        default_factory=list, description="Specific recon techniques to use"
    )
    priority: str = Field("medium", description="Task priority (low, medium, high)")


# Background task functions
async def submit_task_async(
    target_url: str, task_type: str, priority_str: str, options: Dict[str, Any]
) -> Dict[str, Any]:
    """Submit task to the master node asynchronously."""
    global sniper_client

    # Convert priority string to enum
    try:
        priority = TaskPriority[priority_str.upper()]
    except KeyError:
        priority = TaskPriority.MEDIUM
        logger.warning(f"Invalid priority '{priority_str}', using MEDIUM")

    # Handle different task types
    if task_type == "vulnerability_scan":
        vuln_type = options.get("vulnerability_type")
        if vuln_type:
            logger.info(
                f"Submitting vulnerability scan for {target_url} with type {vuln_type}"
            )
            task_id = await sniper_client.submit_autonomous_test(
                target_url=target_url,
                vulnerability_type=vuln_type,
                request_params=options.get("params", {}),
                headers=options.get("headers", {}),
                cookies=options.get("cookies", {}),
                payload_count=options.get("payload_count", 5),
                priority=priority,
            )
        else:
            logger.info(f"Submitting comprehensive scan for {target_url}")
            task_id = await sniper_client.submit_comprehensive_scan(
                target_url=target_url,
                request_params=options.get("params", {}),
                headers=options.get("headers", {}),
                cookies=options.get("cookies", {}),
                priority=priority,
            )

        if task_id:
            return {
                "task_id": task_id,
                "status": "submitted",
                "message": f"Task submitted successfully with ID: {task_id}",
            }
        else:
            return {
                "status": "error",
                "message": "Failed to submit task to master node",
            }
    else:
        # For other task types, use a generic mechanism
        # This would need to be implemented based on your system's capabilities
        logger.warning(
            f"Task type '{task_type}' not directly supported, using generic submission"
        )
        return {
            "status": "error",
            "message": f"Task type '{task_type}' not implemented yet",
        }


# FastAPI routes
@app.get("/")
async def root():
    """Root endpoint - provides basic information."""
    return {"message": "Sniper Task Submitter API", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    global sniper_client

    # Check master node status
    try:
        if sniper_client:
            master_status = await sniper_client.get_master_status()
            if master_status:
                return {"status": "healthy", "master": master_status}

        return {"status": "unhealthy", "message": "Not connected to master node"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "error", "message": f"Health check failed: {str(e)}"}


@app.post("/tasks", response_model=TaskResponse)
async def submit_task(task: TaskSubmission, background_tasks: BackgroundTasks):
    """Submit a task to the distributed system."""
    global sniper_client

    # Validate target URL
    try:
        validated_url = validate_target_url(task.target_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {str(e)}")

    # Queue the task submission
    background_tasks.add_task(
        submit_task_async, validated_url, task.task_type, task.priority, task.options
    )

    return {
        "task_id": f"pending-{int(time.time())}",  # Temporary ID until actual submission
        "status": "queued",
        "message": "Task queued for submission",
    }


@app.post("/scan/vulnerability", response_model=TaskResponse)
async def submit_vulnerability_scan(scan: VulnScanRequest):
    """Submit a vulnerability scan task."""
    global sniper_client

    # Validate target URL
    try:
        validated_url = validate_target_url(scan.target_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {str(e)}")

    # Convert priority string to enum
    try:
        priority = TaskPriority[scan.priority.upper()]
    except KeyError:
        priority = TaskPriority.HIGH

    # Submit task directly
    try:
        if scan.vulnerability_type:
            # Try to convert vulnerability type string to enum
            try:
                vuln_type = VulnerabilityType(scan.vulnerability_type)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid vulnerability type: {scan.vulnerability_type}",
                )

            task_id = await sniper_client.submit_autonomous_test(
                target_url=validated_url,
                vulnerability_type=vuln_type,
                request_params=scan.parameters.get("params", {}),
                headers=scan.parameters.get("headers", {}),
                cookies=scan.parameters.get("cookies", {}),
                priority=priority,
            )
        else:
            task_id = await sniper_client.submit_comprehensive_scan(
                target_url=validated_url,
                request_params=scan.parameters.get("params", {}),
                headers=scan.parameters.get("headers", {}),
                cookies=scan.parameters.get("cookies", {}),
                priority=priority,
            )

        if task_id:
            return {
                "task_id": task_id,
                "status": "submitted",
                "message": f"Vulnerability scan submitted with ID: {task_id}",
            }
        else:
            raise HTTPException(
                status_code=500, detail="Failed to submit task to master node"
            )

    except Exception as e:
        logger.error(f"Error submitting vulnerability scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error submitting scan: {str(e)}")


@app.post("/scan/recon", response_model=TaskResponse)
async def submit_recon_scan(recon: ReconRequest):
    """Submit a reconnaissance task."""
    global sniper_client

    # This is a placeholder - implement based on your actual recon capabilities
    return {
        "task_id": f"recon-{int(time.time())}",
        "status": "not_implemented",
        "message": "Reconnaissance tasks not implemented yet",
    }


@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get the status of a task."""
    global sniper_client

    try:
        # Get task status from master
        status = await sniper_client.get_task_status(task_id)
        if status:
            # Get more detailed result if available
            result = await sniper_client.get_task_result(task_id)

            return {"task_id": task_id, "status": status.name, "result": result}
        else:
            return JSONResponse(
                status_code=404, content={"detail": f"Task {task_id} not found"}
            )
    except Exception as e:
        logger.error(f"Error getting task status: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Error retrieving task status: {str(e)}"},
        )


async def connect_to_master(
    host: str, port: int, retries: int = 5, retry_delay: int = 5
):
    """Connect to the master node with retries."""
    global sniper_client

    logger.info(f"Connecting to master node at {host}:{port}")

    for attempt in range(retries):
        try:
            sniper_client = SniperClient(host, port)
            if await sniper_client.connect():
                logger.info("Successfully connected to master node")
                return True

            logger.warning(
                f"Failed to connect to master node (attempt {attempt+1}/{retries})"
            )
        except Exception as e:
            logger.error(f"Error connecting to master: {str(e)}")

        if attempt < retries - 1:
            logger.info(f"Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)

    logger.error("Failed to connect to master node after multiple attempts")
    return False


async def startup_event():
    """Connect to master node during startup."""
    master_host = os.environ.get("MASTER_HOST", "localhost")
    master_port = int(os.environ.get("MASTER_PORT", "5000"))

    # Initial connection attempt
    await connect_to_master(master_host, master_port)

    # Start background reconnection task
    asyncio.create_task(reconnection_monitor(master_host, master_port))


async def reconnection_monitor(host: str, port: int):
    """Monitor and maintain connection to master node."""
    global sniper_client

    while True:
        await asyncio.sleep(30)  # Check every 30 seconds

        # If client is None or not connected, try to reconnect
        if not sniper_client or not await sniper_client.get_master_status():
            logger.warning("Connection to master lost, attempting to reconnect")
            await connect_to_master(host, port)


async def shutdown_event():
    """Disconnect from master node during shutdown."""
    global sniper_client

    if sniper_client:
        logger.info("Disconnecting from master node")
        await sniper_client.disconnect()


# Register startup and shutdown events
app.add_event_handler("startup", startup_event)
app.add_event_handler("shutdown", shutdown_event)


# CLI interface
def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Sniper Task Submitter")
    parser.add_argument(
        "--master", default="localhost:5000", help="Master node address (host:port)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to run the API server on"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind the API server to"
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level")

    args = parser.parse_args()

    # Set log level
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Extract master host and port
    try:
        master_host, master_port = args.master.split(":")
        master_port = int(master_port)
    except ValueError:
        logger.error(
            f"Invalid master address format: {args.master}. Use host:port format."
        )
        sys.exit(1)

    # Set environment variables for the FastAPI app
    os.environ["MASTER_HOST"] = master_host
    os.environ["MASTER_PORT"] = str(master_port)

    # Start the API server
    logger.info(f"Starting task submitter API server on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
