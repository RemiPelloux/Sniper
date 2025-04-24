"""
REST API implementation for distributed scanning architecture.

This module provides FastAPI-based REST endpoints for:
- Master node API to receive worker registrations, heartbeats, and task results
- Worker node API to interact with master nodes
"""

import logging
from threading import Thread
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.distributed.base import NodeInfo, NodeRole, NodeStatus
from src.distributed.protocol import MessageType, ProtocolMessage

if TYPE_CHECKING:
    from src.distributed.base import BaseNode, DistributedTask, MasterNode, WorkerNode

logger = logging.getLogger(__name__)


# ======== Pydantic Models for Request/Response ========
class RegisterRequest(BaseModel):
    """Worker registration request."""

    node_id: Optional[str] = None
    hostname: str
    address: str
    port: int
    capabilities: List[str]
    role: str = "worker"


class HeartbeatRequest(BaseModel):
    """Worker heartbeat request."""

    node_id: str
    status: str
    active_tasks: int = 0
    resource_usage: Dict[str, float] = Field(default_factory=dict)


class TaskStatusUpdate(BaseModel):
    """Task status update."""

    task_id: str
    worker_id: str
    status: str
    progress: float = 0.0
    message: Optional[str] = None


class TaskResult(BaseModel):
    """Task result data."""

    task_id: str
    worker_id: str
    status: str
    result_data: Dict[str, Any] = Field(default_factory=dict)
    execution_time: float = 0.0
    error_message: Optional[str] = None


class NodeStatusUpdate(BaseModel):
    """Node status update."""

    node_id: str
    status: str
    uptime: int
    active_tasks: int = 0
    resource_usage: Dict[str, float] = Field(default_factory=dict)


class GenericResponse(BaseModel):
    """Generic API response."""

    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


class TaskRequest(BaseModel):
    """Request for a new task."""

    worker_id: str
    capabilities: List[str]


# ======== App Factories ========
def create_master_app(master_node) -> FastAPI:
    """
    Create a FastAPI application for the master node.

    Args:
        master_node: The master node instance to handle the API requests

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Sniper Master Node API",
        description="REST API for Sniper Security Scanner Master Node",
        version="1.0",
    )

    @app.get("/")
    def read_root():
        """Get basic information about the master node."""
        return {
            "node_id": master_node.id,
            "status": master_node.status.name,
            "uptime": master_node.uptime(),
            "worker_count": len(master_node.workers),
            "task_count": len(master_node.tasks),
        }

    @app.post("/register", response_model=GenericResponse)
    def register_worker(registration: RegisterRequest):
        """Register a worker node with the master."""
        try:
            node_info = NodeInfo(
                node_id=registration.node_id,
                hostname=registration.hostname,
                address=registration.address,
                port=registration.port,
                role=NodeRole.WORKER,
                capabilities=registration.capabilities,
            )

            # Convert to protocol message and process
            message = ProtocolMessage(
                message_type=MessageType.REGISTER,
                sender_id=registration.node_id or "unknown",
                receiver_id=master_node.id,
                payload=node_info.to_dict(),
            )

            result = master_node._handle_register(message)

            return GenericResponse(
                success=True,
                message=f"Worker registered successfully with ID {result['node_id']}",
                data=result,
            )
        except Exception as e:
            logger.error(f"Error registering worker: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/heartbeat", response_model=GenericResponse)
    def worker_heartbeat(heartbeat: HeartbeatRequest):
        """Process a worker heartbeat."""
        try:
            # Convert to protocol message and process
            message = ProtocolMessage(
                message_type=MessageType.HEARTBEAT,
                sender_id=heartbeat.node_id,
                receiver_id=master_node.id,
                payload={
                    "status": heartbeat.status,
                    "active_tasks": heartbeat.active_tasks,
                    "resource_usage": heartbeat.resource_usage,
                },
            )

            result = master_node._handle_heartbeat(message)

            return GenericResponse(
                success=True, message="Heartbeat received", data=result
            )
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/task-status", response_model=GenericResponse)
    def update_task_status(status_update: TaskStatusUpdate):
        """Update the status of a task."""
        try:
            # Convert to protocol message and process
            message = ProtocolMessage(
                message_type=MessageType.TASK_STATUS,
                sender_id=status_update.worker_id,
                receiver_id=master_node.id,
                payload={
                    "task_id": status_update.task_id,
                    "status": status_update.status,
                    "progress": status_update.progress,
                    "message": status_update.message,
                },
            )

            result = master_node._handle_task_status(message)

            return GenericResponse(
                success=True,
                message=f"Task status updated: {status_update.status}",
                data=result,
            )
        except Exception as e:
            logger.error(f"Error updating task status: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/task-result", response_model=GenericResponse)
    def submit_task_result(result: TaskResult, background_tasks: BackgroundTasks):
        """Submit the result of a completed task."""
        try:
            # Convert to protocol message and process
            message = ProtocolMessage(
                message_type=MessageType.TASK_RESULT,
                sender_id=result.worker_id,
                receiver_id=master_node.id,
                payload={
                    "task_id": result.task_id,
                    "status": result.status,
                    "result_data": result.result_data,
                    "execution_time": result.execution_time,
                    "error_message": result.error_message,
                },
            )

            # Process in background to avoid blocking the response
            background_tasks.add_task(master_node._handle_task_result, message)

            return GenericResponse(
                success=True,
                message=f"Task result received for task {result.task_id}",
                data={"task_id": result.task_id},
            )
        except Exception as e:
            logger.error(f"Error submitting task result: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/status", response_model=GenericResponse)
    def update_node_status(status_update: NodeStatusUpdate):
        """Update the status of a node."""
        try:
            # Convert to protocol message and process
            message = ProtocolMessage(
                message_type=MessageType.NODE_STATUS,
                sender_id=status_update.node_id,
                receiver_id=master_node.id,
                payload={
                    "status": status_update.status,
                    "uptime": status_update.uptime,
                    "active_tasks": status_update.active_tasks,
                    "resource_usage": status_update.resource_usage,
                },
            )

            result = master_node._handle_node_status(message)

            return GenericResponse(
                success=True, message="Node status updated", data=result
            )
        except Exception as e:
            logger.error(f"Error updating node status: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get(
        "/get-task/{worker_id}", response_model=Union[GenericResponse, Dict[str, Any]]
    )
    def get_task(worker_id: str):
        """Get a task for a worker to execute."""
        try:
            # Find suitable task for worker
            task = master_node.get_task_for_worker(worker_id)

            if task:
                return {
                    "task_id": task.id,
                    "task_type": task.task_type,
                    "parameters": task.parameters,
                    "priority": task.priority,
                }
            else:
                return GenericResponse(
                    success=True, message="No tasks available for worker", data=None
                )
        except Exception as e:
            logger.error(f"Error getting task for worker: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    return app


def create_worker_app(worker_node) -> FastAPI:
    """
    Create a FastAPI application for the worker node.

    Args:
        worker_node: The worker node instance to handle the API requests

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Sniper Worker Node API",
        description="REST API for Sniper Security Scanner Worker Node",
        version="1.0",
    )

    @app.get("/")
    def read_root():
        """Get basic information about the worker node."""
        return {
            "node_id": worker_node.id,
            "status": worker_node.status.name,
            "uptime": worker_node.uptime(),
            "active_tasks": worker_node.active_tasks,
            "capabilities": worker_node.capabilities,
        }

    @app.post("/task", response_model=GenericResponse)
    def receive_task(task_data: Dict[str, Any]):
        """Receive a task from the master node."""
        try:
            # Process the task in a separate thread to avoid blocking
            Thread(
                target=worker_node.handle_task, args=(task_data,), daemon=True
            ).start()

            return GenericResponse(
                success=True,
                message=f"Task {task_data.get('task_id')} accepted",
                data={"task_id": task_data.get("task_id")},
            )
        except Exception as e:
            logger.error(f"Error receiving task: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/cancel-task/{task_id}", response_model=GenericResponse)
    def cancel_task(task_id: str):
        """Cancel a task that is currently being executed."""
        try:
            result = worker_node.cancel_task(task_id)

            return GenericResponse(
                success=result,
                message=f"Task {task_id} {'cancelled' if result else 'not found or could not be cancelled'}",
                data={"task_id": task_id},
            )
        except Exception as e:
            logger.error(f"Error cancelling task: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/status", response_model=Dict[str, Any])
    def get_status():
        """Get the current status of the worker node."""
        return {
            "node_id": worker_node.id,
            "status": worker_node.status.name,
            "uptime": worker_node.uptime(),
            "active_tasks": worker_node.active_tasks,
            "task_count": worker_node.task_count,
            "success_count": worker_node.success_count,
            "failure_count": worker_node.failure_count,
            "capabilities": worker_node.capabilities,
            "resource_usage": worker_node.get_resource_usage(),
        }

    return app


def run_master_app_server(app, host, port):
    """
    Run the master node API server.

    Args:
        app: The FastAPI application
        host: Host address to bind to
        port: Port to listen on
    """
    uvicorn.run(app, host=host, port=port)


def run_worker_app_server(app, host, port):
    """
    Run the worker node API server.

    Args:
        app: The FastAPI application
        host: Host address to bind to
        port: Port to listen on
    """
    uvicorn.run(app, host=host, port=port)


def run_app(app, host="0.0.0.0", port=8000):
    """
    Run a FastAPI app in a thread-safe manner with proper configuration.

    Args:
        app: The FastAPI application to run
        host: Host address to bind to (default: "0.0.0.0")
        port: Port to listen on (default: 8000)

    Returns:
        Thread: The thread running the server
    """
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)

    # Override server install_signal_handlers to prevent conflicts
    # with the main application signal handling
    server.install_signal_handlers = lambda: None

    # Create and start server thread
    thread = Thread(target=server.run, daemon=True)
    thread.start()

    return thread, server


def shutdown_app(app):
    """
    Gracefully shutdown a FastAPI application.

    Args:
        app: The FastAPI application to shut down
    """
    # FastAPI/Uvicorn doesn't have a direct method to shutdown
    # We'll handle this at the thread level in the master/worker classes
    logger.info("Application shutdown requested")


def create_rest_client():
    """
    Create an HTTP client for REST API calls.

    Returns:
        A client instance for making HTTP requests.
    """
    import requests

    return requests
