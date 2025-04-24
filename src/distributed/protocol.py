"""
Communication protocol implementation for the distributed scanning architecture.

This module provides the protocol layer for communication between nodes in the
distributed scanning system. It defines message formats, serialization,
and the transport mechanisms for reliable communication.
"""

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Union

if TYPE_CHECKING:
    from typing import Type

    from src.distributed.base import BaseNode

logger = logging.getLogger("sniper.distributed.protocol")


class MessageType(Enum):
    """Enum defining the types of messages that can be exchanged between nodes."""

    # Registration and discovery
    REGISTER = auto()
    REGISTER_RESPONSE = auto()
    UNREGISTER = auto()
    UNREGISTER_RESPONSE = auto()

    # Heartbeat and status
    HEARTBEAT = auto()
    HEARTBEAT_RESPONSE = auto()
    NODE_STATUS = auto()

    # Task management
    TASK_REQUEST = auto()
    TASK_ASSIGNMENT = auto()
    TASK_STATUS = auto()
    TASK_RESULT = auto()
    TASK_RESULT_RESPONSE = auto()

    # Control messages
    CANCEL_TASK = auto()
    SHUTDOWN = auto()
    PAUSE = auto()
    RESUME = auto()
    ERROR = auto()
    NODE_STATUS_CONFIRM = auto()


class ProtocolMessage:
    """
    Base class for all protocol messages.

    Handles message serialization, deserialization, and basic validation.
    """

    def __init__(
        self,
        message_type: MessageType,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a protocol message.

        Args:
            message_type: Type of the message
            sender_id: ID of the sending node
            receiver_id: ID of the receiving node
            payload: Message-specific data payload
            message_id: Unique message identifier (auto-generated if None)
            timestamp: Message timestamp (current time if None)
        """
        self.message_type = message_type
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.payload = payload or {}
        self.message_id = message_id or f"{int(time.time())}_{sender_id}_{receiver_id}"
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the message to a dictionary for serialization.

        Returns:
            Dictionary representation of the message
        """
        return {
            "message_type": self.message_type.name,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "payload": self.payload,
            "message_id": self.message_id,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """
        Convert the message to a JSON string.

        Returns:
            JSON string representation of the message
        """
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, message_dict: Dict[str, Any]) -> "ProtocolMessage":
        """
        Create a message from a dictionary.

        Args:
            message_dict: Dictionary representation of the message

        Returns:
            ProtocolMessage instance
        """
        message_type_str = message_dict.get("message_type")
        try:
            if message_type_str is not None:
                message_type = MessageType[message_type_str]
            else:
                raise ValueError("Message type is missing")
        except (KeyError, TypeError):
            raise ValueError(f"Invalid message type: {message_type_str}")

        return cls(
            message_type=message_type,
            sender_id=message_dict.get("sender_id", ""),
            receiver_id=message_dict.get("receiver_id", ""),
            payload=message_dict.get("payload", {}),
            message_id=message_dict.get("message_id"),
            timestamp=message_dict.get("timestamp"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "ProtocolMessage":
        """
        Create a message from a JSON string.

        Args:
            json_str: JSON string representation of the message

        Returns:
            ProtocolMessage instance
        """
        try:
            message_dict = json.loads(json_str)
            return cls.from_dict(message_dict)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")


class RegisterMessage(ProtocolMessage):
    """
    Message sent by a node to register with a master node.

    Contains information about the node's capabilities and system information.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a registration message.

        Args:
            sender_id: ID of the registering node
            receiver_id: ID of the master node
            payload: Registration information including capabilities and system info
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.REGISTER,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class HeartbeatMessage(ProtocolMessage):
    """
    Periodic message sent by a node to indicate it's still alive.

    Contains current status and load information.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a heartbeat message.

        Args:
            sender_id: ID of the sending node
            receiver_id: ID of the master node
            payload: Status and load information
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.HEARTBEAT,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class TaskStatusMessage(ProtocolMessage):
    """
    Message sent by a worker to update the status of a task.

    Contains current status, progress information, and any intermediate results.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a task status message.

        Args:
            sender_id: ID of the node sending the status update
            receiver_id: ID of the receiving node
            payload: Status information including task_id, status, progress, etc.
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.TASK_STATUS,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class TaskResultMessage(ProtocolMessage):
    """
    Message sent by a worker to deliver task results.

    Contains task results, metadata, and performance metrics.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a task result message.

        Args:
            sender_id: ID of the worker node that completed the task
            receiver_id: ID of the receiving node (typically master)
            payload: Result data including task_id, findings, metrics, etc.
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.TASK_RESULT,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class NodeStatusMessage(ProtocolMessage):
    """
    Message sent by a node to report its current status.

    Contains detailed status information about the node, including resource utilization,
    active tasks, and other metrics.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a node status message.

        Args:
            sender_id: ID of the node sending the status
            receiver_id: ID of the receiving node
            payload: Status information including load, active_tasks, resource_usage, etc.
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.NODE_STATUS,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class TaskAssignmentMessage(ProtocolMessage):
    """
    Message sent by the master to assign a task to a worker.

    Contains task information and execution parameters.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a task assignment message.

        Args:
            sender_id: ID of the master node
            receiver_id: ID of the worker node receiving the task
            payload: Task information including task_id, task_type, parameters, etc.
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class TaskCancelMessage(ProtocolMessage):
    """
    Message sent to cancel a task that is in progress or pending.

    Contains task identifier and cancellation reason.
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        """
        Initialize a task cancel message.

        Args:
            sender_id: ID of the node requesting cancellation
            receiver_id: ID of the node handling the task
            payload: Cancellation information including task_id, reason, etc.
            message_id: Unique message identifier
            timestamp: Message timestamp
        """
        super().__init__(
            message_type=MessageType.CANCEL_TASK,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload or {},
            message_id=message_id,
            timestamp=timestamp,
        )


class ProtocolBase:
    """
    Base class for all protocol implementations.

    Subclasses must implement the concrete protocol (e.g., REST, gRPC, WebSockets).
    """

    def __init__(self, node):
        """
        Initialize the protocol base with node reference.

        Args:
            node: Node that will use this protocol
        """
        self.node = node

    def connect(self) -> bool:
        """
        Connect to the remote endpoint.

        Returns:
            True if connected successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement connect()")

    def disconnect(self) -> bool:
        """
        Disconnect from the remote endpoint.

        Returns:
            True if disconnected successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement disconnect()")

    def send_message(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """
        Send a message to the remote endpoint.

        Args:
            message: Message to send

        Returns:
            Response message if received, None otherwise
        """
        raise NotImplementedError("Subclasses must implement send_message()")

    def receive_message(self) -> Optional[ProtocolMessage]:
        """
        Receive a message from the remote endpoint.

        Returns:
            Received message if available, None otherwise
        """
        raise NotImplementedError("Subclasses must implement receive_message()")


class RestProtocol(ProtocolBase):
    """REST protocol implementation for distributed communication."""

    def __init__(self, node: "BaseNode"):
        """
        Initialize REST protocol with a node reference.

        Args:
            node: Node instance that will use this protocol
        """
        super().__init__(node)
        # For worker nodes connecting to a master node, include the master node's host/port
        if hasattr(self.node, "master_host") and hasattr(self.node, "master_port"):
            self.base_url = f"http://{self.node.master_host}:{self.node.master_port}"
        else:
            # For master nodes, there is no base_url for outgoing requests
            self.base_url = None
        self.server = None
        self.server_thread = None

    def connect(self) -> bool:
        """Connect to the remote endpoint."""
        logger.debug(f"REST protocol connected to {self.base_url}")
        return True

    def disconnect(self) -> bool:
        """Disconnect from the remote endpoint."""
        logger.debug("REST protocol disconnected")
        return True

    def send_message(self, message: ProtocolMessage) -> Optional[Dict]:
        """
        Send a message via REST API.

        Args:
            message: Message to send

        Returns:
            Response message or None if no response
        """
        from src.distributed.rest import create_rest_client

        try:
            client = create_rest_client()
            endpoint = self._get_endpoint_for_message(message)
            response = client.post(
                f"{self.base_url}/{endpoint}", json=message.to_dict(), timeout=30
            )

            if response.status_code >= 200 and response.status_code < 300:
                return response.json()
            else:
                logger.error(
                    f"REST API error: {response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error sending REST message: {str(e)}")
            return None

    def _get_endpoint_for_message(self, message: ProtocolMessage) -> str:
        """Get the appropriate REST endpoint for a message type."""
        endpoints = {
            MessageType.REGISTER: "register",
            MessageType.HEARTBEAT: "heartbeat",
            MessageType.TASK_STATUS: "task-status",
            MessageType.TASK_RESULT: "task-result",
            MessageType.NODE_STATUS: "status",
        }
        return endpoints.get(message.message_type, "")

    def receive_message(self) -> Optional[ProtocolMessage]:
        """
        Receive a message. In REST, this is unused as it's handled by the server.

        Returns:
            None as REST is request/response based
        """
        return None

    def start_server(self, host: str, port: int, message_handler: Callable) -> bool:
        """
        Start the REST server for receiving messages.

        Args:
            host: Host address to bind to
            port: Port to listen on
            message_handler: Callback for handling incoming messages

        Returns:
            True if server started successfully
        """
        from src.distributed.rest import create_master_app, run_app

        try:
            # Create FastAPI app for master node
            app = create_master_app(self.node)

            # Run in a separate thread without creating a new server
            thread, server = run_app(app, host, port)
            self.server_thread = thread
            self.server = server

            logger.info(f"REST server started on {host}:{port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start REST server: {str(e)}", exc_info=True)
            return False

    def stop_server(self) -> bool:
        """
        Stop the REST server.

        Returns:
            True if server stopped successfully
        """
        try:
            if self.server_thread and self.server_thread.is_alive():
                # We can't easily stop the thread directly
                # The thread is daemon=True so it will be terminated when the process exits
                logger.info("REST server thread is daemon and will exit with process")
                return True
            return True
        except Exception as e:
            logger.error(f"Failed to stop REST server: {str(e)}", exc_info=True)
            return False


def create_protocol(protocol_type: str, node) -> ProtocolBase:
    """
    Create a protocol instance of the specified type.

    Args:
        protocol_type: Type of protocol to create (e.g., "REST", "GRPC", "WS")
        node: Node that will use this protocol

    Returns:
        Protocol instance

    Raises:
        ValueError: If the protocol type is not supported
    """
    protocol_type = protocol_type.upper()

    if protocol_type == "REST":
        return RestProtocol(node)
    elif protocol_type == "GRPC":
        # If we had a gRPC implementation
        raise ValueError(f"Protocol type not implemented: {protocol_type}")
    elif protocol_type == "WS":
        # If we had a WebSocket implementation
        raise ValueError(f"Protocol type not implemented: {protocol_type}")
    else:
        raise ValueError(f"Unknown protocol type: {protocol_type}")
