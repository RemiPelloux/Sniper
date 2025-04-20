"""
Communication protocol implementation for the distributed scanning architecture.

This module provides the protocol layer for communication between nodes in the
distributed scanning system. It defines message formats, serialization,
and the transport mechanisms for reliable communication.
"""

import json
import logging
import time
from datetime import datetime, timezone
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

if TYPE_CHECKING:
    from typing import Type

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

    Defines the interface that all concrete protocol implementations must follow.
    """

    def __init__(self, host: str = "localhost", port: int = 5555):
        """
        Initialize the protocol.

        Args:
            host: Host address for the protocol
            port: Port number for the protocol
        """
        self.host = host
        self.port = port

    def connect(self) -> bool:
        """
        Establish a connection to the remote endpoint.

        Returns:
            True if connected successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement connect()")

    def disconnect(self) -> bool:
        """
        Close the connection to the remote endpoint.

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
            Response message if applicable, None otherwise
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
    """
    REST-based protocol implementation.

    Uses HTTP for communication between nodes, with JSON payloads.
    """

    def __init__(self, host: str = "localhost", port: int = 5555):
        """
        Initialize the REST protocol.

        Args:
            host: Host address for REST endpoints
            port: Port number for REST endpoints
        """
        super().__init__(host, port)
        self.base_url = f"http://{host}:{port}"
        # Note: This would normally use requests library
        # but for now we'll keep it simple

    def connect(self) -> bool:
        """
        Verify connectivity to the REST endpoint.

        For REST, there's no persistent connection, so this just
        checks if the server is reachable.

        Returns:
            True if the endpoint is reachable, False otherwise
        """
        # This would normally try a HEAD request to the base URL
        # and return True if successful
        return True

    def disconnect(self) -> bool:
        """
        Close the connection to the REST endpoint.

        For REST, there's no persistent connection to close.

        Returns:
            Always returns True
        """
        return True

    def send_message(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """
        Send a message to the REST endpoint.

        Args:
            message: Message to send

        Returns:
            Response message if received, None otherwise
        """
        # This would normally use requests.post to send the message
        # and return a ProtocolMessage built from the response
        logger.debug(f"REST send: {message.message_type.name} to {self.base_url}")
        return None

    def receive_message(self) -> Optional[ProtocolMessage]:
        """
        Receive a message from the REST endpoint.

        For REST, this doesn't make sense as REST is request/response,
        not push-based. Included for interface completeness.

        Returns:
            Always returns None
        """
        logger.warning("REST protocol doesn't support receive_message()")
        return None


def create_protocol(
    protocol_type: str, host: str = "localhost", port: int = 5555
) -> ProtocolBase:
    """
    Factory function to create an appropriate protocol instance.

    Args:
        protocol_type: Type of protocol to create ("rest", "websocket", etc.)
        host: Host address for the protocol
        port: Port number for the protocol

    Returns:
        Protocol instance

    Raises:
        ValueError: If protocol_type is not supported
    """
    if protocol_type.lower() == "rest":
        return RestProtocol(host, port)
    else:
        raise ValueError(f"Unsupported protocol type: {protocol_type}")
