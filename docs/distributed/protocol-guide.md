# Distributed Scanning Protocol Guide

## Overview

The Sniper distributed scanning architecture uses a well-defined protocol for communication between master and worker nodes. This document details the protocol design, message formats, and best practices for implementing custom protocol handlers.

## Protocol Design Principles

The distributed protocol is designed with these core principles:

1. **Reliability**: Ensures message delivery even in unreliable network conditions
2. **Efficiency**: Minimizes bandwidth usage and processing overhead
3. **Security**: Protects communication from unauthorized access and tampering
4. **Extensibility**: Allows for future additions without breaking compatibility
5. **Simplicity**: Makes implementation and debugging straightforward

## Message Structure

All protocol messages follow a standard envelope format:

```json
{
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "message_type": "TASK_ASSIGNMENT",
  "timestamp": "2023-11-15T14:30:45.123Z",
  "sender": "master-node-1",
  "recipient": "worker-node-5",
  "payload": {
    // Message-specific content
  }
}
```

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| message_id | UUID | Unique identifier for the message |
| message_type | Enum | Type of message (see Message Types below) |
| timestamp | ISO8601 | Message creation time |
| sender | String | ID of the sending node |
| recipient | String | ID of the intended recipient (or "broadcast") |
| payload | Object | Message-specific content |

### Message Types

The protocol defines these standard message types:

#### REGISTER

Sent by worker nodes to register with a master node.

```json
{
  "message_type": "REGISTER",
  "payload": {
    "capabilities": ["nmap", "sqlmap", "dirbuster"],
    "max_concurrent_tasks": 5,
    "resource_limits": {
      "cpu_percent": 80,
      "memory_mb": 4096,
      "network_mbps": 100
    },
    "version": "1.5.0"
  }
}
```

#### REGISTER_RESPONSE

Sent by master nodes in response to registration requests.

```json
{
  "message_type": "REGISTER_RESPONSE",
  "payload": {
    "status": "accepted",
    "worker_id": "worker-node-5",
    "heartbeat_interval": 30,
    "config_updates": {
      "max_concurrent_tasks": 3
    }
  }
}
```

#### UNREGISTER

Sent by worker nodes to gracefully disconnect from a master node.

```json
{
  "message_type": "UNREGISTER",
  "payload": {
    "reason": "shutdown",
    "pending_tasks": ["task-123", "task-456"]
  }
}
```

#### HEARTBEAT

Sent by worker nodes to indicate they are still active.

```json
{
  "message_type": "HEARTBEAT",
  "payload": {
    "status": "active",
    "current_tasks": 2,
    "system_metrics": {
      "cpu_usage": 45.2,
      "memory_usage": 2048,
      "disk_usage": 15360
    },
    "task_metrics": {
      "completed": 15,
      "failed": 2,
      "average_completion_time": 75.3
    }
  }
}
```

#### TASK_REQUEST

Sent by worker nodes to request tasks when they have available capacity.

```json
{
  "message_type": "TASK_REQUEST",
  "payload": {
    "available_slots": 3,
    "preferred_types": ["port_scan", "web_scan"]
  }
}
```

#### TASK_ASSIGNMENT

Sent by master nodes to assign tasks to workers.

```json
{
  "message_type": "TASK_ASSIGNMENT",
  "payload": {
    "task_id": "task-789",
    "task_type": "port_scan",
    "target": {
      "host": "example.com",
      "ports": "1-1000"
    },
    "parameters": {
      "scan_speed": "normal",
      "timeout": 300
    },
    "priority": 2,
    "deadline": "2023-11-15T15:30:45.123Z"
  }
}
```

#### TASK_RESULT

Sent by worker nodes to report task results.

```json
{
  "message_type": "TASK_RESULT",
  "payload": {
    "task_id": "task-789",
    "status": "completed",
    "execution_time": 127.5,
    "findings": [
      {
        "type": "open_port",
        "severity": "low",
        "host": "example.com",
        "port": 22,
        "service": "ssh",
        "version": "OpenSSH 8.2"
      },
      {
        "type": "open_port",
        "severity": "medium",
        "host": "example.com",
        "port": 80,
        "service": "http",
        "version": "nginx 1.18.0"
      }
    ],
    "raw_output": "base64_encoded_tool_output"
  }
}
```

#### TASK_CANCEL

Sent by master nodes to cancel in-progress tasks.

```json
{
  "message_type": "TASK_CANCEL",
  "payload": {
    "task_id": "task-789",
    "reason": "scan_aborted",
    "force": true
  }
}
```

#### STATUS_UPDATE

Sent by worker nodes to provide updates on task progress.

```json
{
  "message_type": "STATUS_UPDATE",
  "payload": {
    "task_id": "task-789",
    "status": "in_progress",
    "progress": 65,
    "eta_seconds": 45,
    "interim_findings_count": 7
  }
}
```

#### ERROR

Sent by any node to report errors.

```json
{
  "message_type": "ERROR",
  "payload": {
    "error_code": "task_execution_failed",
    "task_id": "task-789",
    "message": "Tool execution timed out",
    "details": {
      "exit_code": 124,
      "stderr": "Operation timed out"
    }
  }
}
```

## Protocol Implementations

The Sniper framework includes multiple protocol implementations:

### REST Protocol

HTTP/HTTPS-based protocol with JSON payloads:

- Uses standard HTTP methods (GET, POST, PUT, DELETE)
- Supports webhook callbacks for asynchronous communication
- Best for environments with proxies or firewall restrictions

### WebSocket Protocol

Persistent connection protocol for real-time communication:

- Maintains persistent connections for low-latency messaging
- Reduces overhead compared to HTTP for frequent messages
- Built-in heartbeating and reconnection

### Message Queue Protocol

Broker-based communication via RabbitMQ, Kafka, or Redis:

- Decouples senders and receivers
- Provides reliable message delivery with queuing
- Supports both direct and pub/sub communication patterns
- Ideal for highly distributed environments

## Protocol Selection

Use these guidelines to select the appropriate protocol:

| Protocol | Advantages | Disadvantages | Best For |
|----------|------------|---------------|----------|
| REST | Simple, firewall-friendly, stateless | Higher latency, larger overhead | Internet-facing deployments, simple setups |
| WebSocket | Low latency, efficient | Requires persistent connections | LAN deployments, high-message-rate scenarios |
| Message Queue | Highly reliable, scalable | Requires broker infrastructure | Large enterprise deployments, cloud environments |

## Performance Considerations

### Batching

For efficiency, the protocol supports batching multiple logical messages into a single physical message:

```json
{
  "message_type": "BATCH",
  "payload": {
    "messages": [
      {
        "message_type": "TASK_RESULT",
        "payload": { /* Task result 1 */ }
      },
      {
        "message_type": "TASK_RESULT",
        "payload": { /* Task result 2 */ }
      },
      {
        "message_type": "STATUS_UPDATE",
        "payload": { /* Status update for another task */ }
      }
    ]
  }
}
```

### Compression

For large payloads, the protocol supports compression:

- Set the `Content-Encoding: gzip` header for REST implementations
- Specify `compression: "gzip"` in the message envelope for other protocols

### Binary Encoding

For maximum efficiency, the protocol supports Protocol Buffers for binary encoding:

- Reduces message size by 60-80% compared to JSON
- Significantly faster serialization/deserialization
- Schema-based validation

## Security Considerations

The protocol implements multiple security measures:

### Authentication

- TLS mutual authentication for REST and WebSocket protocols
- Token-based authentication with JWT
- API key authentication for simple deployments

### Encryption

- TLS 1.3+ for all communications
- Optional payload encryption for sensitive data

### Authorization

- Role-based access control for different node types
- Capability-based authorization for task execution

## Error Handling

The protocol defines a standard approach to error handling:

### Error Codes

| Error Code | Description |
|------------|-------------|
| authentication_failed | Authentication credentials invalid or missing |
| authorization_failed | Node lacks permission for the requested operation |
| invalid_message | Message format or content is invalid |
| task_execution_failed | Task execution encountered an error |
| resource_exhausted | Node lacks resources to process the request |
| node_not_found | Target node does not exist or is unreachable |
| internal_error | Unspecified internal error |

### Retries

The protocol implements a standard retry mechanism:

- Exponential backoff for transient errors
- Configurable retry limits and backoff parameters
- Idempotency keys to prevent duplicate processing

## Monitoring

The protocol includes built-in monitoring capabilities:

- Message tracing with correlation IDs
- Metrics collection for message rates and sizes
- Latency tracking for performance analysis

## Custom Protocol Implementations

To implement a custom protocol adapter:

1. Extend the `ProtocolBase` abstract class
2. Implement the required message handling methods
3. Register the protocol with the protocol factory

Example:

```python
from sniper.distributed.protocol import ProtocolBase, MessageType

class CustomProtocol(ProtocolBase):
    def __init__(self, config):
        super().__init__()
        self.config = config
        # Initialize custom protocol handlers
        
    async def send_message(self, message):
        # Implement message sending logic
        pass
        
    async def receive_message(self):
        # Implement message receiving logic
        pass
        
    def start(self):
        # Start the protocol handler
        pass
        
    def stop(self):
        # Stop the protocol handler
        pass

# Register the custom protocol
from sniper.distributed.protocol import register_protocol
register_protocol("custom", CustomProtocol)
```

## Version Compatibility

The protocol includes versioning to ensure compatibility:

- Version negotiation during node registration
- Backward compatibility guarantees
- Feature detection for optional capabilities

## Conclusion

The Sniper distributed scanning protocol provides a robust, efficient, and secure foundation for communication between distributed nodes. By selecting the appropriate protocol implementation and following the best practices outlined in this guide, you can ensure reliable and high-performance operation of your distributed scanning infrastructure. 