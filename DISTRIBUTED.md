# Sniper Distributed Scanning Architecture

This document describes the distributed scanning architecture implemented in Sniper Security Tool.

## Overview

The distributed architecture allows Sniper to distribute scanning tasks across multiple worker nodes, enabling:

- **Horizontal Scaling**: Run scans across multiple machines to handle large targets
- **Specialized Workers**: Configure workers with specific capabilities for specialized tasks
- **Load Balancing**: Distribute tasks efficiently across available workers
- **Fault Tolerance**: Recover from worker failures and node disconnections

## Architecture Components

### Master Node

The master node is responsible for:
- Coordinating all distributed operations
- Managing worker registration and health
- Distributing tasks to workers
- Tracking task status and results
- Providing a centralized API for clients

### Worker Nodes

Worker nodes handle:
- Executing assigned scanning tasks
- Reporting results back to the master
- Sending heartbeats to indicate health
- Supporting multiple task types based on capabilities

### Task Distribution

Tasks are distributed based on:
- Worker capabilities
- Current worker load
- Task priority
- Configured distribution strategy

## Quick Start

### Starting a Master Node

```bash
# Start a master node with default settings
poetry run sniper distributed master start

# Start with custom settings
poetry run sniper distributed master start --host 0.0.0.0 --port 5000 --strategy round-robin
```

### Starting a Worker Node

```bash
# Start a worker node connecting to a local master
poetry run sniper distributed worker start

# Connect to a remote master with specific capabilities
poetry run sniper distributed worker start --master-host 192.168.1.100 --capabilities "vuln_scan,recon"
```

### Managing Tasks and Workers

```bash
# List all registered workers
poetry run sniper distributed workers list

# View all tasks
poetry run sniper distributed tasks list

# Get detailed information about a specific task
poetry run sniper distributed tasks info --task-id 8a7b6c5d-4e3f-2g1h-0i9j-8k7l6m5n4o3p

# Cancel a running task
poetry run sniper distributed tasks cancel --task-id 8a7b6c5d-4e3f-2g1h-0i9j-8k7l6m5n4o3p
```

## Advanced Configuration

### Worker Configuration

Workers can be configured with:
- **Capabilities**: Types of tasks the worker can handle (e.g., `ports`, `web`, `subdomains`)
- **Max Concurrent Tasks**: Number of tasks to run simultaneously (default: 4)
- **Heartbeat Interval**: Frequency of health checks (default: 30 seconds)
- **Custom Configuration**: Via JSON configuration file

Example worker configuration file (`worker-config.json`):
```json
{
  "capabilities": ["ports", "web", "subdomains", "vuln_scan"],
  "max_concurrent_tasks": 8,
  "heartbeat_interval": 15,
  "resource_limits": {
    "memory": "4GB",
    "cpu": 4
  },
  "tools": {
    "nmap": "/usr/bin/nmap",
    "zap": "docker"
  }
}
```

### Master Configuration

The master node supports:
- **Distribution Strategies**: round-robin, capability-based, load-balanced
- **Worker Timeout**: Time to wait before considering a worker offline (default: 90 seconds)
- **Task Prioritization**: Rules for determining task execution order
- **Auto-discovery**: Optional automatic discovery of workers on the network

Example master configuration file (`master-config.json`):
```json
{
  "distribution_strategy": "load-balanced",
  "worker_timeout": 120,
  "task_priorities": {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25
  },
  "auto_discovery": {
    "enabled": true,
    "subnet": "192.168.1.0/24"
  },
  "security": {
    "require_authentication": true,
    "api_key": "sniper-api-key-secure-random-string"
  }
}
```

## Security Considerations

- All communication between nodes is encrypted using TLS
- Worker authentication is required for registration with the master
- API access is restricted by API keys and optional IP allowlisting
- Sensitive scan results are encrypted in transit and at rest
- Workers are isolated with least privilege access

## Implementing Custom Workers

To create a specialized worker:

1. Extend the `SniperWorkerNode` class
2. Implement custom task handlers
3. Register capabilities with the master
4. Deploy on appropriate hardware

Example custom worker implementation:

```python
from src.distributed.worker import SniperWorkerNode
from src.distributed.tasks import TaskResult

class CustomWorker(SniperWorkerNode):
    def __init__(self, master_host, master_port):
        # Register the custom capability
        capabilities = ["custom_scan"]
        super().__init__(master_host, master_port, capabilities=capabilities)
        
    async def handle_custom_scan(self, task_data):
        # Custom implementation for this specific task type
        target = task_data.get("target")
        options = task_data.get("options", {})
        
        # Perform the custom scanning logic
        result = self._perform_custom_scan(target, options)
        
        # Return the task result
        return TaskResult(
            task_id=task_data["task_id"],
            status="completed",
            data=result
        )
        
    def _perform_custom_scan(self, target, options):
        # Actual scanning implementation
        return {
            "findings": [
                {"type": "vulnerability", "severity": "high", "details": "..."}
            ],
            "metadata": {
                "scan_time": 45.2,
                "tool_version": "1.2.3"
            }
        }
```

## Troubleshooting

Common issues and solutions:

- **Worker Registration Failures**: 
  - Check network connectivity and firewall rules (ports 5000-5010)
  - Verify the master is running and accessible from the worker
  - Ensure the worker has the correct master hostname/IP and port

- **Task Distribution Issues**: 
  - Verify worker capabilities match task requirements
  - Check worker capacity and current load
  - Examine task queues with `poetry run sniper distributed tasks queues`

- **Node Communication Errors**: 
  - Ensure protocol settings match between master and workers
  - Check for certificate validation errors if using TLS
  - Verify network stability between nodes

## API Reference

The distributed system provides a RESTful API for controlling and monitoring the system:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/workers` | GET | List all registered workers |
| `/api/v1/workers/<worker_id>` | GET | Get worker details |
| `/api/v1/workers/<worker_id>/tasks` | GET | List tasks assigned to a worker |
| `/api/v1/tasks` | GET | List all tasks |
| `/api/v1/tasks` | POST | Create a new task |
| `/api/v1/tasks/<task_id>` | GET | Get task details |
| `/api/v1/tasks/<task_id>` | DELETE | Cancel a task |
| `/api/v1/tasks/<task_id>/results` | GET | Get task results |

See the full [API documentation](docs/api_reference.md) for details on programmatically interacting with the distributed system.

## Example: Docker Compose Setup

For quick deployment of a multi-node environment, use the provided Docker Compose configuration:

```bash
# Start a master and 3 workers
docker compose -f docker-compose.distributed.yml up -d

# Scale to more workers if needed
docker compose -f docker-compose.distributed.yml up -d --scale worker=5

# Submit a task via the API
curl -X POST http://localhost:5000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "type": "scan",
    "target": "https://example.org",
    "modules": ["ports", "web", "subdomains"],
    "priority": "high"
  }'
``` 