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
python run_distributed_simple.py master start

# Start with custom settings
python run_distributed_simple.py master start --host 0.0.0.0 --port 5000 --strategy round-robin
```

### Starting a Worker Node

```bash
# Start a worker node connecting to a local master
python run_distributed_simple.py worker start

# Connect to a remote master with specific capabilities
python run_distributed_simple.py worker start --master-host 192.168.1.100 --capabilities "vuln_scan,recon"
```

### Managing Tasks and Workers

```bash
# List all registered workers
python run_distributed_simple.py workers list

# View all tasks
python run_distributed_simple.py tasks list

# Get detailed information about a specific task
python run_distributed_simple.py tasks info --task-id abc123

# Cancel a running task
python run_distributed_simple.py tasks cancel --task-id abc123
```

## Advanced Configuration

### Worker Configuration

Workers can be configured with:
- **Capabilities**: Types of tasks the worker can handle
- **Max Concurrent Tasks**: Number of tasks to run simultaneously
- **Heartbeat Interval**: Frequency of health checks
- **Custom Configuration**: Via JSON configuration file

### Master Configuration

The master node supports:
- **Distribution Strategies**: round-robin, capability-based, load-balanced
- **Worker Timeout**: Time to wait before considering a worker offline
- **Task Prioritization**: Rules for determining task execution order
- **Auto-discovery**: Optional automatic discovery of workers on the network

## Security Considerations

- All communication between nodes can be encrypted
- Worker authentication is required for registration
- API access can be restricted by IP and authentication tokens
- Sensitive scan results are encrypted in transit

## Implementing Custom Workers

To create a specialized worker:

1. Extend the `SniperWorkerNode` class
2. Implement custom task handlers
3. Register capabilities with the master
4. Deploy on appropriate hardware

## Troubleshooting

Common issues and solutions:

- **Worker Registration Failures**: Check network connectivity and firewall rules
- **Task Distribution Issues**: Verify worker capabilities match task requirements
- **Node Communication Errors**: Ensure protocol settings match between master and workers

## API Reference

See the API documentation for details on programmatically interacting with the distributed system.

## Examples

### Complete Distributed Scan Setup

```python
# Example Python code to set up a complete distributed scan
from sniper.distributed import MasterNode, WorkerNode, TaskManager

# Create and start master
master = MasterNode(host="0.0.0.0", port=5000)
master.start()

# Configure multiple workers
workers = []
for i in range(3):
    worker = WorkerNode(
        master_host="localhost",
        master_port=5000,
        capabilities=["vuln_scan", "recon"]
    )
    worker.start()
    workers.append(worker)

# Submit a distributed scan task
task_manager = TaskManager(master_host="localhost", master_port=5000)
task_id = task_manager.submit_task({
    "type": "vulnerability_scan",
    "target": "example.com",
    "options": {"depth": 3, "intensity": "medium"}
})

# Monitor progress
status = task_manager.get_task_status(task_id)
``` 