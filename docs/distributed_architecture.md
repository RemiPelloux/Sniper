# Sniper Distributed Scanning Architecture

The Sniper Distributed Scanning Architecture provides a scalable and efficient framework for performing security reconnaissance, vulnerability scanning, and exploitation tasks across distributed worker nodes.

## Architecture Overview

The distributed architecture consists of three main components:

1. **Master Node**: Coordinates task assignments, tracks worker status, and manages result collection
2. **Worker Nodes**: Process security tasks including autonomous testing, vulnerability scanning, and reconnaissance
3. **Client Interface**: Enables users to submit tasks and retrieve results

```
┌─────────┐         ┌──────────────┐         ┌─────────────┐
│         │  Tasks  │              │  Tasks  │             │
│ Clients ├────────►│ Master Node  ├────────►│ Worker Node │
│         │◄────────┤              │◄────────┤             │
└─────────┘ Results └──────────────┘ Results └─────────────┘
                          │                      ▲
                          │                      │
                          ▼                      │
                    ┌─────────────┐              │
                    │ Worker Node │◄─────────────┘
                    └─────────────┘
                          │
                          ▼
                    ┌─────────────┐
                    │ Worker Node │
                    └─────────────┘
```

## Components

### Master Node

The master node serves as the central coordinator for the distributed architecture. It:

- Maintains a registry of all connected worker nodes and their capabilities
- Distributes tasks based on priority and worker capabilities
- Monitors worker health through heartbeat mechanisms
- Collects and stores task results
- Provides an API for clients to submit tasks and retrieve results

### Worker Node

Worker nodes are responsible for executing security tasks. Each worker:

- Registers with the master node on startup
- Reports its capabilities (supported task types)
- Processes assigned tasks using specialized handlers
- Sends heartbeats to confirm operational status
- Returns task results to the master

Workers support multiple task types including:
- Autonomous vulnerability testing
- Vulnerability scanning
- Reconnaissance

### Client Interface

The client interface provides a programmatic way to interact with the Sniper distributed system. Through the client, users can:

- Submit various types of security tasks
- Check task status
- Retrieve task results
- Cancel running tasks
- Query master node status

## Usage

### Starting a Master Node

```bash
python -m src.distributed.master --host 0.0.0.0 --port 8080
```

### Starting a Worker Node

```bash
python -m src.distributed.worker --master-host <master_ip> --master-port 8080
```

### Using the Client Interface

See the example below for submitting an autonomous testing task:

```python
import asyncio
from src.distributed.client import SniperClient
from src.ml.autonomous_tester import VulnerabilityType
from src.distributed.base import TaskPriority

async def run_test():
    client = SniperClient("localhost", 8080)
    await client.connect()
    
    task_id = await client.submit_autonomous_test(
        target_url="https://example.com",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        priority=TaskPriority.HIGH
    )
    
    result = await client.wait_for_task_completion(task_id)
    print(result)
    
    await client.disconnect()

asyncio.run(run_test())
```

For more detailed examples, see the `examples/autonomous_test_client.py` file.

## Task Types

### Autonomous Testing

Tests a target for specific vulnerability types using advanced testing techniques.

Parameters:
- `target_url`: URL to test
- `vulnerability_type`: Type of vulnerability to test for (from VulnerabilityType enum)
- `custom_payloads`: Optional list of custom payloads to use
- `max_depth`: Maximum depth for crawling
- `timeout`: Maximum time to spend on the test

### Vulnerability Scanning

Performs comprehensive vulnerability scanning against a target.

Parameters:
- `target`: Target to scan (URL or IP)
- `scan_type`: Type of scan to perform
- `options`: Advanced scanning options

### Reconnaissance

Gathers information about a target using various techniques.

Parameters:
- `target`: Target to scan
- `techniques`: List of reconnaissance techniques to use
- `depth`: Depth of reconnaissance

## Security Considerations

- All communication between components uses encrypted protocols
- Worker authentication is required to prevent unauthorized nodes
- Task results are securely stored and accessible only to authorized clients
- Proper error handling prevents information leakage

## Advanced Configuration

For advanced deployment scenarios, the following configuration options are available:

- **Load Balancing**: Configure the master node with custom task distribution strategies
- **High Availability**: Deploy multiple master nodes with synchronization
- **Custom Task Handlers**: Extend worker nodes with specialized task handlers
- **Authentication**: Configure custom authentication mechanisms

## Troubleshooting

Common issues and their solutions:

1. **Connection Issues**: Ensure network connectivity between components and check firewall settings
2. **Task Timeouts**: Adjust task timeout settings or check for resource constraints
3. **Worker Disconnections**: Monitor worker logs for errors and check system resources

## API Reference

For detailed API documentation, see:
- `src/distributed/master.py` - Master node implementation
- `src/distributed/worker.py` - Worker node implementation
- `src/distributed/client.py` - Client interface
- `src/distributed/base.py` - Shared base components 