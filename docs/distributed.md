# Sniper Distributed Scanning Architecture

This guide explains how to use the distributed scanning capabilities in the Sniper Security Tool.

## Overview

The distributed scanning architecture enables:

- Running scans across multiple machines
- Specialized workers for specific tasks
- Efficient distribution of scanning workloads
- Fault tolerance through worker redundancy

## Components

The architecture consists of two main components:

1. **Master Node**: Coordinates all scanning activities, distributes tasks, and collects results
2. **Worker Nodes**: Execute scanning tasks and report results back to the master

## Quick Start

### Starting a Master Node

```bash
# Using the Typer CLI (recommended)
python -m src.cli.distributed_typer master start --host 0.0.0.0 --port 5000

# Using the simplified CLI for demonstration
python -m src.cli.distributed_typer_simple distributed master start

# Using Docker Compose
docker-compose -f docker-compose.distributed.yml up master
```

### Starting Worker Nodes

```bash
# Using the Typer CLI (recommended)
python -m src.cli.distributed_typer worker start --master localhost:5000 --capabilities vulnerability_scan,recon

# Using the simplified CLI for demonstration
python -m src.cli.distributed_typer_simple distributed worker start --master-host localhost

# Using Docker Compose
docker-compose -f docker-compose.distributed.yml up worker
```

### Using the Runner Scripts

For convenience, you can use the provided runner scripts:

```bash
# Start a master node
./run_distributed.py master start

# Start a worker node
./run_worker_typer.py start --master localhost:5000
```

## Command Reference

### Master Node Commands

```bash
# Start a master node
python -m src.cli.distributed_typer master start [OPTIONS]

# Options:
#   --host TEXT                  Host address to bind to [default: 0.0.0.0]
#   --port INTEGER               Port to listen on [default: 5000]
#   --protocol TEXT              Communication protocol to use [default: rest]
#   --distribution-strategy TEXT Task distribution strategy [default: capability_based]
#   --worker-timeout INTEGER     Seconds after which a worker is considered offline [default: 60]
#   --config PATH                Path to configuration file
#   --auto-scaling               Enable auto-scaling of worker nodes [default: False]
#   --min-nodes INTEGER          Minimum number of worker nodes [default: 1]
#   --max-nodes INTEGER          Maximum number of worker nodes [default: 10]
#   --scaling-policy TEXT        Auto-scaling policy [default: queue_depth]
#   --scaling-provider TEXT      Provider for worker nodes [default: docker]
#   --provider-config PATH       Path to provider configuration file
#   --log-level TEXT             Logging level [default: info]
#   --help                       Show this message and exit.

# Stop a master node
python -m src.cli.distributed_typer master stop

# Get master node status
python -m src.cli.distributed_typer master status
```

### Worker Node Commands

```bash
# Start a worker node
python -m src.cli.distributed_typer worker start [OPTIONS]

# Options:
#   -m, --master TEXT       Master node address (host:port) [default: localhost:5000]
#   --worker-id TEXT        Unique ID for this worker (generated if not provided)
#   --protocol TEXT         Communication protocol to use [default: rest]
#   -c, --capabilities TEXT Comma-separated list of task types this worker can execute
#   --max-tasks INTEGER     Maximum number of concurrent tasks [default: 5]
#   --config PATH           Path to configuration file
#   -l, --log-level TEXT    Logging level [default: info]
#   --help                  Show this message and exit.

# Stop a worker node
python -m src.cli.distributed_typer worker stop

# Get worker node status
python -m src.cli.distributed_typer worker status
```

### Task Management Commands

```bash
# List tasks
python -m src.cli.distributed_typer tasks list

# Get task info
python -m src.cli.distributed_typer tasks info TASK_ID

# Cancel a task
python -m src.cli.distributed_typer tasks cancel TASK_ID
```

### Worker Management Commands

```bash
# List workers
python -m src.cli.distributed_typer workers list
```

## Using Docker Compose

The project includes a Docker Compose configuration for the distributed architecture:

```bash
# Start the entire distributed system
docker-compose -f docker-compose.distributed.yml up

# Scale workers as needed
docker-compose -f docker-compose.distributed.yml up --scale worker=5

# Start just the master node
docker-compose -f docker-compose.distributed.yml up master

# Start the simplified version for demonstration
docker-compose -f docker-compose.distributed.yml --profile simple up
```

## Worker Capabilities

Workers can be configured with different capabilities to specialize in certain types of tasks:

- `vulnerability_scan`: Vulnerability scanning and exploitation
- `recon`: Reconnaissance operations
- `autonomous_test`: AI-driven testing with minimal configuration
- `enum`: Enumeration of systems and services
- `fuzzing`: Fuzz testing of applications
- `web_scan`: Web application scanning

## Advanced Configuration

### Configuration Files

Both master and worker nodes can be configured using JSON or YAML files:

```yaml
# Example master.yaml
master:
  host: 0.0.0.0
  port: 5000
  protocol: rest
  distribution_strategy: smart
  worker_timeout: 60
  auto_scaling: true
  min_nodes: 1
  max_nodes: 10

# Example worker.yaml
worker:
  master_host: localhost
  master_port: 5000
  protocol: rest
  capabilities:
    - vulnerability_scan
    - recon
  max_tasks: 5
  heartbeat_interval: 30
```

### Auto-Discovery

The auto-discovery feature automatically sets up a distributed environment:

```bash
python -m src.cli.distributed_typer auto --config config/distributed.yaml
```

## Troubleshooting

### Common Issues

1. **Worker cannot connect to master**:
   - Verify the master is running
   - Check network connectivity
   - Ensure ports are open on firewalls
   - Verify that the master host and port are correct

2. **Worker not receiving tasks**:
   - Check that worker capabilities match task requirements
   - Verify worker registration with `workers list` command
   - Examine master logs for distribution issues

3. **Task execution failures**:
   - Check worker logs for error information
   - Verify dependencies are installed on worker nodes
   - Ensure worker has sufficient resources

### Logs

Log files are essential for debugging issues:

```bash
# View master logs
tail -f logs/master.log

# View worker logs
tail -f logs/worker.log
```

## Extending the System

### Creating Custom Task Types

To add a new task type:

1. Define the task type and parameters
2. Implement a handler in the worker node
3. Register the handler with the worker node
4. Update worker capabilities to include the new task type

### Implementing Custom Distribution Strategies

You can create custom distribution strategies for specialized workflows:

1. Extend the `DistributionAlgorithm` class
2. Implement the `distribute` method
3. Register your strategy with the master node

## API Reference

See the [API documentation](api_reference.md) for programmatic access to the distributed system. 