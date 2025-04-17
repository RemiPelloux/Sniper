# Distributed Scanning Architecture Documentation

## Overview

The Sniper Security Tool's distributed scanning architecture enables scalable and efficient security scanning across multiple worker nodes. This document details the architecture, communication patterns, task distribution mechanisms, scaling strategies, and performance optimization techniques.

## Architecture Components

### 1. Node Types

- **Master Node**: Central coordinator that manages worker nodes, distributes tasks, aggregates results, and provides a unified interface to clients.
- **Worker Node**: Executes scanning tasks, reports results back to the master, and maintains regular heartbeat communication.
- **Hybrid Node**: Combines master and worker functionality, enabling hierarchical deployment for large-scale scanning operations.

### 2. Communication Protocol

The architecture supports multiple communication protocols:

- **REST API**: HTTP-based communication with JSON payloads for broad compatibility.
- **gRPC** *(future)*: High-performance RPC framework for low-latency communication.
- **WebSockets** *(future)*: For real-time bi-directional communication.

### 3. Message Types

- **Registration**: Worker nodes register with master, declaring capabilities and system resources.
- **Heartbeat**: Regular status updates sent from workers to master.
- **Task Assignment**: Master assigns tasks to workers based on distribution algorithms.
- **Task Status**: Workers report task progress and status changes.
- **Task Result**: Workers send completed task results back to master.
- **Control Commands**: Master can send commands to workers (cancel task, shutdown, etc.).

### 4. Distribution Algorithms

The architecture supports multiple task distribution strategies:

- **Round Robin**: Simple rotation through available workers.
- **Priority-Based**: Distributes tasks based on task priority.
- **Capability-Based**: Matches tasks to workers with specific capabilities.
- **Load-Balanced**: Distributes based on current worker load.
- **Weighted**: Factors in worker performance metrics and capabilities.
- **Smart Distribution**: Uses ML to optimize task distribution based on historical performance.

## Deployment Models

### 1. Single Master with Multiple Workers

```
                       ┌──────────────┐
                       │  Master Node │
                       └──────┬───────┘
                              │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼─────────┐  ┌────────▼────────┐  ┌───────▼─────────┐
│   Worker Node   │  │   Worker Node   │  │   Worker Node   │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

- **Best for**: Small to medium deployments with centralized control.
- **Pros**: Simple to manage, single point of control.
- **Cons**: Single point of failure, limited scalability.

### 2. Hierarchical Deployment

```
                       ┌──────────────┐
                       │  Master Node │
                       └──────┬───────┘
                              │
        ┌────────────────────┼────────────────────┐
        │                     │                    │
┌───────▼─────────┐  ┌────────▼────────┐  ┌───────▼─────────┐
│  Hybrid Node    │  │  Hybrid Node    │  │  Hybrid Node    │
└───────┬─────────┘  └────────┬────────┘  └───────┬─────────┘
        │                     │                    │
   ┌────┴────┐           ┌────┴────┐          ┌────┴────┐
   │         │           │         │          │         │
┌──▼──┐   ┌──▼──┐     ┌──▼──┐   ┌──▼──┐    ┌──▼──┐   ┌──▼──┐
│ Worker │ │ Worker │  │ Worker │ │ Worker │  │ Worker │ │ Worker │
└───────┘ └───────┘  └───────┘ └───────┘  └───────┘ └───────┘
```

- **Best for**: Large-scale deployments across multiple networks or regions.
- **Pros**: High scalability, network locality, reduced central load.
- **Cons**: More complex to manage, requires robust synchronization.

### 3. Clustered Masters

```
           ┌─────────────────────────────────────┐
           │             Load Balancer           │
           └───────┬───────────────┬─────────────┘
                   │               │
        ┌──────────▼────┐  ┌───────▼──────┐
        │  Master Node  │  │  Master Node │
        │  (Primary)    │◄─┤  (Secondary) │
        └──────────┬────┘  └───────┬──────┘
                   │               │
         ┌─────────┴───────┬───────┴─────────┐
         │                 │                 │
┌────────▼──────┐  ┌───────▼───────┐  ┌──────▼───────┐
│  Worker Node  │  │  Worker Node  │  │  Worker Node │
└───────────────┘  └───────────────┘  └──────────────┘
```

- **Best for**: High-availability and fault-tolerant deployments.
- **Pros**: No single point of failure, high availability.
- **Cons**: Requires complex state synchronization between masters.

## Communication Sequence Diagrams

### Worker Registration

```
Worker                  Master
  │                       │
  │   Registration        │
  │───────────────────────►
  │                       │ ┌─────────────────┐
  │                       │ │ Validate worker │
  │                       │ │ Store worker info│
  │                       │ └─────────────────┘
  │   Registration ACK    │
  │◄───────────────────────
  │                       │
```

### Task Assignment and Execution

```
Client           Master           Worker
  │                │                │
  │ Submit Task    │                │
  │───────────────►│                │
  │                │                │
  │                │ Select Worker  │
  │                │───────────────►│
  │                │ Task Assignment│
  │                │───────────────►│
  │                │                │ ┌─────────────┐
  │                │                │ │ Execute Task│
  │                │Task Status (Running)           │
  │                │◄───────────────│ └─────────────┘
  │                │                │
  │                │   Task Result  │
  │                │◄───────────────│
  │  Task Result   │                │
  │◄───────────────│                │
  │                │                │
```

## Fault Tolerance Mechanisms

### 1. Worker Node Failures

- **Heartbeat Monitoring**: Regular heartbeats detect worker failures.
- **Task Reassignment**: Failed tasks are automatically reassigned to other workers.
- **Stale Task Detection**: Tasks that have been running too long are considered stalled and reassigned.
- **Graceful Degradation**: Master continues operating with reduced worker capacity.

### 2. Master Node Failures

- **Master Redundancy**: Secondary masters can take over if primary fails.
- **State Persistence**: Task and worker state is persisted to enable recovery.
- **Worker Reconnection**: Workers attempt to reconnect to alternate masters if primary is unreachable.

### 3. Network Failures

- **Message Retries**: Failed message deliveries are retried with exponential backoff.
- **Idempotent Operations**: Operations can be safely retried without side effects.
- **Connection Recovery**: Automatic reconnection after network interruptions.

## Performance Optimization

### 1. Task Batching

- Group small related tasks into batches to reduce communication overhead.
- Batching strategy balances overhead reduction with need for fine-grained control.

### 2. Result Streaming

- Large scan results are streamed rather than sent as single large messages.
- Progressive result reporting allows for partial processing while scan continues.

### 3. Locality-Aware Distribution

- Tasks are preferentially assigned to workers with network locality to targets.
- Reduces latency and bandwidth usage for target-intensive scans.

### 4. Resource-Aware Scheduling

- Distribution algorithms consider worker resources (CPU, memory, network).
- Prevents resource exhaustion and ensures optimal task execution.

### 5. Caching

- Scan results are cached to avoid redundant scanning.
- Cache invalidation policies ensure security data freshness.

## Scaling Strategies

### 1. Horizontal Scaling

- Add more worker nodes to increase scan capacity.
- Worker auto-discovery allows seamless expansion.

### 2. Vertical Scaling

- Increase resources (CPU, memory) for master and worker nodes.
- Resource allocation is automatically detected and utilized.

### 3. Geographic Distribution

- Deploy workers across regions for global scanning coverage.
- Regional masters reduce latency for local task distribution.

### 4. Capability-Based Scaling

- Scale specific worker types based on task demand.
- Dynamically adjust worker capabilities based on scanning needs.

## Security Considerations

### 1. Communication Security

- All node communication is encrypted using TLS.
- Client authentication prevents unauthorized access to master services.
- Worker authentication prevents rogue worker registration.

### 2. Data Protection

- Sensitive scan results are encrypted at rest.
- Access control limits result visibility to authorized users.
- Data retention policies manage scan data lifecycle.

### 3. Operational Security

- Workers operate with minimal privileges required for assigned tasks.
- Network segmentation contains potential compromise impact.
- Regular security updates for all system components.

## Monitoring and Observability

### 1. System Metrics

- Worker and master resource utilization (CPU, memory, disk, network).
- Task throughput, execution time, queue depth.
- Error rates and types.

### 2. Health Checks

- Component health status (master, workers, database, etc.).
- Connectivity verification between system components.
- Automatic alerts for system degradation.

### 3. Logging and Auditing

- Centralized logging for all components.
- Audit trail for security-relevant actions.
- Performance log analysis for optimization.

## Best Practices for Deployment

### 1. Capacity Planning

- Each worker should have sufficient resources for its assigned scan types.
- Master nodes require more memory and storage than worker nodes.
- Network capacity planning should account for scan traffic and result data.

### 2. High Availability

- Deploy redundant master nodes for critical environments.
- Use database replication for result storage.
- Implement auto-scaling for worker nodes based on demand.

### 3. Network Configuration

- Configure appropriate firewall rules for master-worker communication.
- Ensure sufficient bandwidth between nodes.
- Consider network isolation for scan traffic.

### 4. Operation and Maintenance

- Regular backups of master state and scan results.
- Implement rolling updates to prevent service interruption.
- Establish monitoring and alerting thresholds.

## Examples and Tutorials

### 1. Basic Deployment

```bash
# Start a master node
python -m sniper.distributed.master --host 0.0.0.0 --port 5555

# Start a worker node
python -m sniper.distributed.worker --master-host 192.168.1.10 --master-port 5555
```

### 2. Configuration for Different Environments

**Development Configuration:**
```yaml
master:
  host: localhost
  port: 5555
  log_level: DEBUG
  distribution_strategy: round_robin

workers:
  heartbeat_interval: 5
  max_concurrent_tasks: 2
```

**Production Configuration:**
```yaml
master:
  host: 0.0.0.0
  port: 5555
  log_level: INFO
  distribution_strategy: weighted
  high_availability: true

workers:
  heartbeat_interval: 15
  max_concurrent_tasks: 10
  task_execution_timeout: 3600
```

### 3. Scaling Example

**Auto-scaling script example:**
```python
import psutil
import requests
import time

MASTER_URL = "http://master:5555/api/workers"
MAX_CPU_PERCENT = 80

while True:
    # Check current system load
    cpu_percent = psutil.cpu_percent(interval=5)
    
    # Get current worker count
    response = requests.get(f"{MASTER_URL}/count")
    current_workers = response.json()["count"]
    
    if cpu_percent > MAX_CPU_PERCENT and current_workers < 10:
        # Start a new worker
        requests.post(f"{MASTER_URL}/scale?delta=1")
    elif cpu_percent < 30 and current_workers > 1:
        # Reduce workers
        requests.post(f"{MASTER_URL}/scale?delta=-1")
    
    time.sleep(60)
```

## Troubleshooting

### Common Issues and Solutions

1. **Worker fails to register with master**
   - Check network connectivity and firewall rules
   - Verify master host and port configuration
   - Check for protocol version compatibility

2. **Tasks stuck in RUNNING state**
   - Check worker logs for execution errors
   - Verify worker heartbeat is functioning
   - Check resource utilization on worker node

3. **High task latency**
   - Check network bandwidth between nodes
   - Verify worker resources are sufficient
   - Consider adjusting distribution strategy

4. **Master node high resource usage**
   - Consider enabling result streaming for large scans
   - Implement hierarchical deployment with hybrid nodes
   - Reduce logging verbosity if appropriate

## Future Roadmap

1. **Enhanced Distribution Algorithms**
   - Machine learning-based task assignment optimization
   - Predictive scaling based on historical patterns
   - Target-aware clustering of related scan tasks

2. **Additional Protocols**
   - gRPC implementation for high-performance communication
   - WebSocket support for real-time updates
   - MQTT for lightweight IoT scanner integration

3. **Advanced Deployment Options**
   - Kubernetes operator for cloud-native deployment
   - Service mesh integration for enhanced observability
   - Serverless worker execution for burst capacity

4. **Extended Security Features**
   - Fine-grained access control for scan operations
   - Scan result anonymization options
   - Compliance reporting integration

## Conclusion

The distributed scanning architecture of the Sniper Security Tool provides a flexible, scalable, and fault-tolerant platform for security scanning operations. By following the guidelines and best practices outlined in this document, you can deploy and maintain an efficient distributed scanning infrastructure that meets your security testing requirements. 