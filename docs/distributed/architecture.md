# Distributed Scanning Architecture

The Sniper Security Tool implements a distributed scanning architecture to enable efficient and scalable security testing across large enterprises. This document outlines the key components, protocols, and algorithms used in the distributed scanning system.

## Architecture Overview

The distributed scanning architecture follows a master-worker pattern:

```
                    ┌───────────────┐
                    │  Master Node  │
                    └───────┬───────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
     ┌──────▼──────┐  ┌─────▼──────┐  ┌─────▼─────┐
     │ Worker Node │  │ Worker Node│  │Worker Node│
     └─────────────┘  └────────────┘  └───────────┘
```

- **Master Node**: Coordinates all scanning activities, distributes tasks, and aggregates results
- **Worker Nodes**: Execute security scanning tasks and report results back to the master
- **Communication Protocol**: REST-based protocol for reliable message exchange between nodes
- **Distribution Algorithms**: Multiple algorithms for efficiently distributing work based on various criteria

## Core Components

### 1. Master Node (src/distributed/master.py)

The master node is responsible for:

- Managing worker node registration and capabilities
- Distributing scanning tasks to appropriate workers
- Monitoring worker health through heartbeats
- Aggregating scan results from workers
- Implementing fault tolerance for worker failures
- Providing an API for scan management

### 2. Worker Node (src/distributed/worker.py)

Worker nodes are responsible for:

- Registering with the master node
- Executing assigned scanning tasks
- Reporting task status and results to the master
- Sending regular heartbeats to verify availability
- Managing local resources efficiently
- Supporting multiple concurrent tasks

### 3. Communication Protocol (src/distributed/protocol.py)

The communication protocol provides:

- Standardized message format for node communication
- Support for different transport mechanisms (REST, gRPC)
- Message types for registration, heartbeats, task assignment, etc.
- Serialization and deserialization of messages
- Secure communication between nodes

### 4. Distribution Algorithms (src/distributed/distribution.py)

The system implements several work distribution algorithms:

- **Round Robin**: Simple and fair distribution across all workers
- **Priority-Based**: Assigns tasks based on priority levels
- **Capability-Based**: Matches tasks to workers with required capabilities
- **Load-Balanced**: Distributes tasks based on current worker load
- **Weighted**: Considers worker performance and reliability
- **Smart Distribution**: Uses ML to optimize task assignment

## Implementation Details

### Task Lifecycle

1. **Creation**: Tasks are created with specific properties (type, target, parameters)
2. **Assignment**: The master assigns tasks to suitable worker nodes
3. **Execution**: Workers process assigned tasks and update status
4. **Completion**: Workers report results or errors back to the master
5. **Aggregation**: The master aggregates results into a comprehensive report

### Worker Health Monitoring

- Workers send regular heartbeats to indicate availability
- The master tracks worker responsiveness and health metrics
- Unresponsive workers are considered failed, and their tasks are reassigned
- Workers report resource utilization to enable smart task assignment

### Fault Tolerance

- Tasks are automatically reassigned if workers fail
- The master maintains the state of all running tasks
- Workers can recover and resume tasks in certain scenarios
- The system handles network partitions and reconnections

## Deployment Considerations

### Scaling

- Workers can be added dynamically to increase scanning capacity
- The master node can handle thousands of concurrent worker connections
- Resource consumption scales linearly with the number of scanning targets

### Security

- All communication between nodes is authenticated
- Workers verify the identity of the master before accepting tasks
- Sensitive scan data is protected in transit and at rest

## Future Enhancements

1. **Auto-scaling**: Automatically adjust worker count based on scan load
2. **Cloud Integration**: Native deployment to AWS, Azure, and GCP
3. **Hybrid Scanning**: Coordinate scans across internal and cloud workers
4. **Enhanced Fault Tolerance**: Implement master node clustering for high availability

## Configuration Examples

Sample master node configuration:
```yaml
master:
  host: 0.0.0.0
  port: 5555
  protocol: rest
  distribution_algorithm: smart
  worker_timeout: 60
  monitoring_interval: 15
```

Sample worker node configuration:
```yaml
worker:
  master_host: master.example.com
  master_port: 5555
  protocol: rest
  capabilities:
    - nmap
    - web_scan
    - vulnerability_scan
  max_concurrent_tasks: 5
  heartbeat_interval: 15
```

## Conclusion

The distributed scanning architecture provides a flexible and scalable approach to security testing across large environments. By efficiently distributing the scanning workload, the system can handle enterprise-scale security assessments while providing robust fault tolerance and adaptability. 