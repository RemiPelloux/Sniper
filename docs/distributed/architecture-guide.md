# Distributed Scanning Architecture Guide

## Overview

The Sniper distributed scanning architecture is designed to enable high-throughput, scalable security scanning across large infrastructure environments. This document provides a detailed explanation of the architectural components, design patterns, and communication flows that make up the distributed scanning system.

## Architecture Principles

The architecture is built on the following core principles:

1. **Scalability**: The system can scale horizontally by adding more worker nodes to handle increased scanning load.
2. **Reliability**: Fault tolerance is built into every component to ensure scans continue even if individual nodes fail.
3. **Efficiency**: Smart task distribution minimizes resource waste and optimizes scan completion time.
4. **Security**: Communication between components is secured, and access controls are enforced throughout.
5. **Extensibility**: The modular design allows for easy addition of new capabilities and scan types.
6. **Observability**: Comprehensive metrics and logging provide insight into system performance and issues.

## System Components

### Core Node Types

![Node Architecture](../assets/images/node-architecture.png)

#### Master Node

The master node is the central coordinator of the distributed scanning infrastructure. Key responsibilities include:

- Task distribution and worker coordination
- Scan scheduling and prioritization
- Result aggregation and analysis
- System monitoring and worker health checks
- API exposure for external integration

#### Worker Node

Worker nodes are responsible for executing security scanning tasks. Key responsibilities include:

- Tool execution and management
- Target interaction and data collection
- Result processing and normalization
- Resource management and self-monitoring
- Secure communication with master nodes

#### Hybrid Node

Hybrid nodes can function as both master and worker, offering flexibility in deployment topologies. They're particularly useful in:

- Edge deployments with limited connectivity
- High-availability configurations
- Hierarchical deployments spanning multiple networks
- Auto-scaling environments

### Component Architecture

The internal architecture of each node follows a modular design:

![Component Architecture](../assets/images/component-architecture.png)

#### Master Node Components

1. **API Service**:
   - Exposes REST endpoints for system control and integration
   - Handles authentication and authorization
   - Processes scan requests and provides results

2. **Task Manager**:
   - Maintains task queue and state
   - Prioritizes tasks based on configured rules
   - Tracks task execution status

3. **Worker Manager**:
   - Maintains registry of available workers
   - Monitors worker health and capabilities
   - Handles worker registration and deregistration

4. **Distribution Engine**:
   - Implements task distribution algorithms
   - Matches tasks to appropriate workers
   - Optimizes distribution for efficiency

5. **Results Processor**:
   - Aggregates and normalizes scan results
   - Performs cross-correlation analysis
   - Generates reports and alerts

6. **State Store**:
   - Maintains persistent system state
   - Supports high availability and clustering
   - Provides transaction support for critical operations

#### Worker Node Components

1. **Task Executor**:
   - Manages task execution workflow
   - Handles tool invocation and monitoring
   - Implements retry and error handling logic

2. **Tool Manager**:
   - Manages tool installation and updates
   - Validates tool dependencies and configuration
   - Provides abstraction for different tool types

3. **Resource Monitor**:
   - Tracks system resource utilization
   - Enforces resource limits for tasks
   - Reports metrics to master node

4. **Results Collector**:
   - Captures and normalizes tool output
   - Performs local analysis and enrichment
   - Prepares results for transmission

5. **Communication Agent**:
   - Handles all communication with master nodes
   - Implements protocol-specific adapters
   - Ensures secure and reliable messaging

## Master-Worker Communication

### Communication Patterns

The distributed architecture uses several communication patterns:

#### Request-Response

Used for operations requiring immediate confirmation:
- Worker registration and authentication
- Task assignment and acceptance
- On-demand status queries

#### Publish-Subscribe

Used for broadcasting information to multiple nodes:
- Configuration updates
- System-wide alerts
- Master node status changes

#### Asynchronous Messaging

Used for non-blocking operations:
- Result reporting
- Heartbeat messages
- Status updates

### Protocol Implementations

The architecture supports multiple protocol implementations:

#### REST Protocol

- Uses HTTP/HTTPS for communication
- Well-suited for systems with firewalls and proxies
- Supports synchronous operations with webhooks for asynchronous notifications
- Provides good compatibility with existing infrastructure

#### WebSocket Protocol

- Maintains persistent connections between nodes
- Offers lower latency for real-time communication
- Enables bi-directional communication
- More efficient for frequent small messages

#### Message Queue Protocol

- Uses message brokers (e.g., RabbitMQ, Kafka)
- Provides guaranteed message delivery and persistence
- Well-suited for high-scale deployments
- Enables advanced patterns like message routing and filtering

### Message Types

Communication between master and worker nodes uses a standardized message format with the following types:

#### Worker Management Messages

- **REGISTER**: Worker registration with master
- **REGISTER_RESPONSE**: Confirmation of registration
- **UNREGISTER**: Worker graceful shutdown notification
- **HEARTBEAT**: Periodic worker status update

#### Task Management Messages

- **TASK_REQUEST**: Worker request for new tasks
- **TASK_ASSIGNMENT**: Master assigning task to worker
- **TASK_RESULT**: Worker reporting task results
- **TASK_CANCEL**: Master requesting task cancellation
- **STATUS_UPDATE**: Worker reporting task progress

#### System Messages

- **ERROR**: Error notification
- **CONFIG_UPDATE**: Configuration change notification
- **CAPABILITY_UPDATE**: Worker capability update

## Task Distribution

### Distribution Algorithms

The architecture implements several distribution algorithms to match different use cases:

#### Round Robin Distribution

- Distributes tasks evenly across all available workers
- Simple implementation with minimal overhead
- Best for homogeneous environments where all workers have similar capabilities

#### Priority-based Distribution

- Assigns tasks based on priority levels
- Ensures high-priority scans are completed first
- Supports differentiated service levels for different targets

#### Capability-based Distribution

- Matches tasks to workers based on their tool capabilities
- Ensures workers only receive tasks they can execute
- Optimizes for specialized worker configurations

#### Load-balanced Distribution

- Distributes tasks based on current worker load
- Prevents any single worker from becoming overwhelmed
- Adjusts dynamically to changing worker performance

#### Smart Distribution

- Combines multiple factors including worker capabilities, load, performance history, and task requirements
- Uses machine learning to optimize distribution decisions
- Provides the best overall system performance in complex environments

### Distribution Workflow

The task distribution process follows these steps:

1. **Worker Filtering**:
   - Filter out disconnected or unhealthy workers
   - Match task requirements against worker capabilities
   - Apply any task-specific worker selection rules

2. **Algorithm Application**:
   - Apply the selected distribution algorithm to the filtered worker list
   - Generate a ranked list of suitable workers for the task

3. **Assignment**:
   - Assign the task to the highest-ranked available worker
   - Track assignment status and handle acceptance/rejection

4. **Monitoring**:
   - Track task execution status
   - Handle timeouts and worker failures
   - Reassign tasks when necessary

## Task Execution

### Task Lifecycle

Tasks move through the following states during their lifecycle:

1. **Created**: Task is created and placed in the queue
2. **Pending**: Task is waiting to be assigned to a worker
3. **Assigned**: Task has been assigned to a worker but not started
4. **Running**: Task is currently being executed by a worker
5. **Completing**: Task execution has finished, results being processed
6. **Completed**: Task is fully complete with results stored
7. **Failed**: Task execution failed and may be retried
8. **Cancelled**: Task was cancelled before completion

### Execution Flow

The execution flow for a typical task includes:

1. **Preparation**:
   - Worker validates the task parameters
   - Resources are allocated for the task
   - Required tools are verified

2. **Execution**:
   - Tools are launched with appropriate parameters
   - Execution is monitored for resource usage and progress
   - Intermediate results may be captured

3. **Result Processing**:
   - Tool output is parsed and normalized
   - Results are enriched with additional context
   - Findings are classified and prioritized

4. **Reporting**:
   - Results are transmitted to the master node
   - Local task state is updated
   - Resources are released

## High Availability and Fault Tolerance

### Master Node Clustering

For high availability, master nodes can be configured in a cluster:

![Master Clustering](../assets/images/master-clustering.png)

- Uses consensus algorithms (e.g., Raft) for leader election
- Maintains synchronized state across all nodes
- Provides automatic failover if the leader node fails
- Enables rolling updates without service interruption

### Worker Fault Tolerance

Worker failures are handled through multiple mechanisms:

- **Heartbeat monitoring** detects worker node failures
- **Task timeouts** identify stalled executions
- **Automatic task reassignment** moves tasks from failed workers
- **Result persistence** prevents data loss during failures
- **Graceful degradation** prioritizes critical tasks during resource constraints

### Network Partition Handling

The system is designed to handle network partitions:

- Workers can operate independently when disconnected from master
- Results are queued locally until connectivity is restored
- Master nodes can reform clusters after partitions heal
- Conflict resolution strategies prevent duplicate work

## Scaling and Performance

### Horizontal Scaling

The system scales horizontally by adding more nodes:

- **Worker scaling** increases overall scan capacity
- **Master scaling** improves coordination capacity and fault tolerance
- **Dynamic scaling** adjusts capacity based on workload

### Performance Optimization

Several techniques are used to optimize performance:

- **Batched communication** reduces network overhead
- **Connection pooling** minimizes setup/teardown costs
- **Resource-aware scheduling** maximizes hardware utilization
- **Concurrent execution** leverages multi-core processors
- **Cached results** prevent duplicate work
- **Compressed data transfer** reduces network bandwidth

### Resource Management

The architecture includes sophisticated resource management:

- **CPU throttling** prevents workers from becoming overloaded
- **Memory limits** ensure stable operation under pressure
- **Disk space monitoring** prevents failures due to storage exhaustion
- **Network bandwidth controls** prevent scan traffic from overwhelming infrastructure

## Security Considerations

### Authentication and Authorization

The system implements a comprehensive security model:

- **Mutual TLS authentication** secures node communication
- **Token-based authentication** for API access
- **Role-based access control** for administrative functions
- **Capability-based authorization** for worker operations

### Network Security

Network communications are secured through:

- **TLS encryption** for all network traffic
- **Certificate validation** prevents man-in-the-middle attacks
- **Network segmentation** recommendations for deployment
- **Port minimization** reduces attack surface

### Data Protection

Sensitive data is protected through:

- **At-rest encryption** for stored scan results
- **In-transit encryption** for all communications
- **Data minimization** principles in result storage
- **Retention policies** for scan history

## Monitoring and Observability

### Metrics Collection

The system collects comprehensive metrics:

- **Node-level metrics**: CPU, memory, disk, network
- **Task-level metrics**: Execution time, success rate, resource usage
- **System-level metrics**: Queue depth, assignment rate, result processing time
- **Scan-level metrics**: Coverage, finding rates, severity distribution

### Logging and Tracing

Distributed logging is implemented across the system:

- **Structured logging** with consistent formats
- **Correlation IDs** link related events across components
- **Log aggregation** recommendations for centralized analysis
- **Trace context propagation** for end-to-end request tracking

### Alerting and Reporting

The monitoring system supports alerting on various conditions:

- **Worker health degradation** or disconnection
- **Master node failures** or cluster issues
- **Queue depth increases** beyond thresholds
- **Scan failures** or timeout rates
- **Resource constraints** affecting performance

## Custom Extensions

### Adding New Protocols

The architecture supports custom protocol implementations:

1. Implement the `ProtocolBase` interface
2. Register the protocol implementation with the protocol factory
3. Configure nodes to use the new protocol

### Adding Distribution Algorithms

Custom distribution algorithms can be implemented by:

1. Extending the `DistributionAlgorithm` base class
2. Implementing the `distribute()` method with custom logic
3. Registering the algorithm with the distribution engine

### Adding Node Capabilities

Worker node capabilities can be extended by:

1. Implementing tool integration for new scanning tools
2. Defining capability metadata in the worker configuration
3. Updating task requirements to leverage new capabilities

## Deployment Considerations

See the [Deployment Guide](deployment-guide.md) for detailed information about deploying the distributed scanning architecture in various environments.

## Implementation References

For developers looking to understand or contribute to the implementation:

- **Base Node Classes**: `src/distributed/base.py`
- **Protocol Implementations**: `src/distributed/protocol.py`
- **Distribution Algorithms**: `src/distributed/distribution.py`
- **Task Management**: `src/distributed/task.py`
- **Worker Implementation**: `src/distributed/worker.py`
- **Master Implementation**: `src/distributed/master.py`

## Diagrams and Visual References

### System Topology Diagram

![System Topology](../assets/images/system-topology.png)

### Communication Flow Diagram

![Communication Flow](../assets/images/communication-flow.png)

### Task Distribution Sequence

![Task Distribution](../assets/images/task-distribution-sequence.png)

### Task Execution Sequence

![Task Execution](../assets/images/task-execution-sequence.png)

## Conclusion

The Sniper distributed scanning architecture provides a robust, scalable foundation for security scanning across large infrastructures. By leveraging a master-worker pattern with advanced distribution algorithms and fault tolerance mechanisms, the system can efficiently scan thousands of targets while maintaining high reliability and performance.

The modular design allows for customization and extension to meet specific organizational needs, while the built-in security features ensure that the scanning infrastructure itself remains protected. With comprehensive monitoring and observability features, operators have full visibility into the system's performance and health. 