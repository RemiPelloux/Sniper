# Distributed Scanning with Sniper

This guide provides detailed instructions on how to set up and use Sniper's distributed scanning architecture for large-scale security testing.

## Overview

Sniper's distributed architecture consists of three main components:

1. **Master Node**: Coordinates scanning tasks and collects results
2. **Worker Nodes**: Execute security scanning tasks
3. **Client Interface**: Submits tasks and retrieves results

This architecture allows you to:
- Scale scanning capabilities across multiple machines
- Distribute workload for faster scanning
- Centralize result collection and analysis
- Manage resources efficiently

## Prerequisites

Before setting up distributed scanning, ensure you have:

- Sniper installed on all nodes (`pip install sniper-security[distributed]`)
- Network connectivity between all nodes
- Sufficient system resources on each node
- Firewall rules allowing communication on the required ports

## Architecture Setup

### 1. Setting Up the Master Node

The master node coordinates all scanning activities:

```bash
# Initialize configuration
sniper config init

# Configure master node settings
sniper config set distributed.master.host 0.0.0.0
sniper config set distributed.master.port 8080
sniper config set distributed.master.workers_timeout 300
sniper config set distributed.master.data_dir /path/to/data/storage

# Start the master node
sniper distributed start-master
```

Advanced configuration options:

```bash
# Enable authentication
sniper config set distributed.master.auth_enabled true
sniper config set distributed.master.auth_key "your-secret-key"

# Configure SSL
sniper config set distributed.master.ssl_enabled true
sniper config set distributed.master.ssl_cert /path/to/cert.pem
sniper config set distributed.master.ssl_key /path/to/key.pem

# Set worker resource limits
sniper config set distributed.master.max_workers 20
sniper config set distributed.master.max_tasks_per_worker 5

# Start master with specific options
sniper distributed start-master --host 192.168.1.10 --port 8443 --ssl
```

### 2. Setting Up Worker Nodes

Worker nodes perform the actual scanning tasks:

```bash
# Initialize configuration
sniper config init

# Configure worker node settings
sniper config set distributed.worker.master_host <MASTER_IP>
sniper config set distributed.worker.master_port 8080
sniper config set distributed.worker.name worker-1
sniper config set distributed.worker.capabilities "nmap,zap,sqlmap"

# Start the worker node
sniper distributed start-worker
```

Advanced worker configuration:

```bash
# Configure worker authentication
sniper config set distributed.worker.auth_enabled true
sniper config set distributed.worker.auth_key "your-secret-key"

# Configure worker resources
sniper config set distributed.worker.max_tasks 3
sniper config set distributed.worker.max_cpu_percent 80
sniper config set distributed.worker.max_memory_percent 70

# Set up SSL for worker
sniper config set distributed.worker.ssl_enabled true
sniper config set distributed.worker.ssl_verify true

# Start worker with specific options
sniper distributed start-worker --master-host 192.168.1.10 --master-port 8443 --ssl
```

### 3. Using Docker for Deployment

For containerized deployment:

```bash
# Run master node in Docker
docker run -d --name sniper-master -p 8080:8080 \
  -v sniper_data:/app/data \
  sniper-security/sniper distributed start-master

# Run worker node in Docker
docker run -d --name sniper-worker \
  -e SNIPER_DISTRIBUTED_WORKER_MASTER_HOST=<MASTER_IP> \
  -e SNIPER_DISTRIBUTED_WORKER_MASTER_PORT=8080 \
  sniper-security/sniper distributed start-worker
```

Using Docker Compose:

```yaml
# docker-compose.yml
version: '3'

services:
  master:
    image: sniper-security/sniper
    command: distributed start-master
    ports:
      - "8080:8080"
    volumes:
      - sniper_data:/app/data
    environment:
      - SNIPER_DISTRIBUTED_MASTER_HOST=0.0.0.0
      - SNIPER_DISTRIBUTED_MASTER_PORT=8080

  worker1:
    image: sniper-security/sniper
    command: distributed start-worker
    depends_on:
      - master
    environment:
      - SNIPER_DISTRIBUTED_WORKER_MASTER_HOST=master
      - SNIPER_DISTRIBUTED_WORKER_MASTER_PORT=8080
      - SNIPER_DISTRIBUTED_WORKER_NAME=worker-1

  worker2:
    image: sniper-security/sniper
    command: distributed start-worker
    depends_on:
      - master
    environment:
      - SNIPER_DISTRIBUTED_WORKER_MASTER_HOST=master
      - SNIPER_DISTRIBUTED_WORKER_MASTER_PORT=8080
      - SNIPER_DISTRIBUTED_WORKER_NAME=worker-2

volumes:
  sniper_data:
```

## Using the Distributed System

### Submitting Tasks

You can submit scanning tasks from any machine with the Sniper client installed:

```bash
# Configure client
sniper config set distributed.client.master_host <MASTER_IP>
sniper config set distributed.client.master_port 8080

# Submit a basic scan task
sniper distributed submit-task -t example.com --type full

# Submit with advanced options
sniper distributed submit-task -t example.com --type webapp \
  --priority high --timeout 3600 --tools nmap,zap,sqlmap
```

### Task Types

The distributed system supports various task types:

```bash
# Web application scan
sniper distributed submit-task -t example.com --type webapp

# Network scan
sniper distributed submit-task -t 192.168.1.0/24 --type network

# Vulnerability scan
sniper distributed submit-task -t example.com --type vuln

# Autonomous testing
sniper distributed submit-task -t example.com --type autonomous \
  --vulnerability-type xss

# ML training job
sniper distributed submit-ml-job --job-type train --data-file findings.json
```

### Managing Tasks

Monitor and manage tasks in the distributed system:

```bash
# List all tasks
sniper distributed list-tasks

# Get task status
sniper distributed task-status --task-id abc123

# Cancel a task
sniper distributed cancel-task --task-id abc123

# Get task results
sniper distributed get-results --task-id abc123 --output-file results.json
```

### Worker Management

Monitor and manage worker nodes:

```bash
# List all workers
sniper distributed list-workers

# Get worker details
sniper distributed worker-info --worker-id worker-1

# Remove a worker
sniper distributed remove-worker --worker-id worker-1

# Pause/suspend a worker
sniper distributed pause-worker --worker-id worker-1

# Resume a worker
sniper distributed resume-worker --worker-id worker-1
```

## Advanced Features

### Auto-Scaling

Sniper supports auto-scaling of worker nodes based on workload:

```bash
# Enable auto-scaling on master
sniper config set distributed.master.auto_scaling.enabled true
sniper config set distributed.master.auto_scaling.min_workers 2
sniper config set distributed.master.auto_scaling.max_workers 10
sniper config set distributed.master.auto_scaling.scale_up_threshold 80
sniper config set distributed.master.auto_scaling.scale_down_threshold 20

# Configure cloud provider for auto-scaling (if applicable)
sniper config set distributed.master.auto_scaling.provider "kubernetes"
sniper config set distributed.master.auto_scaling.provider_config_file "/path/to/config.yaml"
```

### Task Prioritization

Control task execution order:

```bash
# Submit a high-priority task
sniper distributed submit-task -t example.com --priority high

# Submit a low-priority task
sniper distributed submit-task -t example.com --priority low
```

### Resource-Aware Task Allocation

The master node intelligently assigns tasks based on worker capabilities:

```bash
# Worker with specific capabilities
sniper config set distributed.worker.capabilities "nmap,zap,sqlmap"
sniper config set distributed.worker.resource_profile "high-memory"

# Submit task with resource requirements
sniper distributed submit-task -t example.com --resource-profile "high-memory"
```

### Fault Tolerance

Sniper's distributed system includes fault tolerance features:

```bash
# Configure task retry settings
sniper config set distributed.master.task_retry.enabled true
sniper config set distributed.master.task_retry.max_attempts 3
sniper config set distributed.master.task_retry.delay 60

# Configure worker heartbeat monitoring
sniper config set distributed.master.heartbeat.interval 30
sniper config set distributed.master.heartbeat.timeout 90
```

## Kubernetes Deployment

For enterprise deployments, Sniper can be deployed on Kubernetes:

```yaml
# Example Kubernetes deployment for the master node
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sniper-master
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sniper-master
  template:
    metadata:
      labels:
        app: sniper-master
    spec:
      containers:
      - name: sniper-master
        image: sniper-security/sniper
        command: ["sniper", "distributed", "start-master"]
        ports:
        - containerPort: 8080
        env:
        - name: SNIPER_DISTRIBUTED_MASTER_HOST
          value: "0.0.0.0"
        - name: SNIPER_DISTRIBUTED_MASTER_PORT
          value: "8080"
        volumeMounts:
        - name: sniper-data
          mountPath: /app/data
      volumes:
      - name: sniper-data
        persistentVolumeClaim:
          claimName: sniper-data-pvc
---
# Service for master node
apiVersion: v1
kind: Service
metadata:
  name: sniper-master
spec:
  selector:
    app: sniper-master
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
```

Worker node deployment:

```yaml
# Worker deployment with auto-scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sniper-workers
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sniper-worker
  template:
    metadata:
      labels:
        app: sniper-worker
    spec:
      containers:
      - name: sniper-worker
        image: sniper-security/sniper
        command: ["sniper", "distributed", "start-worker"]
        env:
        - name: SNIPER_DISTRIBUTED_WORKER_MASTER_HOST
          value: "sniper-master"
        - name: SNIPER_DISTRIBUTED_WORKER_MASTER_PORT
          value: "8080"
        - name: SNIPER_DISTRIBUTED_WORKER_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
---
# Horizontal Pod Autoscaler for workers
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sniper-workers-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sniper-workers
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Performance Tuning

Optimize your distributed scanning environment:

```bash
# Master node performance settings
sniper config set distributed.master.task_queue_size 1000
sniper config set distributed.master.result_batch_size 50
sniper config set distributed.master.thread_pool_size 20

# Worker node performance settings
sniper config set distributed.worker.max_concurrent_tasks 5
sniper config set distributed.worker.result_batch_size 20
sniper config set distributed.worker.scan_thread_pool_size 8
```

## Monitoring

Monitor the distributed scanning system:

```bash
# Get system status
sniper distributed status

# Get detailed statistics
sniper distributed stats

# Get worker performance metrics
sniper distributed worker-stats

# Enable metrics endpoint (for Prometheus, etc.)
sniper config set distributed.master.metrics.enabled true
sniper config set distributed.master.metrics.port 9090
```

## Troubleshooting

Common issues and their solutions:

1. **Worker Cannot Connect to Master**:
   ```bash
   # Check firewall settings
   sudo ufw allow 8080
   
   # Verify master is running
   sniper distributed master-status
   
   # Check logs
   sniper logs --component distributed
   ```

2. **Task Execution Failures**:
   ```bash
   # Check task logs
   sniper distributed task-logs --task-id abc123
   
   # Verify worker capabilities
   sniper distributed worker-info --worker-id worker-1
   ```

3. **Performance Issues**:
   ```bash
   # Check resource usage
   sniper distributed system-info
   
   # Adjust worker concurrency
   sniper config set distributed.worker.max_concurrent_tasks 3
   ```

## Best Practices

- Deploy the master node on a reliable, always-on server
- Use auto-scaling for workload spikes
- Configure authentication and SSL for production environments
- Monitor system performance regularly
- Back up the master node's data directory
- Use resource profiles to optimize task allocation
- Set appropriate timeout values for long-running tasks

## Next Steps

After setting up your distributed scanning environment, you may want to explore:

- [API Usage](api_usage.md) to access the distributed system programmatically
- [Kubernetes Deployment](kubernetes_deployment.md) for enterprise-scale deployments
- [ML Capabilities](ml_capabilities.md) to enhance scanning with machine learning 