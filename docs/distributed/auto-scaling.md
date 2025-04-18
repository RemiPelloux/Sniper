# Auto-Scaling in Sniper Distributed Architecture

The Sniper Security Tool provides an advanced auto-scaling system that automatically adjusts the number of worker nodes based on workload demands, queue depth, and resource utilization. This document describes how to configure, use, and troubleshoot the auto-scaling capabilities.

## Overview

Auto-scaling enables the Sniper distributed architecture to:

1. Dynamically add worker nodes when workload increases
2. Remove underutilized worker nodes when demand decreases
3. Optimize resource usage across different deployment environments
4. Maintain consistent scan performance regardless of workload fluctuations
5. Respond to worker node failures by provisioning replacements

## How It Works

The auto-scaling system consists of the following components:

- **Auto-Scaler**: Monitors metrics and makes scaling decisions
- **Scaling Rules**: Define conditions that trigger scaling actions
- **Worker Providers**: Create and remove worker nodes in various environments

The auto-scaler runs as part of the master node and periodically checks system metrics against configured scaling rules. When a rule's threshold is met, the auto-scaler uses the configured provider to provision or remove worker nodes.

```
┌───────────────┐          ┌───────────┐          ┌──────────────┐
│   Metrics     │──────────▶ Autoscaler │──────────▶  Scaling     │
│  Collection   │          │            │          │  Decision    │
└───────────────┘          └───────────┘          └──────────────┘
                                │                          │
                                │                          │
                                ▼                          ▼
                          ┌───────────┐            ┌──────────────┐
                          │  Worker   │            │   Provider   │
                          │  Registry │◀───────────│ (Docker, K8s,│
                          └───────────┘            │   etc.)      │
                                                   └──────────────┘
```

## Scaling Policies

The auto-scaler supports several scaling policies:

- **Queue Depth**: Scales based on the number of pending tasks per worker
- **CPU Utilization**: Scales based on worker CPU usage
- **Task Type**: Scales based on the types of pending tasks and required capabilities
- **Hybrid**: Combines multiple metrics for more sophisticated scaling decisions

## Worker Providers

Worker nodes can be provisioned through several providers:

- **Local**: Starts worker processes on the same machine
- **Docker**: Creates worker containers using Docker
- **Kubernetes**: Deploys worker pods in a Kubernetes cluster
- **AWS**: Launches EC2 instances on Amazon Web Services
- **Azure**: Creates VMs in Microsoft Azure
- **GCP**: Provisions VMs in Google Cloud Platform

## Configuration

### Basic Configuration

To enable auto-scaling, use the `--auto-scaling` flag when starting the master node:

```bash
python -m src.cli.distributed master --auto-scaling
```

### Advanced Configuration

For more control, specify scaling limits and policies:

```bash
python -m src.cli.distributed master \
  --auto-scaling \
  --min-nodes 2 \
  --max-nodes 10 \
  --scaling-policy queue_depth \
  --scaling-provider docker \
  --provider-config config/providers/docker.json
```

### Provider Configurations

#### Docker Provider

Create a JSON configuration file for the Docker provider:

```json
{
  "image": "sniper-worker:latest",
  "network": "sniper-network",
  "env_vars": {
    "LOG_LEVEL": "INFO"
  },
  "volumes": [
    "/var/run/docker.sock:/var/run/docker.sock",
    "~/.sniper:/root/.sniper"
  ]
}
```

#### Kubernetes Provider

Create a JSON configuration file for the Kubernetes provider:

```json
{
  "image": "ghcr.io/sniper/worker:latest",
  "namespace": "sniper-system",
  "resources": {
    "requests": {
      "memory": "512Mi",
      "cpu": "0.5"
    },
    "limits": {
      "memory": "1Gi",
      "cpu": "1"
    }
  }
}
```

## Customizing Scaling Rules

Advanced users can customize scaling rules by creating a configuration file:

```json
{
  "rules": [
    {
      "metric": "queue_depth_per_worker",
      "threshold": 5.0,
      "operation": ">",
      "action": "add",
      "cooldown": 300,
      "adjustment": 1
    },
    {
      "metric": "worker_utilization",
      "threshold": 0.2,
      "operation": "<",
      "action": "remove",
      "cooldown": 600,
      "adjustment": 1
    }
  ]
}
```

## Metrics and Monitoring

The auto-scaler tracks several metrics to make scaling decisions:

- **Active Workers**: Number of connected, active worker nodes
- **Queue Depth**: Number of pending tasks
- **Queue Depth Per Worker**: Average number of pending tasks per worker
- **Worker Utilization**: Average load across all workers
- **Active Tasks**: Number of currently running tasks

You can view these metrics using the status command:

```bash
python -m src.cli.distributed status --host localhost --port 5000
```

## Best Practices

For optimal auto-scaling performance:

1. **Set Appropriate Limits**: Configure min_nodes and max_nodes based on your workload and resources
2. **Use Cooldown Periods**: Avoid scaling thrashing by setting appropriate cooldown periods
3. **Monitor Scaling Events**: Review logs to understand scaling behavior
4. **Choose the Right Provider**: Select the provider that matches your deployment environment
5. **Consider Cost Implications**: For cloud providers, balance performance with cost considerations

## Troubleshooting

### Common Issues

#### Workers Failing to Register

If new worker nodes aren't registering with the master:

1. Check network connectivity between master and worker nodes
2. Verify the master host/port configuration
3. Review logs for authentication or protocol errors

#### Excessive Scaling

If the system is scaling too frequently:

1. Increase the cooldown periods in scaling rules
2. Adjust thresholds to be less sensitive
3. Consider using a hybrid scaling policy

#### Provider-Specific Issues

##### Docker

- Ensure Docker daemon is running
- Verify the worker image exists
- Check network configuration

##### Kubernetes

- Verify RBAC permissions
- Check pod scheduling and resource constraints
- Validate namespace existence

## Advanced Usage

### Custom Metrics

Advanced users can implement custom metrics by extending the `AutoScaler` class:

```python
from src.distributed.auto_scaling import AutoScaler

class CustomAutoScaler(AutoScaler):
    def _collect_metrics(self):
        metrics = super()._collect_metrics()
        
        # Add custom metrics
        metrics["my_custom_metric"] = self._calculate_custom_metric()
        
        return metrics
    
    def _calculate_custom_metric(self):
        # Custom metric calculation
        return 0.5
```

### Integration with External Monitoring

The auto-scaling system can be integrated with external monitoring systems:

```python
# Configure prometheus metrics export
from prometheus_client import start_http_server, Gauge

# Create metrics
worker_count = Gauge('sniper_worker_count', 'Number of active workers')
queue_depth = Gauge('sniper_queue_depth', 'Number of pending tasks')

# Start server to expose metrics
start_http_server(8000)

# Update metrics periodically
def update_metrics():
    worker_count.set(len(master.get_active_workers()))
    queue_depth.set(len(master.pending_tasks))
```

## API Reference

For more detailed information about the auto-scaling API, refer to the code documentation:

- `src/distributed/auto_scaling.py`: Main auto-scaling implementation
- `src/distributed/master.py`: Master node integration with auto-scaling
- `src/cli/distributed.py`: Command-line interface for auto-scaling 