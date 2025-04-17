# Distributed Scanning Deployment Guide

## Overview

This guide provides detailed instructions and best practices for deploying the Sniper distributed scanning infrastructure in various environments. Whether you're setting up a small-scale deployment or an enterprise-grade distributed scanning platform, this document will help you configure your infrastructure for optimal performance, reliability, and security.

## Deployment Topologies

The Sniper distributed scanning architecture supports several deployment topologies to accommodate different organizational needs:

### Single Master Deployment

![Single Master Topology](../assets/images/single-master-topology.png)

- **Configuration**: One master node with multiple worker nodes
- **Best for**: Small to medium deployments (1-20 worker nodes)
- **Advantages**: Simple setup, centralized management
- **Limitations**: Single point of failure, limited horizontal scaling

### Clustered Master Deployment

![Clustered Master Topology](../assets/images/clustered-master-topology.png)

- **Configuration**: Multiple master nodes with load balancing and shared state
- **Best for**: Medium to large deployments (20-100+ worker nodes)
- **Advantages**: High availability, improved performance
- **Limitations**: More complex setup, requires state synchronization

### Hierarchical Deployment

![Hierarchical Topology](../assets/images/hierarchical-topology.png)

- **Configuration**: Master nodes delegating to sub-masters that manage worker groups
- **Best for**: Large distributed deployments spanning multiple networks/locations
- **Advantages**: Improved scalability, network efficiency, geographical distribution
- **Limitations**: Complex management, requires careful configuration

### Mesh Deployment

![Mesh Topology](../assets/images/mesh-topology.png)

- **Configuration**: Hybrid nodes that can act as both masters and workers
- **Best for**: Advanced deployments requiring dynamic adaptation
- **Advantages**: Maximum flexibility, dynamic role assignment, resilience
- **Limitations**: Complex coordination, requires advanced monitoring

## System Requirements

### Master Node Requirements

| Component | Minimum | Recommended | Enterprise |
|-----------|---------|-------------|------------|
| CPU | 4 cores | 8+ cores | 16+ cores |
| RAM | 8 GB | 16 GB | 32+ GB |
| Disk | 100 GB SSD | 500 GB SSD | 1+ TB SSD |
| Network | 1 Gbps | 10 Gbps | 25+ Gbps |
| OS | Linux (Ubuntu 20.04+) | Linux (Ubuntu 22.04+) | Linux (Ubuntu 22.04+) |

### Worker Node Requirements

| Component | Minimum | Recommended | Enterprise |
|-----------|---------|-------------|------------|
| CPU | 2 cores | 4+ cores | 8+ cores |
| RAM | 4 GB | 8 GB | 16+ GB |
| Disk | 50 GB SSD | 100 GB SSD | 200+ GB SSD |
| Network | 100 Mbps | 1 Gbps | 10+ Gbps |
| OS | Linux (Ubuntu 20.04+) | Linux (Ubuntu 22.04+) | Linux (Ubuntu 22.04+) |

### Network Requirements

- All nodes must be able to communicate with each other
- Firewalls must allow the following ports:
  - Master API: TCP 8443 (HTTPS)
  - WebSocket: TCP 8444
  - Message Queue (if used): TCP 5671 (AMQP/TLS)
  - Monitoring: TCP 9100 (Node Exporter), TCP 9090 (Prometheus)
- Latency requirements:
  - Master to worker: <100ms recommended
  - Between master nodes: <50ms recommended

## Installation Options

### Docker Deployment

The recommended deployment method for most environments:

```bash
# Pull the Sniper images
docker pull snipertool/master:latest
docker pull snipertool/worker:latest

# Start a master node
docker run -d --name sniper-master \
  -p 8443:8443 -p 8444:8444 \
  -v /path/to/config:/etc/sniper \
  -v /path/to/data:/var/lib/sniper \
  snipertool/master:latest

# Start a worker node
docker run -d --name sniper-worker \
  -v /path/to/config:/etc/sniper \
  -v /path/to/data:/var/lib/sniper \
  -e MASTER_URL=https://master-hostname:8443 \
  snipertool/worker:latest
```

### Kubernetes Deployment

For cloud-native and enterprise environments:

```yaml
# Example Kubernetes deployment (sniper-deployment.yaml)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sniper-master
spec:
  replicas: 3
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
        image: snipertool/master:latest
        ports:
        - containerPort: 8443
        - containerPort: 8444
        volumeMounts:
        - name: config-volume
          mountPath: /etc/sniper
        - name: data-volume
          mountPath: /var/lib/sniper
      volumes:
      - name: config-volume
        configMap:
          name: sniper-config
      - name: data-volume
        persistentVolumeClaim:
          claimName: sniper-master-data
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sniper-worker
spec:
  replicas: 10
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
        image: snipertool/worker:latest
        env:
        - name: MASTER_URL
          value: "https://sniper-master-service:8443"
        volumeMounts:
        - name: config-volume
          mountPath: /etc/sniper
        - name: data-volume
          mountPath: /var/lib/sniper
      volumes:
      - name: config-volume
        configMap:
          name: sniper-worker-config
      - name: data-volume
        persistentVolumeClaim:
          claimName: sniper-worker-data
```

### Bare Metal Installation

For environments where containers cannot be used:

```bash
# Install prerequisites
apt-get update
apt-get install -y python3 python3-pip python3-venv

# Create a dedicated user
useradd -m -s /bin/bash sniper

# Set up environment
su - sniper
python3 -m venv sniper-env
source sniper-env/bin/activate

# Install Sniper
pip install sniper-security-tool[distributed]

# Configure master node
sniper-cli setup-master --config /etc/sniper/master.yaml

# Configure worker node
sniper-cli setup-worker --master-url https://master-hostname:8443 --config /etc/sniper/worker.yaml

# Set up systemd services
cat > /etc/systemd/system/sniper-master.service << EOF
[Unit]
Description=Sniper Security Tool Master Node
After=network.target

[Service]
User=sniper
WorkingDirectory=/home/sniper
ExecStart=/home/sniper/sniper-env/bin/sniper-master --config /etc/sniper/master.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable sniper-master
systemctl start sniper-master
```

## Configuration

### Master Node Configuration

Basic configuration example (`master.yaml`):

```yaml
node:
  id: "master-node-1"
  role: "master"
  hostname: "master.example.com"

api:
  port: 8443
  tls:
    cert_file: "/etc/sniper/certs/server.crt"
    key_file: "/etc/sniper/certs/server.key"
    ca_file: "/etc/sniper/certs/ca.crt"

distribution:
  algorithm: "smart"  # Options: round_robin, priority, capability, weighted, load_balanced, smart
  parameters:
    max_tasks_per_worker: 5
    prioritize_less_loaded: true
    capability_weight: 0.7
    performance_weight: 0.3

protocols:
  - type: "rest"
    enabled: true
    port: 8443
  - type: "websocket"
    enabled: true
    port: 8444
  - type: "message_queue"
    enabled: false
    connection_string: "amqp://user:password@mq.example.com:5671/%2F"

storage:
  type: "filesystem"  # Options: filesystem, s3, database
  path: "/var/lib/sniper/data"
  
security:
  authentication:
    type: "token"  # Options: token, certificate, oauth
    token_file: "/etc/sniper/tokens.yaml"
  authorization:
    enabled: true
    policy_file: "/etc/sniper/rbac.yaml"

logging:
  level: "info"  # Options: debug, info, warning, error
  file: "/var/log/sniper/master.log"
  
monitoring:
  prometheus:
    enabled: true
    port: 9090
```

### Worker Node Configuration

Basic configuration example (`worker.yaml`):

```yaml
node:
  id: "worker-node-1"
  role: "worker"
  capabilities:
    - "nmap"
    - "sqlmap"
    - "dirbuster"
    - "wpscan"
    - "nuclei"
  hostname: "worker1.example.com"

master:
  url: "https://master.example.com:8443"
  heartbeat_interval: 30  # seconds
  reconnect_attempts: 5
  reconnect_delay: 10  # seconds

execution:
  max_concurrent_tasks: 5
  task_timeout: 3600  # seconds
  result_reporting:
    batch_size: 10
    batch_interval: 30  # seconds

resources:
  cpu:
    limit_percent: 80
  memory:
    limit_mb: 4096
  disk:
    min_free_gb: 5

security:
  authentication:
    type: "token"
    token: "${WORKER_TOKEN}"  # Environment variable or from file
  tls:
    verify: true
    ca_file: "/etc/sniper/certs/ca.crt"
    cert_file: "/etc/sniper/certs/worker.crt"
    key_file: "/etc/sniper/certs/worker.key"

logging:
  level: "info"
  file: "/var/log/sniper/worker.log"
  
tools:
  installation_dir: "/opt/sniper/tools"
  auto_update: true
  update_interval: 86400  # seconds (24 hours)
```

## Security Setup

### TLS Certificate Generation

Generate TLS certificates for secure communication:

```bash
# Create a Certificate Authority
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -subj "/CN=Sniper CA" -out ca.crt -days 3650

# Create Master certificate
openssl genrsa -out master.key 2048
openssl req -new -key master.key -out master.csr -subj "/CN=master.example.com"
openssl x509 -req -in master.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out master.crt -days 365 -sha256

# Create Worker certificate
openssl genrsa -out worker.key 2048
openssl req -new -key worker.key -out worker.csr -subj "/CN=worker.example.com"
openssl x509 -req -in worker.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out worker.crt -days 365 -sha256
```

### Authentication Token Generation

Generate authentication tokens for worker nodes:

```bash
# Generate a random token
WORKER_TOKEN=$(openssl rand -hex 32)
echo "Worker token: $WORKER_TOKEN"

# Add to tokens.yaml
cat >> tokens.yaml << EOF
- id: "worker-node-1"
  token: "$WORKER_TOKEN"
  role: "worker"
EOF
```

## Monitoring Setup

### Prometheus and Grafana

Deploy monitoring with Prometheus and Grafana:

```bash
# Docker-based setup
docker run -d --name prometheus \
  -p 9090:9090 \
  -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus

docker run -d --name grafana \
  -p 3000:3000 \
  -v /path/to/grafana-data:/var/lib/grafana \
  grafana/grafana
```

Example Prometheus configuration:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'sniper-master'
    static_configs:
      - targets: ['master.example.com:9090']
  
  - job_name: 'sniper-workers'
    static_configs:
      - targets: ['worker1.example.com:9100', 'worker2.example.com:9100']
```

## High Availability Setup

### Master Node Clustering

Set up clustered master nodes for high availability:

```yaml
# master-cluster.yaml
node:
  id: "master-node-1"
  role: "master"
  cluster:
    enabled: true
    nodes:
      - id: "master-node-1"
        hostname: "master1.example.com"
        port: 8443
      - id: "master-node-2"
        hostname: "master2.example.com"
        port: 8443
      - id: "master-node-3"
        hostname: "master3.example.com"
        port: 8443
    consensus_protocol: "raft"
    state_sync_interval: 5  # seconds

storage:
  type: "distributed"
  backend: "redis"  # Options: redis, etcd
  connection_string: "redis://redis.example.com:6379/0"
```

### Load Balancing

Set up load balancing for master nodes:

```nginx
# Nginx configuration for load balancing
upstream sniper_masters {
    server master1.example.com:8443;
    server master2.example.com:8443;
    server master3.example.com:8443;
}

server {
    listen 443 ssl;
    server_name api.sniper.example.com;

    ssl_certificate /etc/nginx/certs/sniper.crt;
    ssl_certificate_key /etc/nginx/certs/sniper.key;

    location / {
        proxy_pass https://sniper_masters;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Performance Tuning

### OS-Level Optimizations

Apply these OS-level optimizations to worker nodes:

```bash
# Increase file descriptors
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
cat >> /etc/sysctl.conf << EOF
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535
EOF
sysctl -p

# Set CPU governor to performance
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo "performance" > $cpu
done
```

### Worker Node Optimization

Optimize worker nodes for scanning performance:

```yaml
# worker-perf.yaml
execution:
  max_concurrent_tasks: 10  # Adjust based on CPU cores
  task_prioritization: true
  preload_tools: ["nmap", "nuclei"]  # Most used tools
  
resources:
  memory:
    tool_cache_size_mb: 1024  # Cache for tool results
  disk:
    io_priority: "high"
    
performance:
  connection_pooling: true
  result_compression: true
  network:
    max_bandwidth_mbps: 500  # Limit if needed
```

## Scaling Strategies

### Horizontal Scaling

Guidelines for adding more worker nodes:

1. Deploy new worker nodes following the installation instructions
2. Use unique node IDs for each worker
3. Register workers with the master cluster
4. Monitor the cluster to ensure proper load distribution

### Vertical Scaling

Guidelines for increasing individual node capacity:

1. Upgrade CPU, memory, and storage resources
2. Adjust configuration to utilize additional resources
3. Increase `max_concurrent_tasks` proportionally to CPU cores
4. Optimize memory allocation for increased concurrency

## Backup and Recovery

### Master Node Data Backup

Regular backup of master node data:

```bash
# Backup script (backup.sh)
#!/bin/bash
BACKUP_DIR="/path/to/backups"
DATE=$(date +%Y%m%d%H%M)
BACKUP_FILE="$BACKUP_DIR/sniper-master-$DATE.tar.gz"

# Stop service if needed
systemctl stop sniper-master

# Backup data and configuration
tar -czf $BACKUP_FILE /var/lib/sniper/data /etc/sniper

# Restart service
systemctl start sniper-master

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "sniper-master-*.tar.gz" -mtime +7 -delete
```

### Recovery Procedure

Steps to recover a failed master node:

1. Install a new master node following the installation instructions
2. Restore the latest backup:
   ```bash
   tar -xzf sniper-master-backup.tar.gz -C /
   ```
3. Update configuration if needed (e.g., hostname, IP address)
4. Start the master node service:
   ```bash
   systemctl start sniper-master
   ```
5. Verify that worker nodes can connect to the recovered master

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solution |
|-------|----------------|----------|
| Worker cannot connect to master | Network/firewall issues, TLS certificates | Check network connectivity, verify certificates |
| Tasks stuck in "pending" state | Worker capacity issues, task distribution problems | Check worker status, adjust distribution algorithm |
| High latency in task execution | Network congestion, overloaded workers | Optimize network, adjust worker load limits |
| Master node crashes | Memory leaks, resource exhaustion | Increase resources, check logs for errors |
| Worker node crashes | Tool failures, resource exhaustion | Check tool configurations, increase resource limits |

### Log Analysis

Important log patterns to look for:

```
# Connection failures
ERROR Connection to master failed: Connection refused
ERROR TLS handshake failed: certificate verification error

# Task execution issues
ERROR Task execution failed: tool exited with code 1
WARN Task timeout after 600 seconds

# Resource issues
WARN Memory usage above 90%: 7.2GB/8GB
ERROR Disk space critically low: 0.5GB remaining
```

### Diagnostic Commands

Useful commands for diagnosing issues:

```bash
# Check master node status
sniper-cli status master

# View worker connections
sniper-cli list-workers --status

# Check task queue
sniper-cli list-tasks --status pending

# View recent task results
sniper-cli list-results --count 10

# View system resource usage
sniper-cli system-stats

# Test connectivity between nodes
sniper-cli test-connection --target worker-node-1
```

## Maintenance Procedures

### Updating Nodes

Process for updating master and worker nodes:

```bash
# Update master nodes (rolling update for clusters)
for master in master1 master2 master3; do
  # Put master in maintenance mode
  ssh $master "sniper-cli maintenance enable"
  
  # Wait for task handoff
  sleep 60
  
  # Update software
  ssh $master "docker pull snipertool/master:latest"
  ssh $master "docker stop sniper-master"
  ssh $master "docker rm sniper-master"
  ssh $master "docker run -d --name sniper-master -p 8443:8443 -p 8444:8444 -v /path/to/config:/etc/sniper -v /path/to/data:/var/lib/sniper snipertool/master:latest"
  
  # Verify master is running
  ssh $master "docker logs sniper-master | tail"
  
  # Disable maintenance mode
  ssh $master "sniper-cli maintenance disable"
  
  # Wait for stabilization
  sleep 120
done

# Update worker nodes (can be done in parallel)
for worker in worker1 worker2 worker3; do
  ssh $worker "docker pull snipertool/worker:latest"
  ssh $worker "docker stop sniper-worker"
  ssh $worker "docker rm sniper-worker"
  ssh $worker "docker run -d --name sniper-worker -v /path/to/config:/etc/sniper -v /path/to/data:/var/lib/sniper -e MASTER_URL=https://master.example.com:8443 snipertool/worker:latest"
done
```

### Database Maintenance

Maintenance for distributed storage backend:

```bash
# Redis maintenance example
# Backup Redis data
redis-cli SAVE

# Check Redis memory usage
redis-cli INFO memory

# Optimize Redis configuration
cat > /etc/redis/redis.conf << EOF
maxmemory 4gb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
EOF
systemctl restart redis
```

## Integration with External Systems

### Webhook Notifications

Configure webhooks for scan events:

```yaml
# master-webhooks.yaml
notifications:
  webhooks:
    - name: "slack-alerts"
      url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      events:
        - "scan.completed"
        - "scan.high_severity_finding"
        - "node.disconnected"
      format: "json"
    - name: "jira-tickets"
      url: "https://jira.example.com/api/webhook"
      events:
        - "scan.critical_severity_finding"
      format: "json"
      authentication:
        type: "basic"
        username: "${JIRA_USER}"
        password: "${JIRA_TOKEN}"
```

### API Integration

Example API request to integrate with external systems:

```bash
# Submit a scan via API
curl -X POST \
  https://master.example.com:8443/api/v1/scans \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Weekly Security Scan",
    "targets": ["example.com", "10.0.0.0/24"],
    "scan_profile": "comprehensive",
    "priority": "high",
    "notification": {
      "email": "security@example.com",
      "webhook": "https://example.com/callback"
    }
  }'
```

## Conclusion

This deployment guide provides the foundation for setting up a robust, scalable, and secure distributed scanning infrastructure using the Sniper Security Tool. By following these best practices, you can ensure optimal performance, reliability, and maintainability of your security scanning platform.

For additional support, refer to the following resources:

- [Sniper Documentation](https://docs.sniper.io)
- [Community Forums](https://community.sniper.io)
- [GitHub Repository](https://github.com/snipertool/sniper)
- [Issue Tracker](https://github.com/snipertool/sniper/issues) 