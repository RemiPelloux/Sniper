# How to Use the Distributed Scanning Feature

This document explains the setup and usage of Sniper's distributed scanning capabilities.

## Overview

Distributed scanning allows Sniper to distribute scanning tasks across multiple worker nodes, enabling faster and more scalable assessments, especially for large environments.

## Architecture

-   **Master Node**: Coordinates the scan, distributes tasks, and aggregates results. Typically, this is where you initiate the `sniper` command.
-   **Worker Nodes**: Execute specific scanning tasks assigned by the master. Workers can be run on separate machines, containers (Docker), or orchestrators (Kubernetes).
-   **Communication**: A communication protocol (likely based on a message queue like Redis or RabbitMQ, or a custom RPC mechanism) is used for task distribution and result collection between the master and workers.

## Enabling Distributed Scanning

Distributed scanning needs to be explicitly enabled and configured.

1.  **Configuration**: Modify `config/default.yml` (or environment-specific config) to enable distributed mode and configure communication details (e.g., message queue address, credentials).

    ```yaml
    distributed:
      enabled: true
      mode: docker # or kubernetes or remote_worker
      master_host: <master_ip_or_hostname>
      communication:
        type: redis # Example
        host: <redis_host>
        port: 6379
        # ... other relevant settings (password, db, etc.)
    ```

2.  **Worker Setup**: Deploy and start worker nodes according to the chosen mode:
    -   **`remote_worker`**: Manually start the worker process (`sniper worker start`) on designated machines, ensuring they can connect to the master/communication channel.
    -   **`docker`**: Ensure Docker is running. The master node might automatically launch worker containers if configured.
    -   **`kubernetes`**: Deploy worker pods using provided Kubernetes manifests, ensuring they are configured to connect to the communication channel.

## Running a Distributed Scan

Once configured and workers are running/available, initiate a scan as usual from the master node. Sniper will automatically detect the distributed configuration and distribute tasks.

```bash
# Run from the machine configured as the master
sniper scan <target> [options...]
```

The master node will handle task allocation, monitor worker progress, and collect results.

## Monitoring

Sniper likely includes commands or dashboard features (if the web UI is deployed) to monitor the status of worker nodes and ongoing distributed scans.

```bash
# Example commands (conceptual)
sniper distributed status
sniper workers list
```

## Considerations

-   **Network Connectivity**: Ensure proper network connectivity between the master and worker nodes, and between workers and the target systems.
-   **Resource Allocation**: Configure workers with adequate resources (CPU, memory, network bandwidth).
-   **Security**: Secure the communication channel between master and workers (e.g., use TLS, authentication).
-   **Fault Tolerance**: The system is designed with fault tolerance, but monitor worker health.

Refer to `src/distributed/` and specific provider implementations (Docker, K8s) for more detailed setup instructions and configuration options. 