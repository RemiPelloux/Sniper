# Docker Deployment Guide for Sniper

This guide provides detailed instructions on how to deploy and run the Sniper Security Tool using Docker.

## Prerequisites

Before proceeding, ensure you have the following installed on your system:

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (version 2.0.0 or higher)
- At least 4GB of available RAM
- At least 10GB of free disk space

## Docker Image Overview

Sniper provides official Docker images with all dependencies pre-installed:

- `sniper-security/sniper:latest` - Latest stable release
- `sniper-security/sniper:1.x.x` - Specific version releases
- `sniper-security/sniper:dev` - Development branch

## Quick Start

Get up and running quickly with a simple Docker command:

```bash
# Pull the latest Sniper image
docker pull sniper-security/sniper:latest

# Run a basic scan
docker run --rm -v $(pwd)/reports:/app/reports sniper-security/sniper scan -t example.com

# Get help
docker run --rm sniper-security/sniper --help
```

## Using Docker Compose

For a more complete setup, use Docker Compose to manage multiple containers:

### 1. Create a Docker Compose File

Create a `docker-compose.yml` file with the following content:

```yaml
version: '3'

services:
  sniper:
    image: sniper-security/sniper:latest
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./reports:/app/reports
      - ./models:/app/models
    environment:
      - SNIPER_LOG_LEVEL=INFO
    command: scan -t example.com

  zap:
    image: owasp/zap2docker-stable
    command: zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
    ports:
      - "8080:8080"
    volumes:
      - zap_data:/home/zap/.ZAP

volumes:
  zap_data:
```

### 2. Start the Environment

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Run a specific scan
docker compose run --rm sniper scan -t example.com -m normal
```

## Persistent Storage

Configure these volumes to persist data between container runs:

```yaml
volumes:
  # Store scan reports
  - ./reports:/app/reports
  
  # Store configuration files
  - ./config:/app/config
  
  # Store machine learning models
  - ./models:/app/models
  
  # Store scan data and findings
  - ./data:/app/data
```

## Configuration

### Environment Variables

Configure Sniper through environment variables:

```yaml
environment:
  # Logging level (DEBUG, INFO, WARNING, ERROR)
  - SNIPER_LOG_LEVEL=INFO
  
  # Path to configuration directory
  - SNIPER_CONFIG_PATH=/app/config
  
  # Optional API keys
  - SNIPER_SHODAN_API_KEY=your_api_key
  
  # Proxy settings if needed
  - HTTP_PROXY=http://proxy.example.com:8080
  - HTTPS_PROXY=http://proxy.example.com:8080
```

### Custom Configuration Files

Create a custom configuration directory with your settings:

```bash
# Create config directory
mkdir -p config

# Generate a default config file
docker run --rm -v $(pwd)/config:/app/config sniper-security/sniper config init

# Edit the configuration file
nano config/sniper.yaml
```

## Tool Integration

### OWASP ZAP Integration

Sniper integrates with OWASP ZAP for web application scanning:

```yaml
services:
  sniper:
    # ... sniper configuration ...
    depends_on:
      - zap
    environment:
      - SNIPER_ZAP_API_URL=http://zap:8080

  zap:
    image: owasp/zap2docker-stable
    command: zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
    volumes:
      - zap_data:/home/zap/.ZAP
```

### Additional Tools

Add other security tools as needed:

```yaml
services:
  # ... other services ...
  
  nikto:
    image: secfigo/nikto
    volumes:
      - ./nikto_data:/opt/nikto/var

  sqlmap:
    image: paoloo/sqlmap
    volumes:
      - ./sqlmap_data:/root/.sqlmap
```

## CPU and Memory Constraints

Set resource limits to prevent containers from consuming too many resources:

```yaml
services:
  sniper:
    # ... other configuration ...
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G
```

## Production Deployment

For production environments, follow these additional steps:

### 1. Secure Secrets

Use Docker secrets or environment files for sensitive data:

```bash
# Create an environment file
cat > .env << EOF
SNIPER_SHODAN_API_KEY=your_api_key
SNIPER_AUTH_KEY=your_auth_key
EOF

# Use the environment file
docker compose --env-file .env up -d
```

### 2. Network Security

Create isolated networks for enhanced security:

```yaml
services:
  sniper:
    # ... other configuration ...
    networks:
      - frontend
      - backend

  zap:
    # ... other configuration ...
    networks:
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # This network is not accessible from outside
```

### 3. Health Checks

Add health checks to ensure services are running properly:

```yaml
services:
  sniper:
    # ... other configuration ...
    healthcheck:
      test: ["CMD", "sniper", "status"]
      interval: 1m
      timeout: 10s
      retries: 3
```

## Distributed Scanning with Docker

For distributed scanning deployments:

### Master Node Setup

```yaml
services:
  master:
    image: sniper-security/sniper:latest
    command: distributed start-master
    ports:
      - "8080:8080"
    volumes:
      - master_data:/app/data
    environment:
      - SNIPER_DISTRIBUTED_MASTER_HOST=0.0.0.0
      - SNIPER_DISTRIBUTED_MASTER_PORT=8080
```

### Worker Nodes Setup

```yaml
services:
  worker1:
    image: sniper-security/sniper:latest
    command: distributed start-worker
    depends_on:
      - master
    environment:
      - SNIPER_DISTRIBUTED_WORKER_MASTER_HOST=master
      - SNIPER_DISTRIBUTED_WORKER_MASTER_PORT=8080
      - SNIPER_DISTRIBUTED_WORKER_NAME=worker-1
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G

  worker2:
    image: sniper-security/sniper:latest
    command: distributed start-worker
    depends_on:
      - master
    environment:
      - SNIPER_DISTRIBUTED_WORKER_MASTER_HOST=master
      - SNIPER_DISTRIBUTED_WORKER_MASTER_PORT=8080
      - SNIPER_DISTRIBUTED_WORKER_NAME=worker-2
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

## Docker Image Customization

If you need to customize the Sniper Docker image:

### 1. Create a Custom Dockerfile

```Dockerfile
FROM sniper-security/sniper:latest

# Install additional dependencies
RUN apt-get update && apt-get install -y \
    bind9-dnsutils \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Add custom scripts
COPY custom_scripts/ /app/custom_scripts/

# Set environment variables
ENV SNIPER_LOG_LEVEL=DEBUG

# Change default user if needed
USER root
```

### 2. Build Custom Image

```bash
# Build custom image
docker build -t custom-sniper .

# Run with custom image
docker run --rm custom-sniper scan -t example.com
```

## Example Docker Compose Configurations

### Basic Web Scanning Setup

```yaml
version: '3'

services:
  sniper:
    image: sniper-security/sniper:latest
    volumes:
      - ./reports:/app/reports
    environment:
      - SNIPER_ZAP_API_URL=http://zap:8080
    command: scan -t example.com --type webapp

  zap:
    image: owasp/zap2docker-stable
    command: zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### Full Security Suite

```yaml
version: '3'

services:
  sniper:
    image: sniper-security/sniper:latest
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./reports:/app/reports
      - ./models:/app/models
    environment:
      - SNIPER_ZAP_API_URL=http://zap:8080
      - SNIPER_NMAP_ENABLED=true
    depends_on:
      - zap
    command: scan -t example.com --type full

  zap:
    image: owasp/zap2docker-stable
    command: zap-x.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
    volumes:
      - zap_data:/home/zap/.ZAP

  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=sniper
      - POSTGRES_PASSWORD=securepw
      - POSTGRES_DB=sniper_findings
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  zap_data:
  db_data:
```

### Web Dashboard Setup

```yaml
version: '3'

services:
  sniper:
    image: sniper-security/sniper:latest
    volumes:
      - ./data:/app/data
      - ./reports:/app/reports
    command: api start

  dashboard:
    image: sniper-security/sniper-dashboard:latest
    ports:
      - "8000:80"
    environment:
      - API_URL=http://sniper:5000
    depends_on:
      - sniper
```

## Running Common Tasks

### Running Scans

```bash
# Basic scan
docker compose run --rm sniper scan -t example.com

# Specific scan type
docker compose run --rm sniper scan -t example.com --type webapp

# With specific output
docker compose run --rm sniper scan -t example.com --output-file /app/reports/report.html --output-format html
```

### Managing Configuration

```bash
# Initialize config
docker compose run --rm sniper config init

# Set configuration values
docker compose run --rm sniper config set scan.default_depth 3

# Show current configuration
docker compose run --rm sniper config show
```

### Managing Reports

```bash
# List reports
docker compose run --rm sniper report list

# View a report
docker compose run --rm sniper report view --id abc123
```

## Troubleshooting

### Common Issues

1. **Container fails to start**:
   ```bash
   # Check logs
   docker compose logs sniper
   
   # Ensure volumes have correct permissions
   chmod -R 777 ./data ./reports ./config
   ```

2. **Network connectivity issues**:
   ```bash
   # Check if containers can communicate
   docker compose exec sniper ping zap
   
   # Verify ZAP API is accessible
   docker compose exec sniper curl -I http://zap:8080
   ```

3. **Resource constraints**:
   ```bash
   # Check Docker resource usage
   docker stats
   
   # Increase Docker resource limits in Docker Desktop settings
   ```

### Checking Container Status

```bash
# Check running containers
docker compose ps

# Check container health
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"

# Get container details
docker inspect sniper-sniper-1
```

## Next Steps

After deploying Sniper with Docker, you may want to:

- Learn how to [use the CLI](cli_usage.md) for detailed scan configuration
- Set up [distributed scanning](distributed_scanning.md) for enterprise deployments
- Explore [ML capabilities](ml_capabilities.md) to enhance your security testing 