# Docker Setup for Sniper

This document explains how to run Sniper using Docker containers for easier deployment and consistent behavior across environments.

## Prerequisites

- Docker installed on your system
- Docker Compose installed on your system

## Container Structure

The Sniper project uses a multi-container setup:

1. **sniper**: The main application container that runs the Sniper CLI
2. **zap**: OWASP ZAP container for web scanning capabilities
3. **api** (Future Sprint 4): API server for programmatic access to Sniper functionality

## Getting Started

### Building and Running Containers

```bash
# Build and start all containers
docker compose up -d

# Run a specific scan using the container
docker compose run --rm sniper scan -t example.com -m all

# View logs from the containers
docker compose logs -f
```

### Container Volumes

The Docker setup includes several volumes for data persistence:

- `./data:/app/data`: Storage for scan data
- `./reports:/app/reports`: Storage for generated reports
- `./models:/app/models`: Storage for machine learning models
- `./config:/app/config`: Configuration files
- `zap_data`: Persistent storage for ZAP session data

## Configuration

You can customize the environment variables in the `docker-compose.yml` file:

- `SNIPER_CONFIG_PATH`: Path to configuration directory
- `SNIPER_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Integration with OWASP ZAP

The Sniper container is configured to communicate with the ZAP container for web scanning. The ZAP API is available at `http://zap:8080` from within the Sniper container.

## Common Commands

```bash
# Rebuild containers after changes
docker compose build

# Stop and remove containers
docker compose down

# Stop and remove containers and volumes
docker compose down -v

# Run a specific command in the Sniper container
docker compose run --rm sniper [command]
```

## Troubleshooting

### ZAP Connection Issues

If Sniper cannot connect to ZAP, check that:

1. The ZAP container is running: `docker compose ps`
2. Network connectivity between containers: `docker compose exec sniper ping zap`
3. ZAP API is accessible: `docker compose exec sniper curl http://zap:8080/`

### Permission Issues

If you encounter permission issues with volumes, ensure that:

1. The host directories exist and have appropriate permissions
2. You're running commands with sufficient privileges (e.g., using `sudo` if necessary)

## Performance Considerations

- The ML model training and prediction may require increased container resources
- For resource-intensive scans, consider adjusting container resource limits in the `docker-compose.yml` file 