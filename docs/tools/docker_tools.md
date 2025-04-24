# Docker Security Tools

Sniper provides Docker-based security tools that can be used in environments where installing the tools directly might be difficult or undesirable. These containers include all necessary dependencies and are configured for immediate use.

## Available Tool Containers

Currently, the following security tools are available as Docker containers:

- **Dirsearch**: Advanced web path scanner for directory enumeration
- **Subfinder**: Fast passive subdomain enumeration tool

## Building the Tool Containers

To build all tool containers, use the provided build script:

```bash
cd docker
./build_tools.sh
```

This will build all the tool containers and tag them with the `sniper/` prefix.

## Using Individual Tool Containers

### Dirsearch

To run Dirsearch on a target website:

```bash
docker run --rm -it sniper/dirsearch:latest -u https://example.com -e php,html,js
```

To save results to a local file:

```bash
docker run --rm -it -v "$(pwd):/output" sniper/dirsearch:latest -u https://example.com -e php,html,js -o /output/dirsearch-results.txt
```

### Subfinder

To run Subfinder on a target domain:

```bash
docker run --rm -it sniper/subfinder:latest -d example.com
```

To save results to a local file:

```bash
docker run --rm -it -v "$(pwd):/output" sniper/subfinder:latest -d example.com -o /output/subfinder-results.txt
```

## Using Docker Compose

The `docker-compose.tools.yml` file allows you to manage all tool containers:

To start a specific tool:

```bash
# From the docker directory
docker compose -f docker-compose.tools.yml up dirsearch
docker compose -f docker-compose.tools.yml up subfinder
```

To run a specific command with a tool:

```bash
docker compose -f docker-compose.tools.yml run dirsearch -u https://example.com -e php,html,js
docker compose -f docker-compose.tools.yml run subfinder -d example.com
```

## Integrating with Sniper

The tool containers can be used by Sniper when the native tools are not available. To enable this integration:

1. Build the tool containers as described above
2. Configure Sniper to look for Docker containers when tools are not found locally
3. Run Sniper as normal - it will automatically use the Docker containers when needed

This ensures Sniper can run all required tools even in environments with limited tool installations.

## Adding More Tool Containers

To add more tool containers:

1. Create a new directory under `docker/` for the tool (e.g., `docker/nmap/`)
2. Create a `Dockerfile` in the new directory with appropriate instructions
3. Add the tool to the `docker-compose.tools.yml` file
4. Update the `build_tools.sh` script to build the new container

Following this pattern ensures consistency and ease of use across all tool containers. 