# How to Use the Sniper API

This document provides guidance on interacting with the Sniper REST API.

## Overview

The Sniper API allows programmatic interaction with the tool, enabling integration with other systems, automation of scans, and remote management.

## Starting the API Server

The API server needs to be run as a separate process.

```bash
sniper api start --host <host_ip> --port <port_number>
```

-   `--host`: The IP address to bind the server to (e.g., `0.0.0.0` for all interfaces).
-   `--port`: The port number for the API server (e.g., `8000`).

Ensure the API process has access to the necessary configuration and data.

## Authentication

The API likely requires authentication. Common methods include:
-   **API Keys**: Pass an API key in the request headers (e.g., `Authorization: Bearer <your_api_key>` or `X-API-Key: <your_api_key>`).
-   **User Credentials**: Basic Auth or JWT tokens if integrated with user accounts.

Refer to the API configuration (`config/default.yml`) or startup logs for details on the configured authentication method.

## Common Endpoints

Below are examples of potential API endpoints (specific paths and methods may vary):

### Scans

-   **Start a new scan**: `POST /api/v1/scans`
    -   Body: `{ "target": "<target>", "profile": "<scan_profile>", ... }`
-   **List scans**: `GET /api/v1/scans`
-   **Get scan status**: `GET /api/v1/scans/<scan_id>`
-   **Stop a scan**: `POST /api/v1/scans/<scan_id>/stop`

### Results

-   **Get results for a scan**: `GET /api/v1/scans/<scan_id>/results`
-   **List findings**: `GET /api/v1/findings?scan_id=<scan_id>&severity=high`
-   **Get finding details**: `GET /api/v1/findings/<finding_id>`

### Configuration

-   **Get configuration**: `GET /api/v1/config`
-   **Update configuration**: `PUT /api/v1/config`
    -   Body: `{ "key": "value", ... }`

### Tools

-   **List available tools**: `GET /api/v1/tools`

### Distributed System (if applicable)

-   **List worker nodes**: `GET /api/v1/workers`
-   **Get worker status**: `GET /api/v1/workers/<worker_id>`

## API Documentation (Swagger/OpenAPI)

If available, the API server often hosts interactive documentation (e.g., Swagger UI) at an endpoint like `/docs` or `/openapi.json`.

Access `http://<host_ip>:<port_number>/docs` in your browser to explore available endpoints, parameters, and response schemas.

## Example Usage (using `curl`)

```bash
# Start a scan (replace with actual endpoint and auth)
curl -X POST http://localhost:8000/api/v1/scans \
     -H "Authorization: Bearer your_api_key" \
     -H "Content-Type: application/json" \
     -d '{"target": "example.com"}'

# Get scan status
curl http://localhost:8000/api/v1/scans/<scan_id> \
     -H "Authorization: Bearer your_api_key"
```

Refer to the `src/api/` directory and any generated OpenAPI documentation for precise endpoint definitions and usage instructions. 