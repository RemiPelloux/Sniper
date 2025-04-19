# Sniper Sandbox Environments

## Overview

The Sniper Sandbox provides pre-configured, vulnerable environments (like web applications) running in Docker containers. This allows users to safely and legally test Sniper's scanning capabilities, experiment with different tools and options, and practice vulnerability identification without targeting real-world systems.

The sandbox is managed via the `sniper sandbox` command, implemented as a core plugin.

## Prerequisites

To use the Sandbox plugin, you must have:

1.  **Docker:** The Docker engine must be installed and running.
2.  **Docker Compose (v2):** The Docker Compose CLI plugin (usually included with Docker Desktop) is required. Sniper specifically uses the `docker compose` command syntax (not the legacy `docker-compose` hyphenated command).

If these prerequisites are not met, the `sniper sandbox` command will likely fail or report an error during initialization.

## Available Environments

Currently, the following sandbox environments are pre-configured:

*   `dvwa`: Damn Vulnerable Web Application. A PHP/MySQL web application that is damn vulnerable.
*   `juiceshop`: OWASP Juice Shop. A modern web application containing a wide range of security vulnerabilities.

More environments may be added in the future.

## Usage

The sandbox is controlled using `sniper sandbox` subcommands:

*   `sniper sandbox list`
    *   Lists all available pre-configured sandbox environments.
*   `sniper sandbox start <environment_name>`
    *   Starts the specified environment (e.g., `sniper sandbox start dvwa`).
    *   This command uses `docker compose up -d` to download necessary images (if not present) and start the containers in the background.
    *   On success, it will typically print the URL or access instructions for the running application.
*   `sniper sandbox stop <environment_name>`
    *   Stops and removes the containers for the specified environment (e.g., `sniper sandbox stop juiceshop`).
    *   This uses `docker compose down`.
*   `sniper sandbox status [environment_name]`
    *   Checks the status of the specified environment or all environments if none is specified.
    *   Reports whether the environment is `Running`, `Stopped`, `Partially Running`, `Unknown`, or in an `Error` state.
    *   For `Running` environments, it also shows the access information.

## Example Workflow

1.  **List available sandboxes:**
    ```bash
    sniper sandbox list
    ```

2.  **Start the DVWA environment:**
    ```bash
    sniper sandbox start dvwa
    ```
    *(Wait for Docker images to download and containers to start)*

3.  **Check the status:**
    ```bash
    sniper sandbox status dvwa
    ```
    *(Output should show 'Running' and provide the access URL like http://localhost:80)*

4.  **Run a Sniper scan against the sandbox:**
    ```bash
    sniper scan http://localhost:80 -m web -m directories
    ```

5.  **When finished, stop the environment:**
    ```bash
    sniper sandbox stop dvwa
    ```

## Important Considerations

*   **Resource Usage:** Running Docker containers consumes system resources (CPU, RAM, Disk Space). Ensure your system meets the requirements for the sandbox environments you intend to run.
*   **Network Ports:** Sandbox environments expose network ports (e.g., 80, 3000) on your `localhost`. Ensure these ports are not already in use by other applications.
*   **Security:** While sandboxed, these applications *are* vulnerable. Do not expose the sandbox containers directly to untrusted networks.
*   **Data Persistence:** Most sandbox configurations provided are not designed for data persistence. Stopping an environment (using `docker compose down`) will typically remove associated containers and potentially any data within them (like database entries in DVWA). Restarting will provide a fresh instance.

## Extending the Sandbox

Currently, adding new environments requires modifying the `SANDBOX_ENVIRONMENTS` dictionary and adding the corresponding `docker-compose.<name>.yml` file within the `app/plugins/sandbox/` directory. Future enhancements might allow for user-defined sandbox configurations. 