# Sniper Security Tool - User Guide

Welcome to Sniper, the comprehensive security assessment tool.

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Installation](#2-installation)
3.  [Core Concepts](#3-core-concepts)
4.  [CLI Usage](#4-cli-usage)
    *   [Scanning](#scanning)
    *   [Reporting](#reporting)
    *   [Tools Management](#tools-management)
    *   [Machine Learning](#machine-learning)
    *   [Custom Tools](#custom-tools)
    *   [Distributed Scanning](#distributed-scanning)
    *   [Sandbox Plugin](#sandbox-plugin)
    *   [Other Plugins](#other-plugins)
5.  [Configuration](#5-configuration)
6.  [Using the Sandbox Plugin](#6-using-the-sandbox-plugin)
7.  [Using Distributed Scanning](#7-using-distributed-scanning)
8.  [Troubleshooting](#8-troubleshooting)
9.  [Contributing](#9-contributing)

## 1. Introduction

Sniper is designed to automate and enhance security testing processes. It integrates various security tools, utilizes machine learning for analysis, and provides a flexible plugin architecture for extensibility.

*(More details about philosophy and goals can be added here)*

## 2. Installation

We recommend using [Poetry](https://python-poetry.org/) for managing dependencies and the virtual environment.

```bash
# Clone the repository
git clone <repository-url> sniper
cd sniper

# Install dependencies using Poetry
poetry install

# Activate the virtual environment (optional, commands can be run via 'poetry run')
poetry shell
```

## 3. Core Concepts

Understanding these core concepts is key to using Sniper effectively:

*   **Targets:** The systems, applications, or networks being assessed.
*   **Scans:** The process of running security tools against targets to identify potential vulnerabilities or gather information.
*   **Findings:** Individual pieces of information discovered during a scan (e.g., a vulnerability, an open port, misconfiguration).
*   **Reports:** Aggregated and processed findings, often presented in a structured format (JSON, HTML, etc.).
*   **Tools:** Specific security utilities integrated into Sniper (e.g., Nmap, OWASP ZAP, custom scripts).
*   **Machine Learning (ML):** Sniper utilizes ML models for tasks like predicting vulnerability severity or prioritizing findings.
*   **Plugins:** Extend Sniper's functionality. They can add new commands, integrate tools, or modify behavior (e.g., Sandbox Plugin).
*   **Sandbox:** An isolated environment (often using Docker) for running potentially unsafe tools or analyzing artifacts.
*   **Distributed Scanning:** A system for distributing scanning tasks across multiple worker nodes for increased performance and scalability.

## 4. CLI Usage

Sniper is primarily controlled via its command-line interface (CLI). Use `poetry run sniper --help` to see all available commands and options.

### Scanning

Initiate scans against specified targets.

```bash
# Example: Run a default scan profile against a target
poetry run sniper scan <target_host_or_ip> --profile default

# Example: Run specific tools
poetry run sniper scan <target_host_or_ip> --tools nmap zap

# Example: Save findings to a specific file
poetry run sniper scan <target_host_or_ip> -o results.json
```

*(More details on scan profiles, target formats, specific tool options)*

### Reporting

Generate reports from scan findings.

```bash
# Example: Generate an HTML report from findings
poetry run sniper report findings.json --format html -o report.html
```

*(More details on report formats, filtering, customization)*

### Tools Management

Manage integrated security tools.

```bash
# List available tools
poetry run sniper tools list

# Get info about a specific tool
poetry run sniper tools info nmap
```

*(More details on adding/configuring tools if applicable)*

### Machine Learning

Interact with Sniper's ML capabilities.

```bash
# Example: Train an ML model (if applicable)
poetry run sniper ml train --data <training_data>

# Example: Predict using a model
poetry run sniper ml predict --model <model_name> --input <input_data>
```

*(More details on available ML models, training data formats, prediction outputs)*

### Custom Tools

Manage and run custom tools defined by the user.

```bash
# List custom tools
poetry run sniper custom-tools list

# Run a specific custom tool
poetry run sniper custom-tools run <tool_name> --target <target>
```

*(More details on defining and configuring custom tools)*

### Distributed Scanning

Manage and interact with distributed scanning components.

```bash
# Start a master node
poetry run sniper distributed master start --host 0.0.0.0 --port 5000

# Start a worker node
poetry run sniper distributed worker start --master-host <master_ip> --master-port 5000

# Check worker status
poetry run sniper distributed worker status --worker-id <worker_id>

# Submit a task
poetry run sniper distributed task submit --profile default --target <target>

# Get task status
poetry run sniper distributed task status --task-id <task_id>

# List all workers
poetry run sniper distributed list-workers

# List all tasks
poetry run sniper distributed list-tasks
```

*(See Section 7 for more details on distributed scanning)*

### Sandbox Plugin

Commands provided by the Sandbox plugin (if enabled).

```bash
# List sandbox environments
poetry run sniper sandbox list

# Start the default sandbox
poetry run sniper sandbox start

# Stop the sandbox
poetry run sniper sandbox stop

# Check sandbox status
poetry run sniper sandbox status
```

*(See Section 6 for more details)*

### Other Plugins

Plugins add their own subcommands. Use `--help` to explore them.

```bash
# Example: Help for a hypothetical 'MyScanner' plugin
poetry run sniper myscanner --help

poetry run sniper myscanner run --help
```

## 5. Configuration

Sniper's behavior can be customized through configuration files.

*   **Main Configuration:** `config/config.yaml` (or location specified by `SNIPER_CONFIG_PATH`). Controls core settings, logging, tool paths, ML model paths, etc.
*   **Plugin Configuration:** Plugins might have their own configuration files or sections within the main config.
*   **Environment Variables:** Certain settings can be overridden via environment variables (e.g., `LOG_LEVEL`).

*(More details on specific configuration options, format, priorities)*

## 6. Using the Sandbox Plugin

The Sandbox plugin provides an isolated Docker environment.

**Prerequisites:**
*   Docker and Docker Compose (or `docker compose`) must be installed and running.

**Usage:**
*   Use `poetry run sniper sandbox start` to launch the environment defined in `app/plugins/sandbox/docker-compose.yml`.
*   Use `poetry run sniper sandbox stop` to shut it down.
*   Use `poetry run sniper sandbox status` to check if it's running.

*(More details on customizing the sandbox, interacting with it, use cases)*

## 7. Using Distributed Scanning

Distributed scanning allows you to distribute security assessment tasks across multiple machines or containers for improved performance and scalability.

### Architecture

The distributed scanning architecture consists of:

* **Master Node:** Coordinates task distribution, tracks worker status, and aggregates results
* **Worker Nodes:** Execute scanning tasks and report results back to the master
* **Task Queue:** Manages pending tasks and their assignments
* **Result Aggregator:** Combines and deduplicates findings from multiple workers

### Setup and Configuration

#### Master Node Setup

```bash
# Start a master node on the default host and port
poetry run sniper distributed master start

# Start with custom settings
poetry run sniper distributed master start --host 0.0.0.0 --port 5000 --protocol http
```

Configuration options:
* `--host`: IP address to bind to (default: 0.0.0.0)
* `--port`: Port to listen on (default: 5000)
* `--protocol`: Communication protocol (http or https, default: http)
* `--config`: Path to configuration file

The master node API will be available at `http://<host>:<port>/api/v1/`.

#### Worker Node Setup

```bash
# Start a worker node connecting to a master
poetry run sniper distributed worker start --master-host 192.168.1.100 --master-port 5000

# Start with specific capabilities
poetry run sniper distributed worker start --master-host 192.168.1.100 --capabilities web_scan,recon
```

Configuration options:
* `--master-host`: Master node IP or hostname
* `--master-port`: Master node port
* `--worker-id`: Unique worker ID (auto-generated if not specified)
* `--protocol`: Communication protocol (http or https, default: http)
* `--capabilities`: Comma-separated list of supported scan types
* `--max-tasks`: Maximum concurrent tasks (default: 2)
* `--config`: Path to configuration file

#### Using Docker Compose

For easier deployment, you can use Docker Compose:

```bash
# Start the entire distributed scanning system
docker compose -f docker-compose.distributed.yml up -d

# Scale workers as needed
docker compose -f docker-compose.distributed.yml up -d --scale worker=5
```

### Task Management

#### Submitting Tasks

```bash
# Submit a basic scan task
poetry run sniper distributed task submit --target example.com --profile default

# Submit with specific tools and options
poetry run sniper distributed task submit --target example.com --tools nmap,zap --options '{"depth": 2}'
```

Task submission options:
* `--target`: Target URL, IP, or hostname
* `--profile`: Scan profile to use (default, quick, thorough)
* `--tools`: Specific tools to run
* `--options`: JSON string of additional options
* `--priority`: Task priority (1-10, higher is more urgent)

#### Monitoring Tasks

```bash
# List all tasks
poetry run sniper distributed list-tasks

# Filter tasks by status
poetry run sniper distributed list-tasks --status pending,running

# Check specific task status
poetry run sniper distributed task status --task-id <task_id>

# Get task results
poetry run sniper distributed task results --task-id <task_id> --output results.json
```

### Worker Management

```bash
# List all registered workers
poetry run sniper distributed list-workers

# Filter workers by status
poetry run sniper distributed list-workers --status active

# Get worker details
poetry run sniper distributed worker status --worker-id <worker_id>

# Stop a worker
poetry run sniper distributed worker stop --worker-id <worker_id>
```

### Smart Task Distribution

The system intelligently distributes tasks based on:
* Worker capabilities and current load
* Task priority and waiting time
* Target type and scanning requirements

This ensures optimal resource utilization and faster completion of high-priority tasks.

### Results Aggregation

When a distributed scan completes, results from all workers are aggregated:
* Findings are deduplicated based on similarity
* Severity levels are normalized
* A comprehensive report is generated

Access the aggregated results:
```bash
poetry run sniper distributed task results --task-id <task_id> --output aggregated_results.json
```

## 8. Troubleshooting

*   **Check Logs:** Increase log verbosity (`--log-level DEBUG` or set `LOG_LEVEL=DEBUG`) for detailed information. Logs are typically found in a `logs/` directory.
*   **Dependencies:** Ensure all dependencies are correctly installed (`poetry install`).
*   **Permissions:** Verify Sniper has the necessary permissions to run tools, write files, or access network resources.
*   **Plugin Issues:** Check plugin-specific logs or documentation. Ensure plugin prerequisites (like Docker for the sandbox) are met.
*   **Distributed Scanning Issues:**
    * Verify network connectivity between master and worker nodes
    * Check that ports are open and accessible
    * Ensure worker capabilities match the requirements of submitted tasks
    * Examine logs for communication errors or task failures

*(List common errors and solutions)*

## 9. Contributing

Contributions are welcome! Please refer to the `CONTRIBUTING.md` guide for details on how to contribute code, report issues, or suggest features.

---
*This guide is a work in progress and will be updated as Sniper evolves.* 