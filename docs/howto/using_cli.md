# How to Use the Sniper CLI

This document provides instructions on using the Sniper Command Line Interface (CLI).

## Basic Usage

The Sniper CLI is the primary way to interact with the tool for initiating scans, managing configurations, and viewing results.

```bash
sniper [OPTIONS] COMMAND [ARGS]...
```

## Common Commands

### Initiating a Scan

To start a basic scan against a target:

```bash
sniper scan <target>
```

Replace `<target>` with the IP address, hostname, or URL you want to scan.

### Listing Available Tools

To see the list of integrated security tools:

```bash
sniper tools list
```

### Viewing Scan Results

To view the results of a previous scan:

```bash
sniper results view <scan_id>
```

Replace `<scan_id>` with the ID of the scan you want to view.

### Configuration

To manage Sniper's configuration:

```bash
sniper config show  # Show current configuration
sniper config set <key> <value>  # Set a configuration value
```

## Advanced Usage

For more advanced options and specific command details, use the `--help` flag:

```bash
sniper --help
sniper scan --help
```

Refer to the main `README.md` and specific module documentation for more details. 