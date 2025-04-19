# Sniper Installation Guide

This guide provides detailed instructions on how to install and set up the Sniper Security Tool on various platforms.

## System Requirements

Before installing Sniper, ensure your system meets the following requirements:

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+), macOS 12.0+, or Windows 10/11 with WSL2
- **Python**: Python 3.11 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for larger scans)
- **Storage**: At least 2GB free disk space (more for scan data storage)
- **Network**: Internet access for tool downloads and updates
- **Privileges**: Admin/sudo privileges for tool installation

## Installation Methods

### Method 1: Using pip (Recommended)

The simplest way to install Sniper is using pip:

```bash
# Install latest stable version
pip install sniper-security

# Install specific version
pip install sniper-security==1.2.3

# Install with optional ML dependencies
pip install sniper-security[ml]

# Install with all optional dependencies
pip install sniper-security[all]
```

### Method 2: Using Poetry

For development and more controlled environments:

```bash
# Clone the repository
git clone https://github.com/sniper-security/sniper.git
cd sniper

# Install using Poetry
poetry install

# Install with optional dependencies
poetry install --extras "ml distributed api"
```

### Method 3: Using Docker

For containerized deployment:

```bash
# Pull the official Docker image
docker pull sniper-security/sniper:latest

# Or build from Dockerfile
git clone https://github.com/sniper-security/sniper.git
cd sniper
docker build -t sniper .

# Run Sniper using Docker
docker run -it --rm sniper-security/sniper --help
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3.11 python3.11-dev python3-pip git curl build-essential libffi-dev libssl-dev

# Install Sniper
pip3 install sniper-security

# Verify installation
sniper --version
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python@3.11 git openssl

# Install Sniper
pip3 install sniper-security

# Verify installation
sniper --version
```

### Windows with WSL2

```bash
# In PowerShell (as Administrator), install WSL2
wsl --install

# Launch Ubuntu WSL2 and run:
sudo apt update
sudo apt install -y python3.11 python3.11-dev python3-pip git curl build-essential libffi-dev libssl-dev

# Install Sniper
pip3 install sniper-security

# Verify installation
sniper --version
```

## Post-Installation Setup

After installing Sniper, you need to set up external tools and configurations:

### 1. Configure Sniper

```bash
# Initialize configuration
sniper config init

# Configure API keys (if needed)
sniper config set api_keys.shodan YOUR_SHODAN_API_KEY
```

### 2. Install External Tools

Sniper relies on several external security tools. Use the built-in tool manager to install them:

```bash
# Check which tools are missing
sniper tools check

# Install required tools automatically
sniper tools install
```

### 3. Set Up Python Environment (Optional)

It's recommended to use a virtual environment:

```bash
# Create a virtual environment
python -m venv sniper-env

# Activate the virtual environment
# On Linux/macOS:
source sniper-env/bin/activate

# On Windows:
sniper-env\Scripts\activate

# Install Sniper in the virtual environment
pip install sniper-security
```

## Installing Machine Learning Components

For the ML features to work properly:

```bash
# Install ML dependencies
pip install sniper-security[ml]

# Download pre-trained models
sniper ml download-models

# Test ML setup
sniper ml status
```

## Installing for Distributed Scanning

To set up distributed scanning capabilities:

```bash
# Install with distributed components
pip install sniper-security[distributed]

# Configure master node (on the master server)
sniper config set distributed.master.host 0.0.0.0
sniper config set distributed.master.port 8080

# Configure worker node (on worker machines)
sniper config set distributed.worker.master_host <MASTER_IP>
sniper config set distributed.worker.master_port 8080
```

## Docker Compose Setup

For a complete environment with all dependencies, use Docker Compose:

```bash
# Clone the repository
git clone https://github.com/sniper-security/sniper.git
cd sniper

# Start the Docker Compose environment
docker compose up -d

# Use Sniper through Docker
docker compose exec sniper scan -t example.com
```

## Verifying Installation

Verify that Sniper is installed correctly:

```bash
# Check version
sniper --version

# Check if all dependencies are properly installed
sniper check

# Run a basic test scan
sniper scan -t example.com --type quick
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**:
   ```bash
   # Install Python development packages
   sudo apt install -y python3.11-dev  # For Debian/Ubuntu
   ```

2. **Permission Errors**:
   ```bash
   # Install for current user only
   pip install --user sniper-security
   ```

3. **Tool Installation Failures**:
   ```bash
   # Install tools manually
   sudo apt install -y nmap
   ```

4. **SSL Certificate Errors**:
   ```bash
   # Update certificates
   pip install --upgrade certifi
   ```

### Getting Help

If you encounter issues not covered here:

- Check the [Common Issues](common_issues.md) guide
- Visit the official GitHub repository
- Join the community Slack/Discord channel

## Next Steps

After successfully installing Sniper, you may want to:

- Read the [CLI Usage Guide](cli_usage.md) to learn how to use Sniper
- Review the [Configuration Guide](configuration.md) to customize your setup
- See [Running Scans](running_scans.md) to start your first security scan 