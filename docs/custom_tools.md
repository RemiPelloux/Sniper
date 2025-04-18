# Sniper Security Tool - Custom Tools

## Overview

Sniper supports adding custom security tools to extend its capabilities. Each tool is defined in a YAML configuration file, which specifies details such as how to install the tool, check if it's available, and other metadata.

## Tool Configuration Structure

Tool configurations are stored in two locations:
- `config/tools/` - Contains the standard built-in tools
- `config/custom_tools/` - For adding your own custom tools

Each tool should be in its own YAML file, named appropriately (e.g., `mytool.yaml`).

## Adding a Custom Tool

To add a new tool to Sniper:

1. Create a new YAML file in the `config/custom_tools/` directory
2. Define the tool using the format shown below
3. Restart Sniper (or reload the tool configuration)

## Tool Configuration Format

Here's an example of a tool configuration:

```yaml
mytool:
  name: mytool
  category: reconnaissance  # One of: reconnaissance, vulnerability_scanning, exploitation, post_exploitation, miscellaneous
  description: "Description of what the tool does"
  binary: mytool  # The binary name that will be executed
  check_command: "mytool --version"  # Command to check if the tool is installed
  install:
    apt: "apt-get install -y mytool"
    brew: "brew install mytool"
    pip: "pip install mytool"
    # Other installation methods as needed
  update:
    apt: "apt-get update && apt-get install -y --only-upgrade mytool"
    brew: "brew upgrade mytool"
    pip: "pip install --upgrade mytool"
  website: "https://example.com/mytool"
  documentation: "https://example.com/mytool/docs"
  execution_time: "fast"  # One of: fast, medium, slow
  target_types: ["ip", "domain", "webapp"]  # Types of targets this tool works with
  recommendation_score: 85  # 0-100, higher = more recommended
```

## Supported Installation Methods

The following installation methods are supported:

- `apt`: For Debian/Ubuntu-based systems
- `brew`: For macOS systems with Homebrew
- `pip`: For Python packages
- `npm`: For Node.js packages
- `git`: For cloning and building from a Git repository
- `binary`: For downloading and installing a binary directly

For Git installations, use this format:

```yaml
install:
  git:
    repository: "https://github.com/user/repo"
    commands:
      - "pip install -r requirements.txt"
      - "make install"
```

## Tool Categories

Sniper organizes tools into the following categories:

- `reconnaissance`: Tools for gathering information about targets
- `vulnerability_scanning`: Tools for identifying security vulnerabilities
- `exploitation`: Tools for exploiting vulnerabilities
- `post_exploitation`: Tools for post-exploitation activities
- `miscellaneous`: Other security tools that don't fit the above categories

## Example Custom Tools

The following are examples of custom tools you can add:

### Dirb

```yaml
dirb:
  name: dirb
  category: reconnaissance
  description: "A Web Content Scanner for finding existing and/or hidden web directories and files"
  binary: dirb
  check_command: "dirb -h"
  install:
    apt: "apt-get install -y dirb"
    brew: "brew install dirb"
  update:
    apt: "apt-get update && apt-get install -y --only-upgrade dirb"
    brew: "brew upgrade dirb"
  website: "https://sourceforge.net/projects/dirb/"
  documentation: "https://tools.kali.org/web-applications/dirb"
  execution_time: "medium"
  target_types: ["url", "webapp"]
  recommendation_score: 85
```

### JWT Tool

```yaml
jwt_tool:
  name: jwt_tool
  category: exploitation
  description: "A toolkit for testing, tweaking and cracking JSON Web Tokens"
  binary: jwt_tool.py
  check_command: "python3 -c 'import jwt_tool' 2>/dev/null || python3 -c 'import sys; sys.exit(1)'"
  install:
    pip: "pip install jwt-tool"
    git: 
      repository: "https://github.com/ticarpi/jwt_tool"
      commands:
        - "pip install -r requirements.txt"
  update:
    pip: "pip install --upgrade jwt-tool"
  website: "https://github.com/ticarpi/jwt_tool"
  documentation: "https://github.com/ticarpi/jwt_tool/wiki"
  execution_time: "fast"
  target_types: ["webapp", "api"]
  recommendation_score: 88
```

## Using Tools Programmatically

To use tools programmatically in your code:

```python
from tools.manager import ToolManager, ToolCategory

# Initialize the tool manager
manager = ToolManager()

# Get all tools in the reconnaissance category
recon_tools = manager.get_tools_by_category(ToolCategory.RECONNAISSANCE)

# Get a specific tool
dirb = manager.get_tool("dirb")
if dirb and manager.check_tool_availability("dirb"):
    print(f"Dirb is available: {dirb['description']}")
    
# Install a tool
if not manager.check_tool_availability("feroxbuster"):
    manager.install_tool("feroxbuster")
``` 