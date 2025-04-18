# Sniper Security Tool - Custom Tools

## Overview

Sniper supports adding custom security tools to extend its capabilities. Each tool is defined in its own YAML configuration file, which specifies details such as how to install the tool, check if it's available, and other metadata.

## Tool Configuration Structure

Tool configurations are stored in two locations:
- `config/tools/` - Contains the standard built-in tools
- `config/custom_tools/` - For adding your own custom tools

Each tool must be in its own YAML file, named appropriately (e.g., `mytool.yaml`).

## Adding a Custom Tool

To add a new tool to Sniper:

1. Create a new YAML file in the `config/custom_tools/` directory
2. Define the tool using the format shown below
3. Restart Sniper (or reload the tool configuration)

## Tool Configuration Format

Each tool YAML file should contain a single tool definition. Here's an example of a tool configuration:

```yaml
mytool:
  name: mytool
  category: reconnaissance  # One of: reconnaissance, vulnerability_scanning, exploitation, post_exploitation, miscellaneous
  description: "Description of what the tool does"
  binary: mytool  # The binary name that will be executed
  check_cmd: "mytool --version"  # Command to check if the tool is installed
  api_key:
    required: false  # Set to true if the tool requires an API key
    env_var: "MYTOOL_API_KEY"  # Environment variable name for the API key (if required)
    url: "https://example.com/api-key"  # URL where the user can obtain an API key
    description: "API key for mytool services"  # Description of the API key
  execution_time: 300  # Estimated execution time in seconds
  target_types: ["ip", "domain", "webapp"]  # Types of targets this tool works with
  recommendation_score: 85  # 0-100, higher = more recommended
```

## Important Notes

- Each tool must be in its own file in the `config/custom_tools/` directory
- The filename should be lowercase and match the tool name (e.g., `nmap.yaml` for Nmap)
- Tool names must be unique across all tools
- The system will automatically load all tools from both the built-in and custom directories

## Tool Categories

Sniper organizes tools into the following categories:

- `reconnaissance`: Tools for gathering information about targets
- `vulnerability_scanning`: Tools for identifying security vulnerabilities
- `exploitation`: Tools for exploiting vulnerabilities
- `sast`: Static Application Security Testing tools
- `sca`: Software Composition Analysis tools
- `fuzzing`: Tools for fuzz testing
- `active_directory`: Tools for Active Directory testing
- `wireless`: Tools for wireless network testing
- `threat_intelligence`: Tools for threat intelligence gathering
- `endpoint_security`: Tools for endpoint security testing
- `incident_response`: Tools for incident response
- `reverse_engineering`: Tools for reverse engineering
- `malware_analysis`: Tools for malware analysis
- `network_security`: Tools for network security testing
- `mobile_security`: Tools for mobile application security testing
- `forensics`: Tools for digital forensics
- `cms_scanning`: Tools for Content Management System scanning

## Example Custom Tools

The following are examples of custom tools:

### JWT Tool

```yaml
jwt_tool:
  name: JWT Tool
  category: exploitation
  description: "A toolkit for testing, tweaking and cracking JSON Web Tokens"
  binary: jwt_tool.py
  check_cmd: "python3 jwt_tool.py -h"
  api_key:
    required: false
  execution_time: 60
  target_types: ["webapp", "api", "jwt"]
  recommendation_score: 88
```

### Feroxbuster

```yaml
feroxbuster:
  name: Feroxbuster
  category: fuzzing
  description: "A fast, simple, recursive content discovery tool"
  binary: feroxbuster
  check_cmd: "feroxbuster --version"
  api_key:
    required: false
  execution_time: 900
  target_types: ["webapp"]
  recommendation_score: 89
```

## Using Tools Programmatically

To use tools programmatically in your code:

```python
from tools.manager import ToolManager

# Initialize the tool manager
manager = ToolManager()

# Get all tools in the reconnaissance category
recon_tools = manager.get_tools_by_category("reconnaissance")

# Get a specific tool
nmap = manager.get_tool("nmap")
if nmap and manager.is_tool_available("nmap"):
    print(f"Nmap is available: {nmap['description']}")
    
# Get tools by target type
webapp_tools = manager.get_tools_by_target_type("webapp")

# Get top recommended tools
top_tools = manager.get_top_recommended_tools(limit=5) 