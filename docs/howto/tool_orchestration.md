# Tool Orchestration Guide

Tool orchestration is a powerful feature that allows you to chain multiple security tools together to create complex security assessment workflows. This guide explains how to use the tool orchestration features to automate security testing processes.

## Introduction

Tool orchestration in Sniper allows you to:

- Define complex workflows with multiple security tools
- Pass data between tools automatically
- Create conditional execution paths based on findings
- Build reusable security testing templates
- Visualize attack paths and exploitation chains

## Getting Started

### Basic Tool Chain

The simplest form of tool orchestration is a linear chain of tools. Here's how to create a basic chain:

```bash
sniper orchestrate --chain "nmap > nikto > dirb" --target example.com
```

This command will:
1. Run Nmap against example.com
2. Pass the open web ports to Nikto
3. Pass discovered web directories to Dirb

### Using the Orchestration Configuration File

For more complex orchestration, you can define a YAML configuration file:

```yaml
name: "Web Application Assessment"
description: "Complete web application security assessment workflow"
target: "${TARGET}"
tools:
  - name: "port-scan"
    tool: "nmap"
    params: "-sV -p 1-65535 ${TARGET}"
    
  - name: "web-scan"
    tool: "zap"
    depends_on: "port-scan"
    params: "--target http://${TARGET}:${port-scan.web_port} --spider"
    condition: "port-scan.has_web_services == true"
    
  - name: "dir-bruteforce"
    tool: "dirsearch"
    depends_on: "web-scan"
    params: "-u http://${TARGET}:${port-scan.web_port} -e php,asp,aspx,jsp,html"
    
  - name: "vuln-scan"
    tool: "nuclei"
    depends_on: ["web-scan", "dir-bruteforce"]
    params: "-u http://${TARGET}:${port-scan.web_port} -t cves/ -severity critical,high"
```

Run this configuration with:

```bash
sniper orchestrate --config web_assessment.yaml --var TARGET=example.com
```

## Advanced Features

### Conditional Execution

Tools can be executed conditionally based on the results of previous tools:

```yaml
- name: "wordpress-scan"
  tool: "wpscan"
  depends_on: "tech-detect"
  params: "--url http://${TARGET} --enumerate u,p"
  condition: "tech-detect.wordpress == true"
```

### Data Passing Between Tools

You can reference outputs from previous tools using the `${tool_name.output_key}` syntax:

```yaml
- name: "exploit-attempt"
  tool: "metasploit"
  depends_on: "vuln-scan"
  params: "exploit/unix/webapp/${vuln-scan.exploit_module} RHOST=${TARGET} RPORT=${port-scan.web_port}"
  condition: "vuln-scan.exploitable == true"
```

### Parallel Execution

Tools that don't have dependencies on each other can run in parallel:

```yaml
- name: "ssl-scan"
  tool: "sslscan"
  depends_on: "port-scan"
  params: "${TARGET}:${port-scan.ssl_port}"
  parallel: true
  
- name: "dns-enum"
  tool: "sublist3r"
  params: "-d ${TARGET}"
  parallel: true
```

## Attack Path Visualization

The tool orchestration framework includes attack path visualization to help you understand potential exploitation chains:

```bash
sniper visualize --workflow workflow.yaml --target example.com
```

This will generate an interactive graph showing:
- All tools in the workflow
- Dependencies between tools
- Potential attack paths
- Successful exploitation chains

### Interactive Mode

You can also run the visualization in interactive mode, which allows you to:
- Click on nodes to see details
- Filter by risk level
- Highlight specific attack paths
- Export the graph as an image or SVG

```bash
sniper visualize --workflow workflow.yaml --target example.com --interactive
```

## Creating Workflow Templates

You can create reusable workflow templates for common security testing scenarios:

```bash
sniper template create --name "Web Full Scan" --tools nmap,nikto,zap,sqlmap,dirsearch
```

This will create a template that you can use as a starting point for your orchestration configurations.

## Integration with Safe Exploitation Framework

The tool orchestration framework integrates with the Safe Exploitation Framework to allow for controlled exploitation attempts:

```yaml
- name: "exploit-attempt"
  tool: "exploitation-framework"
  depends_on: "vuln-scan"
  params: "--vulnerability ${vuln-scan.vuln_id} --sandbox isolated --target ${TARGET}"
  safety:
    sandbox: "isolated"
    rollback: true
    monitoring: true
```

This configuration ensures that any exploitation attempts are performed in an isolated environment with proper monitoring and rollback capabilities.

## Best Practices

1. Start with simple tool chains and gradually build complexity
2. Use descriptive names for your workflow steps
3. Include conditions to avoid unnecessary tool execution
4. Test workflows on controlled environments before using them on production targets
5. Use the visualization tool to understand complex workflows
6. Always implement safety measures when using exploitation capabilities

## Troubleshooting

### Common Issues

1. **Tool Dependencies**: Ensure all required tools are installed and properly configured
2. **Condition Syntax**: Verify that condition expressions are valid
3. **Variable References**: Check that all variable references are properly defined
4. **Tool Timeouts**: Adjust timeouts for tools that may take longer to complete
5. **Data Passing**: Ensure output formats are compatible between chained tools

### Logs and Debugging

Enable debug logging for detailed information about the orchestration process:

```bash
sniper orchestrate --config workflow.yaml --debug --log-file orchestration.log
```

## Example Workflows

### Web Application Assessment

```yaml
name: "Complete Web Assessment"
description: "Full web application security assessment workflow"
target: "${TARGET}"
tools:
  - name: "port-scan"
    tool: "nmap"
    params: "-sV -p 1-65535 ${TARGET}"
    
  - name: "tech-detect"
    tool: "wappalyzer"
    depends_on: "port-scan"
    params: "http://${TARGET}:${port-scan.web_port}"
    
  - name: "web-spider"
    tool: "zap"
    depends_on: "tech-detect"
    params: "--spider --target http://${TARGET}:${port-scan.web_port}"
    
  - name: "vuln-scan"
    tool: "zap"
    depends_on: "web-spider"
    params: "--active-scan --target http://${TARGET}:${port-scan.web_port}"
    
  - name: "dir-enum"
    tool: "dirsearch"
    depends_on: "web-spider"
    params: "-u http://${TARGET}:${port-scan.web_port} -e php,asp,aspx,jsp,html"
    parallel: true
    
  - name: "sql-injection"
    tool: "sqlmap"
    depends_on: "web-spider"
    params: "--url http://${TARGET}:${port-scan.web_port} --forms --batch"
    parallel: true
    
  - name: "report-generation"
    tool: "report-gen"
    depends_on: ["vuln-scan", "dir-enum", "sql-injection"]
    params: "--output web-assessment-report.html --template detailed"
```

### Network Infrastructure Assessment

```yaml
name: "Network Infrastructure Assessment"
description: "Comprehensive network security assessment workflow"
target: "${TARGET_NETWORK}"
tools:
  - name: "network-discovery"
    tool: "nmap"
    params: "-sn ${TARGET_NETWORK}"
    
  - name: "service-enumeration"
    tool: "nmap"
    depends_on: "network-discovery"
    params: "-sV -sC -p- ${network-discovery.live_hosts}"
    
  - name: "vulnerability-scan"
    tool: "nessus"
    depends_on: "service-enumeration"
    params: "--targets ${network-discovery.live_hosts} --policy 'Advanced Scan'"
    
  - name: "windows-enumeration"
    tool: "crackmapexec"
    depends_on: "service-enumeration"
    params: "smb ${service-enumeration.windows_hosts} --pass-pol"
    condition: "service-enumeration.has_windows_hosts == true"
    
  - name: "network-report"
    tool: "report-gen"
    depends_on: ["vulnerability-scan", "windows-enumeration"]
    params: "--output network-assessment-report.html --template executive"
```

## Further Reading

- [API Documentation](api_usage.md)
- [Safe Exploitation Framework](autonomous_testing.md)
- [Distributed Scanning](distributed_scanning.md)
- [Report Generation](report_generation.md) 