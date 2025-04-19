# Sniper REST API Usage Guide

This guide explains how to use the Sniper REST API to programmatically control Sniper's security testing capabilities.

## API Overview

The Sniper REST API provides:

- Remote access to scanning functionality
- Real-time scan monitoring
- Result retrieval and management
- Machine learning feature access
- Distributed scanning management

## Getting Started

### Starting the API Server

```bash
# Start the API server (default port 5000)
sniper api start

# Specify custom host and port
sniper api start --host 0.0.0.0 --port 8000

# Start with authentication enabled
sniper api start --auth

# Start with SSL
sniper api start --ssl --cert cert.pem --key key.pem
```

### Authentication

The API supports authentication via JWT (JSON Web Tokens):

```bash
# Create an API key
sniper api create-key --name "my-integration" --role admin

# Get the list of API keys
sniper api list-keys

# Revoke an API key
sniper api revoke-key --id abc123
```

### Making API Requests

For all requests that require authentication, include the JWT token in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Core API Endpoints

### API Information

```http
GET /api/v1/info
```

Response:

```json
{
  "version": "1.2.0",
  "api_version": "v1",
  "tools": 42,
  "capabilities": ["scanning", "ml", "autonomous", "distributed"]
}
```

### Health Check

```http
GET /api/v1/health
```

Response:

```json
{
  "status": "ok",
  "components": {
    "database": "ok",
    "scanner": "ok",
    "distributed": "ok"
  }
}
```

## Scan Management

### Starting a Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target": "example.com",
  "scan_type": "webapp",
  "scan_mode": "normal",
  "options": {
    "depth": 3,
    "include_tools": ["nmap", "zap", "sqlmap"],
    "ml_enabled": true
  }
}
```

Response:

```json
{
  "scan_id": "abc123",
  "status": "scheduled",
  "target": "example.com",
  "created_at": "2023-07-15T14:30:21Z",
  "estimated_completion": "2023-07-15T15:30:21Z"
}
```

### Getting Scan Status

```http
GET /api/v1/scans/{scan_id}
```

Response:

```json
{
  "scan_id": "abc123",
  "status": "running",
  "target": "example.com",
  "progress": 45,
  "current_stage": "webapp_scanning",
  "created_at": "2023-07-15T14:30:21Z",
  "estimated_completion": "2023-07-15T15:30:21Z"
}
```

### Listing Scans

```http
GET /api/v1/scans?status=completed&limit=10&offset=0
```

Response:

```json
{
  "total": 42,
  "offset": 0,
  "limit": 10,
  "scans": [
    {
      "scan_id": "abc123",
      "status": "completed",
      "target": "example.com",
      "created_at": "2023-07-15T14:30:21Z",
      "completed_at": "2023-07-15T15:25:47Z"
    },
    // More scans...
  ]
}
```

### Stopping a Scan

```http
POST /api/v1/scans/{scan_id}/stop
```

Response:

```json
{
  "scan_id": "abc123",
  "status": "stopping",
  "message": "Scan is being stopped"
}
```

### Deleting a Scan

```http
DELETE /api/v1/scans/{scan_id}
```

Response:

```json
{
  "message": "Scan abc123 deleted successfully"
}
```

## Scan Results

### Getting Scan Results

```http
GET /api/v1/scans/{scan_id}/results
```

Response:

```json
{
  "scan_id": "abc123",
  "target": "example.com",
  "status": "completed",
  "summary": {
    "total_findings": 12,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 3
  },
  "findings": [
    {
      "id": "finding-001",
      "type": "xss",
      "severity": "high",
      "confidence": "high",
      "title": "Reflected XSS in Search Parameter",
      "description": "The search parameter reflects user input without proper encoding...",
      "location": "https://example.com/search?q=test",
      "evidence": "...",
      "remediation": "..."
    },
    // More findings...
  ]
}
```

### Filtering Results

```http
GET /api/v1/scans/{scan_id}/results?severity=high,critical&type=xss,sqli
```

### Exporting Results

```http
GET /api/v1/scans/{scan_id}/export?format=json
```

```http
GET /api/v1/scans/{scan_id}/export?format=html
```

## Autonomous Testing API

### Starting Autonomous Testing

```http
POST /api/v1/autonomous
Content-Type: application/json

{
  "target": "example.com",
  "vulnerability_type": "xss",
  "options": {
    "payload_count": 20,
    "max_depth": 3,
    "include_evidence": true
  }
}
```

Response:

```json
{
  "task_id": "task-123",
  "status": "scheduled",
  "target": "example.com",
  "vulnerability_type": "xss"
}
```

### Getting Autonomous Test Status

```http
GET /api/v1/autonomous/{task_id}
```

Response:

```json
{
  "task_id": "task-123",
  "status": "running",
  "target": "example.com",
  "vulnerability_type": "xss",
  "progress": 65,
  "findings_count": 3
}
```

### Getting Autonomous Test Results

```http
GET /api/v1/autonomous/{task_id}/results
```

Response:

```json
{
  "task_id": "task-123",
  "status": "completed",
  "target": "example.com",
  "summary": {
    "total_findings": 5,
    "verified_findings": 3
  },
  "findings": [
    {
      "id": "auto-001",
      "vulnerability_type": "xss",
      "severity": "high",
      "confidence": "high",
      "location": "https://example.com/search?q=test",
      "payload": "<script>alert(1)</script>",
      "evidence": "..."
    },
    // More findings...
  ]
}
```

## ML Features API

### ML Tool Selection

```http
POST /api/v1/ml/tool-selection
Content-Type: application/json

{
  "target_info": {
    "url": "example.com",
    "technologies": ["Apache", "PHP", "MySQL"],
    "open_ports": [80, 443, 22]
  }
}
```

Response:

```json
{
  "recommended_tools": [
    {
      "name": "nmap",
      "score": 0.95,
      "category": "reconnaissance"
    },
    {
      "name": "sqlmap",
      "score": 0.87,
      "category": "vulnerability_scanning"
    },
    // More tools...
  ]
}
```

### ML Vulnerability Prediction

```http
POST /api/v1/ml/vulnerability-prediction
Content-Type: application/json

{
  "finding": {
    "type": "possible_xss",
    "location": "https://example.com/search?q=test",
    "evidence": "Input reflected in response without encoding",
    "context": "HTML body"
  }
}
```

Response:

```json
{
  "prediction": {
    "vulnerability": "xss",
    "confidence": 0.89,
    "severity": "high",
    "false_positive_probability": 0.12
  },
  "recommended_tests": [
    {
      "payload": "<script>alert(1)</script>",
      "confidence": 0.85
    },
    // More tests...
  ]
}
```

### ML Model Training

```http
POST /api/v1/ml/train
Content-Type: application/json

{
  "model": "vulnerability_predictor",
  "training_data": "...",
  "options": {
    "epochs": 10,
    "batch_size": 32
  }
}
```

Response:

```json
{
  "task_id": "train-123",
  "status": "scheduled",
  "model": "vulnerability_predictor",
  "estimated_completion": "2023-07-15T16:30:00Z"
}
```

## Distributed Scanning API

### Starting Master Node

```http
POST /api/v1/distributed/master/start
Content-Type: application/json

{
  "host": "0.0.0.0",
  "port": 8080,
  "options": {
    "max_workers": 10,
    "auth_enabled": true
  }
}
```

Response:

```json
{
  "status": "started",
  "address": "0.0.0.0:8080",
  "master_id": "master-123"
}
```

### Getting Master Status

```http
GET /api/v1/distributed/master/status
```

Response:

```json
{
  "status": "running",
  "address": "0.0.0.0:8080",
  "uptime": "3h 21m",
  "workers_connected": 5,
  "tasks_queued": 3,
  "tasks_running": 2,
  "tasks_completed": 45
}
```

### Submitting a Distributed Task

```http
POST /api/v1/distributed/tasks
Content-Type: application/json

{
  "target": "example.com",
  "type": "scan",
  "scan_type": "webapp",
  "priority": "high",
  "options": {
    "depth": 3,
    "tools": ["nmap", "zap", "sqlmap"]
  }
}
```

Response:

```json
{
  "task_id": "dtask-123",
  "status": "scheduled",
  "target": "example.com",
  "priority": "high"
}
```

### Getting Worker Status

```http
GET /api/v1/distributed/workers
```

Response:

```json
{
  "total": 5,
  "workers": [
    {
      "worker_id": "worker-1",
      "status": "active",
      "address": "192.168.1.101",
      "capabilities": ["nmap", "zap", "sqlmap"],
      "tasks_completed": 12,
      "tasks_running": 1,
      "last_heartbeat": "2023-07-15T15:25:47Z"
    },
    // More workers...
  ]
}
```

## API Webhooks

### Creating a Webhook

```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "url": "https://example.com/callback",
  "events": ["scan_completed", "finding_detected"],
  "secret": "your_webhook_secret"
}
```

Response:

```json
{
  "webhook_id": "wh-123",
  "url": "https://example.com/callback",
  "events": ["scan_completed", "finding_detected"],
  "created_at": "2023-07-15T15:30:00Z"
}
```

### Listing Webhooks

```http
GET /api/v1/webhooks
```

Response:

```json
{
  "webhooks": [
    {
      "webhook_id": "wh-123",
      "url": "https://example.com/callback",
      "events": ["scan_completed", "finding_detected"],
      "created_at": "2023-07-15T15:30:00Z"
    },
    // More webhooks...
  ]
}
```

### Deleting a Webhook

```http
DELETE /api/v1/webhooks/{webhook_id}
```

Response:

```json
{
  "message": "Webhook wh-123 deleted successfully"
}
```

## API Clients

### Python Client Example

```python
import requests
import json

class SniperClient:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}'
            })
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def start_scan(self, target, scan_type="webapp", mode="normal", options=None):
        payload = {
            "target": target,
            "scan_type": scan_type,
            "scan_mode": mode,
            "options": options or {}
        }
        response = self.session.post(f"{self.base_url}/api/v1/scans", json=payload)
        response.raise_for_status()
        return response.json()

    def get_scan_status(self, scan_id):
        response = self.session.get(f"{self.base_url}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        return response.json()

    def get_scan_results(self, scan_id):
        response = self.session.get(f"{self.base_url}/api/v1/scans/{scan_id}/results")
        response.raise_for_status()
        return response.json()

# Usage example
client = SniperClient("http://localhost:5000", "your_api_key")
scan = client.start_scan("example.com", scan_type="webapp")
print(f"Scan started with ID: {scan['scan_id']}")
```

### JavaScript Client Example

```javascript
class SniperClient {
  constructor(baseUrl, apiKey = null) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };
    
    if (apiKey) {
      this.headers['Authorization'] = `Bearer ${apiKey}`;
    }
  }

  async startScan(target, scanType = "webapp", mode = "normal", options = {}) {
    const payload = {
      target,
      scan_type: scanType,
      scan_mode: mode,
      options
    };
    
    const response = await fetch(`${this.baseUrl}/api/v1/scans`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    return await response.json();
  }

  async getScanStatus(scanId) {
    const response = await fetch(`${this.baseUrl}/api/v1/scans/${scanId}`, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    return await response.json();
  }

  async getScanResults(scanId) {
    const response = await fetch(`${this.baseUrl}/api/v1/scans/${scanId}/results`, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    return await response.json();
  }
}

// Usage example
const client = new SniperClient('http://localhost:5000', 'your_api_key');
client.startScan('example.com', 'webapp')
  .then(scan => console.log(`Scan started with ID: ${scan.scan_id}`))
  .catch(error => console.error('Error starting scan:', error));
```

## Integration Examples

### CI/CD Integration

```yaml
# GitHub Actions Example
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Run Sniper scan
      run: |
        curl -X POST "https://your-sniper-api.com/api/v1/scans" \
          -H "Authorization: Bearer ${{ secrets.SNIPER_API_KEY }}" \
          -H "Content-Type: application/json" \
          -d '{
            "target": "https://staging.example.com",
            "scan_type": "webapp",
            "scan_mode": "normal",
            "options": {
              "min_severity": "high",
              "fail_on_critical": true
            }
          }' > scan.json
        
        SCAN_ID=$(jq -r '.scan_id' scan.json)
        
        # Poll for scan completion
        while true; do
          STATUS=$(curl -s "https://your-sniper-api.com/api/v1/scans/$SCAN_ID" \
            -H "Authorization: Bearer ${{ secrets.SNIPER_API_KEY }}" | jq -r '.status')
          
          if [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then
            break
          fi
          
          echo "Scan in progress, status: $STATUS"
          sleep 30
        done
        
        # Get results
        curl -s "https://your-sniper-api.com/api/v1/scans/$SCAN_ID/results" \
          -H "Authorization: Bearer ${{ secrets.SNIPER_API_KEY }}" > results.json
        
        # Check for critical findings
        CRITICAL_COUNT=$(jq '.summary.critical' results.json)
        if [[ $CRITICAL_COUNT -gt 0 ]]; then
          echo "Found $CRITICAL_COUNT critical vulnerabilities!"
          exit 1
        fi
```

### JIRA Integration

```python
import requests
import json
from jira import JIRA

# Sniper API client
sniper_api_url = "https://your-sniper-api.com"
sniper_api_key = "your_sniper_api_key"

# JIRA configuration
jira_url = "https://your-jira-instance.com"
jira_username = "your_username"
jira_api_token = "your_api_token"
jira_project = "SEC"

# Initialize JIRA client
jira = JIRA(server=jira_url, basic_auth=(jira_username, jira_api_token))

# Get scan results from Sniper
def get_scan_results(scan_id):
    response = requests.get(
        f"{sniper_api_url}/api/v1/scans/{scan_id}/results",
        headers={"Authorization": f"Bearer {sniper_api_key}"}
    )
    response.raise_for_status()
    return response.json()

# Create JIRA issue for a vulnerability
def create_jira_issue(finding):
    issue_dict = {
        'project': {'key': jira_project},
        'summary': f"Security Finding: {finding['title']}",
        'description': f"""
Security finding detected by Sniper.

**Type:** {finding['type']}
**Severity:** {finding['severity']}
**Confidence:** {finding['confidence']}

**Description:**
{finding['description']}

**Location:**
{finding['location']}

**Evidence:**
{finding['evidence']}

**Remediation:**
{finding['remediation']}
        """,
        'issuetype': {'name': 'Bug'},
        'priority': {'name': map_severity_to_priority(finding['severity'])},
        'labels': ['security', 'sniper', finding['type']]
    }
    
    return jira.create_issue(fields=issue_dict)

# Map Sniper severity to JIRA priority
def map_severity_to_priority(severity):
    mapping = {
        'critical': 'Highest',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Lowest'
    }
    return mapping.get(severity, 'Medium')

# Main function to process scan results
def process_scan_results(scan_id):
    results = get_scan_results(scan_id)
    
    print(f"Processing scan results for {results['target']}")
    print(f"Found {results['summary']['total_findings']} findings")
    
    for finding in results['findings']:
        if finding['severity'] in ['critical', 'high']:
            try:
                issue = create_jira_issue(finding)
                print(f"Created JIRA issue {issue.key} for {finding['title']}")
            except Exception as e:
                print(f"Failed to create JIRA issue: {e}")

# Example usage
process_scan_results("abc123")
```

## Best Practices

### Security Recommendations

1. **Always use HTTPS and authentication** for production deployments
2. **Rotate API keys** periodically and use separate keys for different integrations
3. **Limit API access** to trusted networks where possible
4. **Validate webhook payloads** using the secret to prevent spoofing
5. **Follow the principle of least privilege** when assigning API key roles

### Performance Considerations

1. **Use pagination** for endpoints that return large amounts of data
2. **Limit concurrent requests** to prevent overloading the API server
3. **Implement caching** for frequently accessed results
4. **Use webhooks** instead of polling for long-running operations
5. **Include only necessary fields** in requests to reduce payload size

### Error Handling

API errors are returned with appropriate HTTP status codes and JSON error messages:

```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired API key",
  "status_code": 401
}
```

Common status codes:

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

## API Versioning

The API uses versioning in the URL path (`/api/v1/...`). When new major versions are released, they will be available at `/api/v2/...`, etc. Minor updates and bug fixes will be made to existing versions without breaking changes.

## Next Steps

After becoming familiar with the Sniper API, you may want to explore:

- [API Authentication](api_authentication.md) for detailed authentication options
- [Webhooks](webhooks.md) for real-time event processing
- [Integration Examples](integration_examples.md) for more complete integration scenarios 