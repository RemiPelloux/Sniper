"""
REST API for Sniper Security Scanner

This module provides a REST API interface to the Sniper security scanning tool,
allowing for remote execution of scans and retrieval of results.

Features:
- Token-based authentication
- Rate limiting
- Scan job management
- Result retrieval and filtering
- Webhook notifications
- Live scan status updates
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Optional, Union, Any

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import Sniper modules
from src.core.config import ConfigManager
from src.core.logging import setup_logging
from src.results.types import BaseFinding, ScanResult
from src.integrations.base import BaseIntegration
from src.cli.scan import run_scan

# Set up logging
logger = logging.getLogger(__name__)
setup_logging()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute", "1000 per hour"],
    storage_uri="memory://",
)

# Dictionary to store active scans and their status
active_scans: Dict[str, Dict[str, Any]] = {}

# Load configuration
config_manager = ConfigManager()
api_config = config_manager.get_config().get("api", {})
auth_enabled = api_config.get("authentication", {}).get("enabled", True)

# Authentication middleware
def authenticate_request():
    """Authenticate incoming API requests"""
    if not auth_enabled:
        return True
    
    auth_token = request.headers.get("X-API-Token")
    expected_token = api_config.get("authentication", {}).get("token")
    
    if not auth_token or auth_token != expected_token:
        return False
    
    return True

# Routes
@app.route("/api/v1/health", methods=["GET"])
def health_check() -> Response:
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route("/api/v1/scans", methods=["POST"])
@limiter.limit("10 per minute")
def start_scan() -> Response:
    """Start a new scan"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        scan_data = request.json
        if not scan_data:
            return jsonify({"error": "No scan parameters provided"}), 400
        
        target = scan_data.get("target")
        if not target:
            return jsonify({"error": "No target specified"}), 400
        
        tools = scan_data.get("tools", [])
        options = scan_data.get("options", {})
        depth = scan_data.get("depth", 1)
        
        # Generate a unique scan ID
        scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{hash(target) % 10000}"
        
        # Store scan metadata
        active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "tools": tools,
            "options": options,
            "depth": depth,
            "status": "pending",
            "start_time": datetime.datetime.now().isoformat(),
            "end_time": None,
            "results": None,
        }
        
        # TODO: Run scan in background thread or task queue
        # This is a placeholder for Sprint 4 implementation
        
        return jsonify({
            "scan_id": scan_id,
            "status": "pending",
            "target": target,
            "message": "Scan queued successfully"
        })
    
    except Exception as e:
        logger.exception("Error starting scan")
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/scans/<scan_id>", methods=["GET"])
def get_scan_status(scan_id: str) -> Response:
    """Get the status of a scan"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify(active_scans[scan_id])

@app.route("/api/v1/scans/<scan_id>/results", methods=["GET"])
def get_scan_results(scan_id: str) -> Response:
    """Get the results of a completed scan"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan = active_scans[scan_id]
    if scan["status"] != "completed":
        return jsonify({"error": "Scan not completed yet", "status": scan["status"]}), 400
    
    # Filter results based on query parameters
    severity = request.args.get("severity")
    tool = request.args.get("tool")
    
    # In Sprint 4, implement actual result filtering
    results = scan.get("results", {})
    
    return jsonify(results)

@app.route("/api/v1/scans/<scan_id>", methods=["DELETE"])
def cancel_scan(scan_id: str) -> Response:
    """Cancel a running scan"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan = active_scans[scan_id]
    if scan["status"] in ["completed", "cancelled", "failed"]:
        return jsonify({"error": f"Scan already {scan['status']}"})
    
    # TODO: Implement actual scan cancellation in Sprint 4
    scan["status"] = "cancelled"
    scan["end_time"] = datetime.datetime.now().isoformat()
    
    return jsonify({"message": "Scan cancelled successfully", "scan_id": scan_id})

@app.route("/api/v1/tools", methods=["GET"])
def list_available_tools() -> Response:
    """List all available scanning tools and their capabilities"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    # In Sprint 4, implement actual tool discovery and capability reporting
    tools = {
        "nmap": {
            "name": "Nmap",
            "description": "Network mapper for port scanning",
            "options": ["sudo", "arguments"]
        },
        "zap": {
            "name": "OWASP ZAP",
            "description": "Web application security scanner",
            "options": ["scan_type", "auth", "ajax", "active"]
        },
        "wappalyzer": {
            "name": "Wappalyzer",
            "description": "Technology detection tool",
            "options": ["headless"]
        },
        "sublist3r": {
            "name": "Sublist3r",
            "description": "Subdomain enumeration tool",
            "options": ["threads"]
        },
        "dirsearch": {
            "name": "Dirsearch",
            "description": "Web path discovery tool",
            "options": ["wordlist", "extensions"]
        }
    }
    
    return jsonify(tools)

@app.route("/api/v1/config", methods=["GET"])
def get_config() -> Response:
    """Get current API configuration"""
    if auth_enabled and not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    
    # Return safe configuration (omitting sensitive values)
    safe_config = {
        "rate_limiting": api_config.get("rate_limiting", {}),
        "authentication": {
            "enabled": api_config.get("authentication", {}).get("enabled", True),
            "method": api_config.get("authentication", {}).get("method", "token")
        },
        "host": api_config.get("host", "0.0.0.0"),
        "port": api_config.get("port", 5000)
    }
    
    return jsonify(safe_config)

def run_api_server(host: str = None, port: int = None) -> None:
    """
    Run the API server with the specified host and port.
    
    Args:
        host: The host to run the server on. Defaults to config value or 0.0.0.0.
        port: The port to run the server on. Defaults to config value or 5000.
    """
    if host is None:
        host = api_config.get("host", "0.0.0.0")
    
    if port is None:
        port = api_config.get("port", 5000)
    
    logger.info(f"Starting API server on {host}:{port}")
    app.run(host=host, port=port, debug=False)

if __name__ == "__main__":
    # Entry point for direct execution
    run_api_server() 