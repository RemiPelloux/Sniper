"""OWASP ZAP integration for web vulnerability scanning using Docker."""

import logging
import subprocess
import tempfile
import time
import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseIntegration, ToolIntegrationError, ToolNotFoundError

log = logging.getLogger(__name__)

class ZAPIntegration(BaseIntegration):
    """Integration with OWASP ZAP for web vulnerability scanning using Docker.
    
    This integration uses the official OWASP ZAP Docker container to perform
    security scans against web applications. It supports different scan types
    including baseline scans (passive scanning only), full scans (active scanning),
    and API scans.
    
    All scans are executed within Docker containers to ensure isolation and
    avoid the need to install ZAP directly on the host system.
    """

    def __init__(self, verify_ssl: bool = True, options: Dict[str, Any] = None):
        """Initialize ZAP integration.
        
        Args:
            verify_ssl: Whether to verify SSL certificates during scanning
            options: Additional ZAP options including:
                - docker_image: ZAP Docker image (default: zaproxy/zap-stable)
                - api_key: ZAP API key (default: None for no key)
                - scan_policy: Scan policy (default: varies by scan_depth)
                - max_spider_duration: Maximum spider duration in minutes (default: 30)
                - max_ajax_spider_duration: Maximum AJAX spider duration in minutes (default: 10)
                - timeout: Maximum scan duration in seconds (default: 1800)
                - context_name: Name of the ZAP context to use (default: "Default Context")
                - include_paths: List of paths to include in the scan (default: [])
                - exclude_paths: List of paths to exclude from the scan (default: [])
        """
        self._verify_ssl = verify_ssl
        self._options = options or {}
        
        # Docker configuration
        self._docker_image = self._options.get("docker_image", "zaproxy/zap-stable")
        self._api_key = self._options.get("api_key", "")  # Empty string for no API key
        
        # Scan configuration defaults
        self._timeout = self._options.get("timeout", 1800)  # 30 minutes default
        self._max_spider_duration = self._options.get("max_spider_duration", 30)
        self._max_ajax_spider_duration = self._options.get("max_ajax_spider_duration", 10)
        self._context_name = self._options.get("context_name", "Default Context")
        self._include_paths = self._options.get("include_paths", [])
        self._exclude_paths = self._options.get("exclude_paths", [])
        
        # Check if Docker is available
        self._docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        """Check if Docker is available.
        
        Returns:
            bool: Whether Docker is available
        """
        try:
            # Check if Docker CLI is available
            result = subprocess.run(
                ["docker", "--version"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                check=False,
                timeout=10  # Add timeout to prevent hanging
            )
            if result.returncode != 0:
                log.error(f"Docker CLI not available: {result.stderr.decode('utf-8').strip()}")
                return False
                
            log.info(f"Docker available: {result.stdout.decode('utf-8').strip()}")
            return True
        except subprocess.TimeoutExpired:
            log.error("Docker command timed out")
            return False
        except Exception as e:
            log.error(f"Error checking Docker availability: {e}")
            return False

    @property
    def tool_name(self) -> str:
        """Get the name of the tool.
        
        Returns:
            str: The tool name
        """
        return "zap"

    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute ZAP scan against the target using Docker.

        Args:
            target: The target URL to scan
            **kwargs: Additional scan parameters including:
                - timeout: Maximum scan duration in seconds (default: 1800)
                - scan_policy: Policy to use (quick, standard, comprehensive)
                - debug: Enable debug output (default: False)
                - ajax_spider: Use AJAX spider (default: False)
                - include_paths: List of paths to include in the scan
                - exclude_paths: List of paths to exclude from the scan

        Returns:
            Dict containing scan results with alerts found

        Raises:
            ToolIntegrationError: If ZAP scan fails
            ToolNotFoundError: If Docker is not available
        """
        if not self._docker_available:
            log.error("Docker is not available. ZAP scan requires Docker.")
            raise ToolNotFoundError("Docker is not available. ZAP scan requires Docker.")
            
        try:
            # Create a temporary directory for ZAP output
            with tempfile.TemporaryDirectory() as temp_dir:
                # Define the output file location
                output_file = os.path.join(temp_dir, "zap_report.json")
                
                # Extract scan parameters from kwargs or use defaults from options
                timeout = kwargs.get("timeout", self._timeout)
                scan_policy = kwargs.get("scan_policy", self._options.get("scan_policy", ""))
                debug = kwargs.get("debug", False)
                ajax_spider = kwargs.get("ajax_spider", self._options.get("ajax_spider", False))
                include_paths = kwargs.get("include_paths", self._include_paths)
                exclude_paths = kwargs.get("exclude_paths", self._exclude_paths)
                
                log.info(f"Starting ZAP Docker scan against {target} with policy: {scan_policy}")
                
                # Build Docker command for appropriate scan type based on scan_policy
                docker_cmd = ["docker", "run", "--rm", "-v", f"{temp_dir}:/zap/wrk:rw"]
                
                if debug:
                    docker_cmd.append("-e")
                    docker_cmd.append("DEBUG=1")
                
                docker_cmd.append(self._docker_image)
                
                # Select scan type based on scan_policy
                if scan_policy == "quick":
                    # Use baseline scan (passive only)
                    docker_cmd.extend([
                        "zap-baseline.py", 
                        "-t", target,
                        "-J", "zap_report.json",  # Save directly in the mounted directory
                        "-I",  # Do not show informational alerts
                        "-m", str(self._max_spider_duration),  # Set maximum spider duration
                    ])
                    
                    if not self._verify_ssl:
                        docker_cmd.append("-n")  # Disable SSL verification
                        
                elif scan_policy == "comprehensive":
                    # Use full scan (active scanning)
                    docker_cmd.extend([
                        "zap-full-scan.py", 
                        "-t", target,
                        "-J", "zap_report.json",  # Save directly in the mounted directory
                        "-I",  # Do not show informational alerts
                        "-m", str(self._max_spider_duration),  # Set maximum spider duration
                    ])
                    
                    if not self._verify_ssl:
                        docker_cmd.append("-n")  # Disable SSL verification
                        
                    if ajax_spider:
                        docker_cmd.append("--ajax")  # Use AJAX spider
                        
                    # Add include/exclude paths if specified
                    for path in include_paths:
                        docker_cmd.extend(["-i", path])
                    
                    for path in exclude_paths:
                        docker_cmd.extend(["-e", path])
                else:
                    # Default to API scan for standard
                    docker_cmd.extend([
                        "zap-api-scan.py", 
                        "-t", target,
                        "-f", "openapi",  # Default format, will auto-detect
                        "-J", "zap_report.json",  # Save directly in the mounted directory
                        "-I",  # Do not show informational alerts
                    ])
                    
                    if not self._verify_ssl:
                        docker_cmd.append("-n")  # Disable SSL verification
                
                log.info(f"Running ZAP Docker command: {' '.join(docker_cmd)}")
                
                # Run the Docker command
                process = subprocess.Popen(
                    docker_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Stream logs from ZAP with timeout
                start_time = time.time()
                while process.poll() is None:
                    # Check if we've exceeded timeout
                    if time.time() - start_time > timeout:
                        log.warning(f"ZAP scan timed out after {timeout} seconds")
                        process.terminate()
                        try:
                            process.wait(timeout=10)  # Give it 10 seconds to terminate
                        except subprocess.TimeoutExpired:
                            process.kill()
                        break
                        
                    stdout_line = process.stdout.readline()
                    if stdout_line:
                        log.info(f"ZAP: {stdout_line.strip()}")
                        
                # Check if the process completed successfully
                exit_code = process.wait()
                if exit_code != 0:
                    stderr = process.stderr.read()
                    log.error(f"ZAP scan failed with exit code {exit_code}: {stderr}")
                
                # Read the output file
                try:
                    if os.path.exists(output_file):
                        with open(output_file, 'r') as f:
                            report_data = json.load(f)
                            
                        # Extract alerts from the report
                        site = report_data.get("site", [{}])[0]
                        alerts = site.get("alerts", [])
                        
                        # Format results
                        findings = []
                        for alert in alerts:
                            findings.append({
                                "name": alert.get("name", "Unknown"),
                                "risk": alert.get("risk", "Low"),
                                "confidence": alert.get("confidence", "Low"),
                                "url": alert.get("url", target),
                                "description": alert.get("description", "No description"),
                                "solution": alert.get("solution", "No solution provided"),
                                "evidence": alert.get("evidence", ""),
                                "cwe_id": alert.get("cweid", ""),
                                "wascid": alert.get("wascid", ""),
                                "instances": len(alert.get("instances", [])),
                                "alert_refs": alert.get("alertRef", ""),
                                "tags": alert.get("tags", {})
                            })
                        
                        log.info(f"ZAP scan completed for {target}, found {len(findings)} issues")
                        return {"alerts": findings}
                    else:
                        log.warning(f"ZAP output file not found: {output_file}")
                        return {"alerts": []}
                except Exception as e:
                    log.error(f"Error reading ZAP output: {e}")
                    return {"alerts": []}
            
        except Exception as e:
            log.exception(f"Error during ZAP scan: {e}")
            raise ToolIntegrationError(f"ZAP scan failed: {str(e)}") from e
            
    def check_prerequisites(self) -> bool:
        """Check if ZAP prerequisites are met.
        
        Returns:
            bool: Whether prerequisites are met
        """
        if not self._docker_available:
            log.error("Docker is not available for ZAP scanning")
            return False
            
        # Check if ZAP Docker image is available
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self._docker_image],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            if result.returncode != 0:
                log.warning(f"ZAP Docker image '{self._docker_image}' not found. Will attempt to pull when running scan.")
                
                # Try to pull the image now to verify it exists
                pull_result = subprocess.run(
                    ["docker", "pull", self._docker_image],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False
                )
                
                if pull_result.returncode != 0:
                    log.error(f"Failed to pull ZAP Docker image: {pull_result.stderr.decode('utf-8').strip()}")
                    return False
                    
                log.info(f"Successfully pulled ZAP Docker image: {self._docker_image}")
            else:
                log.info(f"ZAP Docker image '{self._docker_image}' is available")
                
            return True
        except Exception as e:
            log.error(f"Error checking ZAP Docker image: {e}")
            return False
