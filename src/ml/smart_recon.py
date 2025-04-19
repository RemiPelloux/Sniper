"""
SmartRecon ML Module for Sniper Tool.

This module provides machine learning capabilities for intelligent reconnaissance,
including tool selection, pattern recognition, and vulnerability prediction.
It leverages historical scan data to optimize scanning strategies and improve
the efficiency and effectiveness of security testing.

Features:
- Smart tool selection based on target characteristics
- Pattern recognition for identifying potential vulnerabilities
- Learning from past scans and bug bounty reports
- Optimization of scan strategies based on target profile
- Statistical analysis of findings and vulnerabilities

Dependencies:
- numpy
- pandas
- scikit-learn
- joblib

Usage:
    from src.ml.smart_recon import SmartRecon

    # Initialize the SmartRecon module
    recon = SmartRecon(model_dir="/path/to/models")

    # Extract features from a target
    features = recon.extract_target_features("example.com")

    # Get recommended tools for a target
    tools = recon.select_tools("example.com")

    # Recognize patterns in findings
    patterns = recon.recognize_patterns(findings)

    # Optimize scan strategy
    strategy = recon.optimize_scan_strategy("example.com", previous_findings)
"""

import json
import logging
import os
import re
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Set up logging
logger = logging.getLogger(__name__)


class SmartRecon:
    """
    SmartRecon class provides machine learning capabilities for intelligent
    reconnaissance, tool selection, and pattern recognition.
    """

    def __init__(self, model_dir: str = None):
        """
        Initialize the SmartRecon class.

        Args:
            model_dir: Directory to store trained models
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)

        # Initialize models
        self.tool_selector_model = None
        self.pattern_recognizer_model = None
        self.clustering_model = None
        self.scaler = StandardScaler()

        # Tool efficiency metrics
        self.tool_efficiency = {
            "nmap": {"speed": 0.7, "accuracy": 0.9, "resource_usage": 0.6},
            "zap": {"speed": 0.5, "accuracy": 0.85, "resource_usage": 0.8},
            "wappalyzer": {"speed": 0.9, "accuracy": 0.75, "resource_usage": 0.3},
            "dirsearch": {"speed": 0.6, "accuracy": 0.8, "resource_usage": 0.5},
            "sublist3r": {"speed": 0.8, "accuracy": 0.7, "resource_usage": 0.4},
        }

        # Load models if they exist
        self._load_models()

    def _load_models(self):
        """Load trained models if they exist."""
        tool_selector_path = os.path.join(self.model_dir, "tool_selector.joblib")
        pattern_recognizer_path = os.path.join(
            self.model_dir, "pattern_recognizer.joblib"
        )

        if os.path.exists(tool_selector_path):
            try:
                self.tool_selector_model = joblib.load(tool_selector_path)
                logger.info("Loaded tool selector model")
            except Exception as e:
                logger.error(f"Error loading tool selector model: {e}")

        if os.path.exists(pattern_recognizer_path):
            try:
                self.pattern_recognizer_model = joblib.load(pattern_recognizer_path)
                logger.info("Loaded pattern recognizer model")
            except Exception as e:
                logger.error(f"Error loading pattern recognizer model: {e}")

    def save_models(self):
        """Save trained models to disk."""
        if self.tool_selector_model:
            tool_selector_path = os.path.join(self.model_dir, "tool_selector.joblib")
            joblib.dump(self.tool_selector_model, tool_selector_path)
            logger.info(f"Saved tool selector model to {tool_selector_path}")

        if self.pattern_recognizer_model:
            pattern_recognizer_path = os.path.join(
                self.model_dir, "pattern_recognizer.joblib"
            )
            joblib.dump(self.pattern_recognizer_model, pattern_recognizer_path)
            logger.info(f"Saved pattern recognizer model to {pattern_recognizer_path}")

    def extract_target_features(self, target: Union[str, Dict[str, Any]]) -> np.ndarray:
        """
        Extract a feature vector from a target for model prediction.

        Args:
            target: The target URL, IP, domain or a dictionary with target details

        Returns:
            A numpy array of features
        """
        if isinstance(target, str):
            # Basic features from the target string
            target_str = target
            target_dict = {"url": target}
        else:
            target_str = target.get("url", "")
            target_dict = target

        # Initialize feature dictionary
        feature_dict = {}

        # Process the URL/domain/IP
        hostname_target = target_str
        if hostname_target.startswith(("http://", "https://")):
            parsed_url = urlparse(hostname_target)
            hostname_target = parsed_url.netloc

            # Protocol features
            feature_dict["is_https"] = 1 if parsed_url.scheme == "https" else 0

            # Add path-related features
            path = parsed_url.path
            feature_dict["has_path"] = 1 if path and path != "/" else 0
            feature_dict["path_length"] = len(path) if path else 0
            feature_dict["path_depth"] = path.count("/") if path else 0

            # Query parameters
            query = parsed_url.query
            feature_dict["has_query"] = 1 if query else 0
            feature_dict["query_length"] = len(query) if query else 0
            feature_dict["query_params_count"] = query.count("&") + 1 if query else 0

        # IP address features
        is_ip = self._is_ip_address(hostname_target)
        feature_dict["is_ip"] = 1 if is_ip else 0

        if is_ip:
            # Private IP feature
            is_private = self._is_private_ip(hostname_target)
            feature_dict["is_private_ip"] = 1 if is_private else 0

            # IP range features (useful for understanding the target's network)
            octets = hostname_target.split(".")
            if len(octets) == 4:
                try:
                    feature_dict["first_octet"] = int(octets[0]) / 255
                    feature_dict["second_octet"] = int(octets[1]) / 255
                except (ValueError, IndexError):
                    feature_dict["first_octet"] = 0
                    feature_dict["second_octet"] = 0
        else:
            feature_dict["is_private_ip"] = 0
            feature_dict["first_octet"] = 0
            feature_dict["second_octet"] = 0

            # Domain length (more entropy in longer domain names)
            feature_dict["domain_length"] = len(hostname_target)

            # Domain entropy (randomness, might suggest algorithmically generated domains)
            try:
                feature_dict["domain_entropy"] = (
                    self._calculate_entropy(hostname_target) / 5.0
                )
            except:
                feature_dict["domain_entropy"] = 0.0

            # Subdomain features
            subdomain_count = (
                hostname_target.count(".") - 1 if hostname_target.count(".") > 0 else 0
            )
            feature_dict["subdomain_count"] = min(subdomain_count, 5) / 5  # normalized

            # Handle TLD encoding - convert strings to numerical features
            tld = self._extract_tld(hostname_target)
            # Common TLDs get specific binary flags
            feature_dict["tld_com"] = 1 if tld == "com" else 0
            feature_dict["tld_org"] = 1 if tld == "org" else 0
            feature_dict["tld_net"] = 1 if tld == "net" else 0
            feature_dict["tld_edu"] = 1 if tld == "edu" else 0
            feature_dict["tld_gov"] = 1 if tld == "gov" else 0
            feature_dict["tld_io"] = 1 if tld == "io" else 0
            feature_dict["tld_co"] = 1 if tld == "co" else 0
            # Add a numerical representation of TLD length as an additional feature
            feature_dict["tld_length"] = len(tld) if tld else 0

            # Add a hash-based encoding of the TLD for less common TLDs
            if tld and not any(
                feature_dict.get(f"tld_{t}")
                for t in ["com", "org", "net", "edu", "gov", "io", "co"]
            ):
                # Simple hash function to convert TLD to a number between 0 and 1
                tld_hash = sum(ord(c) for c in tld) % 100 / 100.0
                feature_dict["tld_hash"] = tld_hash
            else:
                feature_dict["tld_hash"] = 0.0

        # Convert dictionary to numpy array - ensure all values are numeric
        feature_values = []
        for key, val in feature_dict.items():
            if isinstance(val, (int, float)):
                feature_values.append(val)
            elif isinstance(val, bool):
                feature_values.append(1 if val else 0)
            elif isinstance(val, str):
                # Skip string values as they can't be converted to float for the model
                logger.debug(f"Skipping string feature '{key}': {val}")
                continue
            else:
                # Skip non-numeric values
                logger.debug(f"Skipping non-numeric feature '{key}': {val}")
                continue

        return np.array(feature_values, dtype=np.float64)

    def extract_finding_features(self, findings: List[Dict]) -> np.ndarray:
        """
        Extract features from a list of findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Numpy array of features
        """
        if not findings:
            return np.array([])

        # Extract basic features
        features = []
        for finding in findings:
            # Normalize severity to numerical value
            severity = self._normalize_severity(finding.get("severity", "low"))

            # Extract confidence
            confidence = self._normalize_confidence(finding.get("confidence", "low"))

            # Extract tool information
            tool = finding.get("source", "unknown")
            tool_encoded = self._encode_tool(tool)

            # Extract description features
            description = finding.get("description", "")
            desc_length = len(description)
            has_cve = 1 if "CVE-" in description else 0
            has_url = 1 if "http://" in description or "https://" in description else 0

            finding_features = [
                severity,
                confidence,
                tool_encoded,
                desc_length,
                has_cve,
                has_url,
            ]
            features.append(finding_features)

        return np.array(features)

    def _normalize_severity(self, severity: str) -> float:
        """Convert severity string to numerical value."""
        severity_map = {
            "info": 0.0,
            "low": 0.25,
            "medium": 0.5,
            "high": 0.75,
            "critical": 1.0,
        }
        return severity_map.get(severity.lower(), 0.25)

    def _normalize_confidence(self, confidence: str) -> float:
        """Convert confidence string to numerical value."""
        confidence_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "confirmed": 1.0}
        return confidence_map.get(confidence.lower(), 0.5)

    def _encode_tool(self, tool: str) -> int:
        """Encode tool name to numerical value."""
        tool_map = {
            "nmap": 1,
            "zap": 2,
            "wappalyzer": 3,
            "dirsearch": 4,
            "sublist3r": 5,
            "manual": 6,
        }
        return tool_map.get(tool.lower(), 0)

    def _is_ip_address(self, target: str) -> bool:
        """
        Check if a target is an IP address.

        Args:
            target: The target string to check

        Returns:
            Whether the target is an IP address
        """
        try:
            ip_address(target)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip_str: str) -> bool:
        """
        Check if an IP address is private.

        Args:
            ip_str: The IP address string

        Returns:
            Whether the IP is private
        """
        try:
            ip = ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def train_tool_selector(
        self, targets: List[str], tool_effectiveness: List[Dict]
    ) -> None:
        """
        Train the tool selector model based on past scans.

        Args:
            targets: List of targets (domains/IPs) that were scanned
            tool_effectiveness: List of dictionaries with tool effectiveness metrics
                for each target
        """
        logger.info(f"Starting train_tool_selector with {len(targets)} targets")
        if (
            not targets
            or not tool_effectiveness
            or len(targets) != len(tool_effectiveness)
        ):
            logger.error("Invalid training data for tool selector")
            return

        # Extract features from targets
        X = []
        y = []

        logger.info(f"Processing {len(targets)} targets for feature extraction")
        for idx, target in enumerate(targets):
            # Extract target features
            target_features = self.extract_target_features(target)
            logger.info(
                f"Extracted features for target {idx}: shape={target_features.shape}"
            )

            if len(target_features) > 0:
                X.append(target_features)

                # Get the most effective tool for this target
                effectiveness = tool_effectiveness[idx]
                logger.info(f"Tool effectiveness for target {idx}: {effectiveness}")
                best_tool = max(effectiveness.items(), key=lambda x: x[1])
                y.append(self._encode_tool(best_tool[0]))

        logger.info(f"Collected {len(X)} feature vectors and {len(y)} labels")
        if not X or not y:
            logger.error("No valid features extracted for tool selector training")
            return

        # Train the model
        logger.info("Creating RandomForestClassifier")
        self.tool_selector_model = RandomForestClassifier(
            n_estimators=100, random_state=42
        )

        logger.info(f"Fitting model with {len(X)} samples")
        self.tool_selector_model.fit(X, y)
        logger.info("Trained tool selector model")

        # Save the model
        logger.info("Saving trained model")
        self.save_models()

    def train_pattern_recognizer(
        self, findings_groups: List[List[Dict]], labels: List[int]
    ) -> None:
        """
        Train the pattern recognizer model based on past findings.

        Args:
            findings_groups: List of findings groups, where each group is a list of
                finding dictionaries
            labels: List of labels for each findings group (1 for vulnerability pattern,
                0 for benign pattern)
        """
        if not findings_groups or not labels or len(findings_groups) != len(labels):
            logger.error("Invalid training data for pattern recognizer")
            return

        # Extract features from findings groups
        X = []

        for findings in findings_groups:
            # Extract features from findings
            findings_features = self.extract_finding_features(findings)
            if len(findings_features) == 0:
                continue

            # Compute aggregated features for the group
            group_features = [
                np.mean(findings_features[:, 0]),  # Mean severity
                np.max(findings_features[:, 0]),  # Max severity
                np.mean(findings_features[:, 1]),  # Mean confidence
                len(findings),  # Number of findings
                np.sum(findings_features[:, 4]),  # Total CVEs
                np.mean(findings_features[:, 3]),  # Average description length
            ]
            X.append(group_features)

        if not X:
            logger.error("No valid features extracted for pattern recognizer")
            return

        # Train the model
        self.pattern_recognizer_model = RandomForestClassifier(
            n_estimators=100, random_state=42
        )
        self.pattern_recognizer_model.fit(X, labels[: len(X)])
        logger.info("Trained pattern recognizer model")

        # Save the model
        self.save_models()

    def learn_from_bug_bounty_reports(self, reports: List[Dict]) -> None:
        """
        Learn from bug bounty reports to improve pattern recognition.

        Args:
            reports: List of bug bounty report dictionaries
        """
        if not reports:
            logger.warning("No bug bounty reports provided for learning")
            return

        findings_groups = []
        labels = []

        for report in reports:
            # Extract findings from the report
            findings = report.get("findings", [])
            if not findings:
                continue

            # Extract features
            severity = report.get("severity", "medium")
            severity_val = self._normalize_severity(severity)

            # Determine if this is a vulnerability pattern (higher severity = more likely)
            is_vulnerability = 1 if severity_val >= 0.5 else 0

            findings_groups.append(findings)
            labels.append(is_vulnerability)

        # Train the pattern recognizer with these findings
        self.train_pattern_recognizer(findings_groups, labels)

    def select_tools(self, target: str) -> List[str]:
        """
        Select the most appropriate tools for a given target.

        Args:
            target: The target domain or IP address

        Returns:
            List of recommended tools
        """
        # Extract features from target
        features = self.extract_target_features(target)

        # If tool selector is not trained, use heuristics
        if self.tool_selector_model is None:
            return self._select_tools_heuristic(target)

        try:
            # Predict the best tool based on the model
            tool_code = self.tool_selector_model.predict([features])[0]

            # Get probabilities for all tools
            probabilities = self.tool_selector_model.predict_proba([features])[0]
            sorted_indices = np.argsort(probabilities)[::-1]  # Sort in descending order

            # Map tool codes back to tool names
            tool_map = {
                1: "nmap",
                2: "zap",
                3: "wappalyzer",
                4: "dirsearch",
                5: "sublist3r",
                6: "manual",
            }

            # Select top 3 tools
            selected_tools = []
            for idx in sorted_indices[:3]:
                if (
                    idx < len(tool_map) and probabilities[idx] > 0.1
                ):  # Only add if probability > 10%
                    selected_tools.append(tool_map.get(idx + 1, "unknown"))

            # Always ensure at least one tool is selected
            if not selected_tools:
                selected_tools.append(tool_map.get(tool_code, "nmap"))

            return selected_tools

        except Exception as e:
            logger.error(f"Error selecting tools with model: {e}")
            return self._select_tools_heuristic(target)

    def _select_tools_heuristic(self, target: Union[str, Dict[str, Any]]) -> List[str]:
        """
        Select tools based on heuristics when no model is available.

        Args:
            target: Target string or dictionary

        Returns:
            List of recommended tools
        """
        selected_tools = []

        # Convert string target to dictionary if needed
        if isinstance(target, str):
            is_ip = self._is_ip_address(target)
            target_dict = {"host": target, "is_ip": is_ip}
        else:
            target_dict = target
            is_ip = self._is_ip_address(target_dict.get("host", ""))

        # For IP addresses
        if is_ip or target_dict.get("is_ip", False):
            selected_tools.append("nmap")  # Always use nmap for IPs

            # Only add ZAP for web-related protocols/ports
            protocol = target_dict.get("protocol", "").lower()
            port = target_dict.get("port", 0)
            web_port = port in [80, 443, 8080, 8443]
            web_protocol = protocol in ["http", "https"]

            # If it's a public IP with web services, also use ZAP
            if (not target_dict.get("is_private", False)) and (
                web_port or web_protocol
            ):
                selected_tools.append("zap")

        # For domains
        else:
            # For all domains, check technology stack
            selected_tools.append("wappalyzer")

            # For all domains, check subdomains
            selected_tools.append("sublist3r")

            # If domain might have a web interface
            has_web = target_dict.get("protocol", "").lower() in ["http", "https"]
            if has_web or any(
                s in ["http", "https"] for s in target_dict.get("services", [])
            ):
                selected_tools.append("dirsearch")
                selected_tools.append("zap")

        return selected_tools

    def recognize_patterns(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Recognize vulnerability patterns in findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary with pattern recognition results
        """
        if not findings:
            return {"patterns": [], "probability": 0.0}

        # Extract features from findings
        findings_features = self.extract_finding_features(findings)

        if len(findings_features) == 0:
            return {"patterns": [], "probability": 0.0}

        # Compute aggregated features
        group_features = [
            np.mean(findings_features[:, 0]),  # Mean severity
            np.max(findings_features[:, 0]),  # Max severity
            np.mean(findings_features[:, 1]),  # Mean confidence
            len(findings),  # Number of findings
            np.sum(findings_features[:, 4]),  # Total CVEs
            np.mean(findings_features[:, 3]),  # Average description length
        ]

        # If pattern recognizer is not trained, use heuristics
        if self.pattern_recognizer_model is None:
            return self._recognize_patterns_heuristic(findings, group_features)

        try:
            # Predict if this is a vulnerability pattern
            probability = self.pattern_recognizer_model.predict_proba([group_features])[
                0
            ][1]

            # Identify specific patterns if probability is high enough
            patterns = []
            if probability > 0.5:
                patterns = self._identify_specific_patterns(findings)

            return {"probability": float(probability), "patterns": patterns}

        except Exception as e:
            logger.error(f"Error recognizing patterns with model: {e}")
            return self._recognize_patterns_heuristic(findings, group_features)

    def _recognize_patterns_heuristic(
        self, findings: List[Dict], features
    ) -> Dict[str, Any]:
        """
        Recognize patterns using heuristics when no model is available.

        Args:
            findings: List of finding dictionaries
            features: Aggregated features

        Returns:
            Dictionary with pattern recognition results
        """
        # Check for high severity findings
        mean_severity = features[0]
        max_severity = features[1]
        num_findings = features[3]

        # Basic probability estimate based on severity and number of findings
        probability = (
            (mean_severity * 0.3) + (max_severity * 0.5) + (min(num_findings / 10, 0.2))
        )

        # Identify specific patterns
        patterns = self._identify_specific_patterns(findings)

        return {"probability": float(probability), "patterns": patterns}

    def _identify_specific_patterns(self, findings: List[Dict]) -> List[Dict]:
        """
        Identify specific vulnerability patterns in findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of identified patterns
        """
        patterns = []

        # Check for SQL injection pattern
        sql_injection_findings = [
            f for f in findings if "sql injection" in f.get("description", "").lower()
        ]
        if sql_injection_findings:
            patterns.append(
                {
                    "name": "SQL Injection",
                    "confidence": len(sql_injection_findings) / len(findings),
                    "findings": [f.get("id", "") for f in sql_injection_findings],
                }
            )

        # Check for XSS pattern
        xss_findings = [
            f
            for f in findings
            if "cross-site scripting" in f.get("description", "").lower()
            or "xss" in f.get("description", "").lower()
        ]
        if xss_findings:
            patterns.append(
                {
                    "name": "Cross-Site Scripting (XSS)",
                    "confidence": len(xss_findings) / len(findings),
                    "findings": [f.get("id", "") for f in xss_findings],
                }
            )

        # Check for authentication bypass pattern
        auth_findings = [
            f
            for f in findings
            if "authentication" in f.get("description", "").lower()
            or "auth bypass" in f.get("description", "").lower()
        ]
        if auth_findings:
            patterns.append(
                {
                    "name": "Authentication Bypass",
                    "confidence": len(auth_findings) / len(findings),
                    "findings": [f.get("id", "") for f in auth_findings],
                }
            )

        # Check for information disclosure pattern
        info_findings = [
            f
            for f in findings
            if "information disclosure" in f.get("description", "").lower()
            or "sensitive data" in f.get("description", "").lower()
        ]
        if info_findings:
            patterns.append(
                {
                    "name": "Information Disclosure",
                    "confidence": len(info_findings) / len(findings),
                    "findings": [f.get("id", "") for f in info_findings],
                }
            )

        # Check for outdated software pattern
        outdated_findings = [
            f
            for f in findings
            if "outdated" in f.get("description", "").lower()
            or "vulnerable version" in f.get("description", "").lower()
        ]
        if outdated_findings:
            patterns.append(
                {
                    "name": "Outdated Software",
                    "confidence": len(outdated_findings) / len(findings),
                    "findings": [f.get("id", "") for f in outdated_findings],
                }
            )

        return patterns

    def adapt_similar_case(
        self, target: str, similar_cases: List[Dict]
    ) -> Dict[str, Any]:
        """
        Adapt similar cases to the current target for improved reconnaissance.

        Args:
            target: The target domain or IP address
            similar_cases: List of similar case dictionaries with targets and findings

        Returns:
            Dictionary with adaptation recommendations
        """
        if not similar_cases:
            return {
                "recommended_tools": self.select_tools(target),
                "expected_patterns": [],
                "confidence": 0.0,
            }

        # Extract features from the current target
        target_features = self.extract_target_features(target)

        # Compute similarity scores with each case
        similarities = []
        for case in similar_cases:
            case_target = case.get("target", "")
            if not case_target:
                continue

            case_features = self.extract_target_features(case_target)

            # Calculate feature similarity (simple overlap for now)
            similarity = 0
            overlap_count = 0

            for key in target_features:
                if key in case_features:
                    overlap_count += 1
                    if target_features[key] == case_features[key]:
                        similarity += 1

            if overlap_count > 0:
                similarity = similarity / overlap_count

            similarities.append({"case": case, "score": similarity})

        # Sort by similarity score
        similarities.sort(key=lambda x: x["score"], reverse=True)

        # If no similar cases, fall back to regular tool selection
        if not similarities:
            return {
                "recommended_tools": self.select_tools(target),
                "expected_patterns": [],
                "confidence": 0.0,
            }

        # Extract tools and findings from the most similar case
        most_similar = similarities[0]
        case = most_similar["case"]
        similarity_score = most_similar["score"]

        effective_tools = case.get("effective_tools", [])
        if not effective_tools:
            effective_tools = self.select_tools(target)

        patterns = []
        case_findings = case.get("findings", [])
        if case_findings:
            pattern_results = self.recognize_patterns(case_findings)
            patterns = pattern_results.get("patterns", [])

        return {
            "recommended_tools": effective_tools,
            "expected_patterns": patterns,
            "confidence": similarity_score,
            "similar_target": case.get("target", ""),
        }

    def optimize_scan_strategy(
        self, target: str, previous_findings: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Optimize scan strategy based on target and previous findings.

        Args:
            target: The target domain or IP address
            previous_findings: Optional list of previous findings

        Returns:
            Dictionary with optimization recommendations
        """
        # Get recommended tools
        recommended_tools = self.select_tools(target)

        # Default scan parameters
        scan_params = {
            "nmap": {"port_range": "1-1000", "scan_type": "SYN"},
            "zap": {"spider_depth": 3, "ajax_spider": True, "active_scan": True},
            "dirsearch": {"wordlist": "medium", "extensions": "php,html,js"},
            "sublist3r": {"threads": 5, "engines": "all"},
            "wappalyzer": {"timeout": 30},
        }

        # Convert to dictionary if string
        if isinstance(target, str):
            is_ip = self._is_ip_address(target)
            target_dict = {"host": target, "is_ip": is_ip}
        else:
            # Target is already a dictionary
            target_dict = target
            is_ip = self._is_ip_address(target_dict.get("host", ""))

        # Determine scan depth based on target
        scan_depth = "deep"

        # For IP targets
        if is_ip:
            # Deep scan for private IPs, standard for public
            if not self._is_private_ip(target_dict.get("host", "")):
                scan_depth = "standard"

            # Adjust nmap scan parameters for IP ranges
            if "-" in target_dict.get("host", "") or "/" in target_dict.get("host", ""):
                scan_params["nmap"]["port_range"] = "20-25,53,80,443,3306,8080"
                scan_params["nmap"]["scan_type"] = "SYN"

        # For web targets
        else:
            protocol = target_dict.get("protocol", "").lower()
            if protocol == "https":
                # HTTPS sites get deeper scans by default
                scan_depth = "deep"
                scan_params["zap"]["spider_depth"] = 5
            else:
                scan_depth = "standard"

            # Adjust directory scanning based on server type if known
            server_type = target_dict.get("server", "").lower()
            if "apache" in server_type:
                scan_params["dirsearch"]["extensions"] += ",txt,bak,old"
            elif "nginx" in server_type:
                scan_params["dirsearch"]["extensions"] += ",conf,json"
            elif "iis" in server_type:
                scan_params["dirsearch"]["extensions"] += ",asp,aspx,config"

        # Build optimization strategy
        strategy = {
            "tools": recommended_tools,
            "scan_depth": scan_depth,
            "scan_params": scan_params,
        }

        # Optimize based on previous findings if available
        if previous_findings:
            # Extract useful paths from previous findings
            priority_paths = []
            vulnerability_types = []

            for finding in previous_findings:
                # Extract paths from URLs if available
                url = finding.get("url", "")
                if url:
                    try:
                        path = urlparse(url).path
                        if path and path not in priority_paths:
                            priority_paths.append(path)
                    except Exception:
                        pass

                # Track vulnerability types
                vuln_type = finding.get("type", "").lower()
                if vuln_type and vuln_type not in vulnerability_types:
                    vulnerability_types.append(vuln_type)

            strategy["priority_paths"] = priority_paths

            # Allocate time to tools based on previous findings
            time_allocation = {}

            if "xss" in vulnerability_types or "sqli" in vulnerability_types:
                # Web vulnerabilities - focus on zap
                time_allocation["zap"] = 50
                time_allocation["dirsearch"] = 30
                time_allocation["wappalyzer"] = 10
                time_allocation["nmap"] = 10
            elif any(t in vulnerability_types for t in ["port", "service", "banner"]):
                # Infrastructure vulnerabilities - focus on nmap
                time_allocation["nmap"] = 50
                time_allocation["zap"] = 30
                time_allocation["wappalyzer"] = 10
                time_allocation["dirsearch"] = 10
            else:
                # Balanced allocation
                time_allocation["zap"] = 40
                time_allocation["nmap"] = 25
                time_allocation["dirsearch"] = 20
                time_allocation["wappalyzer"] = 15

            strategy["time_allocation"] = time_allocation

        return strategy

    def generate_statistics(self, findings_history: List[Dict]) -> Dict[str, Any]:
        """
        Generate statistics about findings and tool effectiveness.

        Args:
            findings_history: List of finding history dictionaries with target, tools, and findings

        Returns:
            Dictionary with statistics
        """
        if not findings_history:
            return {"message": "No history available for statistics"}

        # Initialize statistics
        stats = {
            "total_targets": len(findings_history),
            "total_findings": 0,
            "findings_by_severity": {
                "info": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            },
            "tool_effectiveness": {
                "nmap": {"findings": 0, "targets": 0},
                "zap": {"findings": 0, "targets": 0},
                "wappalyzer": {"findings": 0, "targets": 0},
                "dirsearch": {"findings": 0, "targets": 0},
                "sublist3r": {"findings": 0, "targets": 0},
            },
            "common_vulnerabilities": {},
        }

        # Process each historical record
        for history in findings_history:
            findings = history.get("findings", [])
            tools_used = history.get("tools_used", [])

            # Update findings count
            stats["total_findings"] += len(findings)

            # Update tools used
            for tool in tools_used:
                if tool in stats["tool_effectiveness"]:
                    stats["tool_effectiveness"][tool]["targets"] += 1

            # Process each finding
            for finding in findings:
                severity = finding.get("severity", "low").lower()
                source = finding.get("source", "unknown").lower()
                description = finding.get("description", "")

                # Update findings by severity
                if severity in stats["findings_by_severity"]:
                    stats["findings_by_severity"][severity] += 1

                # Update tool effectiveness
                if source in stats["tool_effectiveness"]:
                    stats["tool_effectiveness"][source]["findings"] += 1

                # Update common vulnerabilities
                vuln_type = self._extract_vulnerability_type(description)
                if vuln_type:
                    if vuln_type not in stats["common_vulnerabilities"]:
                        stats["common_vulnerabilities"][vuln_type] = 0
                    stats["common_vulnerabilities"][vuln_type] += 1

        # Calculate effectiveness ratios
        for tool, data in stats["tool_effectiveness"].items():
            targets = data["targets"]
            findings = data["findings"]

            if targets > 0:
                data["findings_per_target"] = findings / targets
            else:
                data["findings_per_target"] = 0

        # Sort common vulnerabilities by frequency
        stats["common_vulnerabilities"] = dict(
            sorted(
                stats["common_vulnerabilities"].items(),
                key=lambda item: item[1],
                reverse=True,
            )[:10]
        )

        return stats

    def _extract_vulnerability_type(self, description: str) -> Optional[str]:
        """
        Extract vulnerability type from description.

        Args:
            description: Finding description

        Returns:
            Vulnerability type or None
        """
        # Common vulnerability types to check for
        vuln_types = [
            "SQL Injection",
            "Cross-Site Scripting",
            "Cross-Site Request Forgery",
            "Remote Code Execution",
            "Information Disclosure",
            "Authentication Bypass",
            "Server-Side Request Forgery",
            "XML External Entity",
            "Directory Traversal",
            "Insecure Deserialization",
            "Security Misconfiguration",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "Insufficient Logging",
            "Race Condition",
        ]

        description_lower = description.lower()

        for vuln_type in vuln_types:
            if vuln_type.lower() in description_lower:
                return vuln_type

        # Check for CVE
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", description)
        if cve_match:
            return cve_match.group(0)

        return None

    def load_available_tools(self) -> List[Dict[str, Any]]:
        """
        Load all available tools and their metadata for recommendations.

        Returns:
            List of tool dictionaries with metadata
        """
        # This would typically load from a database or configuration file
        # For now, we'll hardcode a representative set of tools

        available_tools = [
            # Existing reconnaissance tools
            {
                "name": "nmap",
                "category": "reconnaissance",
                "description": "Network port scanner",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["ip", "domain", "network"],
                "output_formats": ["xml", "json", "text"],
            },
            {
                "name": "whois",
                "category": "reconnaissance",
                "description": "Domain registration information lookup",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            {
                "name": "dig",
                "category": "reconnaissance",
                "description": "DNS lookup utility",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            {
                "name": "sublist3r",
                "category": "reconnaissance",
                "description": "Subdomain enumeration tool",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            {
                "name": "amass",
                "category": "reconnaissance",
                "description": "In-depth subdomain enumeration",
                "execution_time": "slow",
                "thoroughness": "high",
                "target_types": ["domain"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "subfinder",
                "category": "reconnaissance",
                "description": "Fast subdomain discovery tool",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["domain"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "wappalyzer",
                "category": "reconnaissance",
                "description": "Web technology fingerprinting",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["json"],
            },
            {
                "name": "whatweb",
                "category": "reconnaissance",
                "description": "Web scanner to identify technologies",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "gobuster",
                "category": "reconnaissance",
                "description": "Directory/file & DNS busting tool",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["url", "webapp", "domain"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "ffuf",
                "category": "reconnaissance",
                "description": "Fast web fuzzer",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "shodan",
                "category": "reconnaissance",
                "description": "Search engine for Internet-connected devices",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["ip", "domain"],
                "output_formats": ["json"],
            },
            {
                "name": "censys",
                "category": "reconnaissance",
                "description": "Search engine for Internet-connected devices and certificates",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["ip", "domain"],
                "output_formats": ["json"],
            },
            {
                "name": "ripe",
                "category": "reconnaissance",
                "description": "Regional Internet registry database lookup",
                "execution_time": "fast",
                "thoroughness": "low",
                "target_types": ["ip", "asn"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "swagger-scan",
                "category": "reconnaissance",
                "description": "API documentation scanner",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["api", "url"],
                "output_formats": ["json"],
            },
            {
                "name": "nuclei",
                "category": "vulnerability_scanning",
                "description": "Template-based vulnerability scanner",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["ip", "domain", "url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "nikto",
                "category": "vulnerability_scanning",
                "description": "Web server scanner",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["xml", "json", "text"],
            },
            {
                "name": "zap",
                "category": "vulnerability_scanning",
                "description": "OWASP Zed Attack Proxy for web app scanning",
                "execution_time": "slow",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["xml", "json", "html"],
            },
            {
                "name": "burp-scanner",
                "category": "vulnerability_scanning",
                "description": "Burp Suite Professional scanner",
                "execution_time": "slow",
                "thoroughness": "high",
                "target_types": ["url", "webapp", "api"],
                "output_formats": ["xml", "html"],
            },
            {
                "name": "sqlmap",
                "category": "vulnerability_scanning",
                "description": "Automated SQL injection detection and exploitation",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "xsstrike",
                "category": "vulnerability_scanning",
                "description": "Advanced XSS detection suite",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "hydra",
                "category": "vulnerability_scanning",
                "description": "Online password cracking tool",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["service", "webapp"],
                "output_formats": ["text"],
            },
            {
                "name": "medusa",
                "category": "vulnerability_scanning",
                "description": "Parallel login brute-forcer",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["service"],
                "output_formats": ["text"],
            },
            {
                "name": "patator",
                "category": "vulnerability_scanning",
                "description": "Multi-purpose brute-forcer",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["service", "webapp"],
                "output_formats": ["text"],
            },
            {
                "name": "metasploit",
                "category": "exploitation",
                "description": "Exploitation framework",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["ip", "service", "webapp"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "burp-intruder",
                "category": "exploitation",
                "description": "Burp Suite Intruder for targeted attacks",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp", "api"],
                "output_formats": ["text", "html"],
            },
            {
                "name": "postman",
                "category": "exploitation",
                "description": "API testing tool",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["api"],
                "output_formats": ["json"],
            },
            # Additional reconnaissance tools
            {
                "name": "dnsenum",
                "category": "reconnaissance",
                "description": "DNS enumeration tool for domain analysis",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            {
                "name": "massdns",
                "category": "reconnaissance",
                "description": "High-performance DNS resolver for subdomain enumeration",
                "execution_time": "fast",
                "thoroughness": "high",
                "target_types": ["domain"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "masscan",
                "category": "reconnaissance",
                "description": "Fast port scanner for large IP ranges",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["ip", "network"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "waybackurls",
                "category": "reconnaissance",
                "description": "Fetch URLs from Wayback Machine for a domain",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            {
                "name": "gau",
                "category": "reconnaissance",
                "description": "Get All URLs from multiple sources",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["domain"],
                "output_formats": ["text"],
            },
            # Additional vulnerability scanning tools
            {
                "name": "sslscan",
                "category": "vulnerability_scanning",
                "description": "SSL/TLS scanner for checking configurations and vulnerabilities",
                "execution_time": "fast",
                "thoroughness": "high",
                "target_types": ["ip", "domain"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "wpscan",
                "category": "vulnerability_scanning",
                "description": "WordPress vulnerability scanner",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["json", "text"],
            },
            {
                "name": "droopescan",
                "category": "vulnerability_scanning",
                "description": "CMS scanner (Drupal, Joomla, WordPress, etc.)",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "cmseek",
                "category": "vulnerability_scanning",
                "description": "CMS detection and exploitation tool",
                "execution_time": "medium",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["text", "json"],
            },
            # Advanced exploitation tools
            {
                "name": "commix",
                "category": "exploitation",
                "description": "Command injection exploitation tool",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "xsshunter",
                "category": "exploitation",
                "description": "XSS payload generator and discovery tool",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["text"],
            },
            {
                "name": "nosqlmap",
                "category": "exploitation",
                "description": "NoSQL database exploitation tool",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp"],
                "output_formats": ["text"],
            },
            {
                "name": "jwt_tool",
                "category": "exploitation",
                "description": "JWT testing and exploitation tool",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["url", "webapp", "api"],
                "output_formats": ["text"],
            },
            {
                "name": "ssrf-sheriff",
                "category": "exploitation",
                "description": "SSRF detection and exploitation tool",
                "execution_time": "medium",
                "thoroughness": "high",
                "target_types": ["url", "webapp", "api"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "graphql-voyager",
                "category": "exploitation",
                "description": "GraphQL API exploration and analysis tool",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["api"],
                "output_formats": ["text", "json"],
            },
            {
                "name": "crlfuzz",
                "category": "exploitation",
                "description": "CRLF injection scanner",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["text"],
            },
            {
                "name": "csrf-poc-generator",
                "category": "exploitation",
                "description": "CSRF proof-of-concept generator",
                "execution_time": "fast",
                "thoroughness": "medium",
                "target_types": ["url", "webapp"],
                "output_formats": ["html"],
            },
        ]

        return available_tools

    def recommend_tools(
        self, target: Union[str, Dict[str, Any]], context: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Recommend tools for a given target based on its features and optional context.

        Args:
            target: The target domain, IP address, or target info dictionary
            context: Optional context dict with keys like 'assessment_phase', 'assessment_type',
                    'previous_findings', and 'max_recommendations'

        Returns:
            List of dictionaries containing tool recommendations with their confidence scores,
            parameters, and reasons
        """
        # Extract features from the target
        features = self.extract_target_features(target)

        # Process context if provided
        top_n = 3  # Default value
        assessment_phase = None
        assessment_type = "standard"
        previous_findings = []

        if context:
            top_n = context.get("max_recommendations", top_n)
            assessment_phase = context.get("assessment_phase")
            assessment_type = context.get("assessment_type", assessment_type)
            previous_findings = context.get("previous_findings", previous_findings)

        # If tool selector model is not loaded, try to load it
        if not self.tool_selector_model:
            # Try to load models if they exist
            try:
                self._load_models()
            except Exception as e:
                logger.warning(f"Could not load tool selector model: {e}")
                # Continue without model, will use heuristics

        # Get tools either using the model or heuristics
        tools = self.select_tools(target)

        # Load all available tools for phase filtering and prioritization
        available_tools = self.load_available_tools()

        # Filter tools by assessment phase if specified
        phase_filtered_tools = tools
        if assessment_phase:
            phase_tools = [
                tool["name"]
                for tool in available_tools
                if assessment_phase.lower() in tool.get("phases", [])
            ]
            phase_filtered_tools = [tool for tool in tools if tool in phase_tools]

            # If no tools match the phase, fall back to original list
            if not phase_filtered_tools:
                phase_filtered_tools = tools

        # Phase-specific prioritization
        # This ensures different top recommendations for different phases
        phase_priority = {
            "reconnaissance": [
                "sublist3r",
                "nmap",
                "wappalyzer",
                "gobuster",
                "whois",
                "dig",
            ],
            "vulnerability_scanning": [
                "zap",
                "nikto",
                "wpscan",
                "testssl",
                "feroxbuster",
            ],
            "exploitation": ["sqlmap", "hydra", "metasploit", "burpsuite", "netcat"],
        }

        # If we have a specific phase, prioritize tools specifically designed for that phase
        if assessment_phase and assessment_phase in phase_priority:
            priority_order = phase_priority[assessment_phase]

            # Sort phase_filtered_tools based on the priority order
            def priority_key(tool_name):
                try:
                    # Lower index = higher priority
                    return priority_order.index(tool_name)
                except ValueError:
                    # Tools not in the priority list go last
                    return len(priority_order)

            phase_filtered_tools = sorted(phase_filtered_tools, key=priority_key)

        # Generate recommendations with confidence scores
        recommendations = []
        for i, tool_name in enumerate(phase_filtered_tools):
            # Assign confidence scores based on position in the prioritized list
            # First tool gets highest confidence, diminishing for later positions
            confidence = max(0.95 - (i * 0.1), 0.5)

            # Generate reasons for this recommendation
            reasons = self._generate_recommendation_reasons(
                tool_name, target, assessment_phase, assessment_type
            )

            # Generate recommended parameters
            params = self._generate_recommended_params(tool_name, target)

            recommendations.append(
                {
                    "tool_name": tool_name,
                    "confidence": confidence,
                    "parameters": params,
                    "reasons": reasons,
                }
            )

        # Sort by confidence score and limit to top_n
        recommendations.sort(key=lambda x: x["confidence"], reverse=True)
        return recommendations[:top_n]

    def _generate_recommendation_reasons(
        self,
        tool_name: str,
        target: Union[str, Dict[str, Any]],
        assessment_phase: Optional[str] = None,
        assessment_type: Optional[str] = None,
    ) -> List[str]:
        """
        Generate reasons for recommending a specific tool based on the target and context.

        Args:
            tool_name: Name of the tool
            target: The target information
            assessment_phase: Phase of the assessment (reconnaissance, vulnerability_scanning, exploitation)
            assessment_type: Type of assessment (quick, standard, thorough)

        Returns:
            List of reasons for recommending this tool
        """
        reasons = []

        # Convert string target to dict format if needed
        if isinstance(target, str):
            target_info = {"host": target}
        else:
            target_info = target

        hostname = target_info.get("host", "")
        is_ip = self._is_ip_address(hostname)
        protocol = target_info.get("protocol", "").lower()
        services = target_info.get("services", [])

        # Common tools
        if tool_name == "nmap":
            reasons.append("Comprehensive port and service scanning")
            if is_ip:
                reasons.append("Effective for IP-based targets")
            if assessment_phase == "reconnaissance":
                reasons.append("Essential for initial reconnaissance")

        elif tool_name == "gobuster" or tool_name == "dirsearch":
            if (
                "http" in services
                or "https" in services
                or protocol in ["http", "https"]
            ):
                reasons.append("Directory and file discovery for web applications")
                if assessment_phase == "reconnaissance":
                    reasons.append(
                        "Useful for identifying hidden directories and files"
                    )

        elif tool_name == "wpscan":
            if (
                "http" in services
                or "https" in services
                or protocol in ["http", "https"]
            ):
                reasons.append("Specialized scanner for WordPress installations")

        elif tool_name == "sqlmap":
            if (
                "http" in services
                or "https" in services
                or protocol in ["http", "https"]
            ):
                reasons.append("Automated SQL injection detection and exploitation")
                if assessment_phase == "exploitation":
                    reasons.append("Suitable for the exploitation phase")

        elif tool_name == "nikto":
            if (
                "http" in services
                or "https" in services
                or protocol in ["http", "https"]
            ):
                reasons.append("Comprehensive web server scanning")

        elif tool_name == "sublist3r":
            if not is_ip:
                reasons.append("Subdomain discovery for domain targets")
                if assessment_phase == "reconnaissance":
                    reasons.append("Essential for expanding the attack surface")

        elif tool_name == "dig" or tool_name == "whois":
            if not is_ip:
                reasons.append("Domain information gathering")

        elif tool_name == "testssl":
            if "https" in services or protocol == "https":
                reasons.append("SSL/TLS configuration and vulnerability analysis")

        elif tool_name == "hydra":
            reasons.append("Brute force authentication testing")
            if any(service in services for service in ["ssh", "ftp", "telnet"]):
                reasons.append(
                    f"Suitable for the detected services: {', '.join(services)}"
                )

        elif tool_name == "zap" or tool_name == "owasp-zap":
            if (
                "http" in services
                or "https" in services
                or protocol in ["http", "https"]
            ):
                reasons.append("Comprehensive web application security scanner")
                if assessment_type == "thorough":
                    reasons.append("Thorough scanning capabilities")

        # Add a recommendation based on assessment type if applicable
        if assessment_type == "thorough" and any(
            [
                tool_name == "nmap"
                and "--script vuln"
                in str(self._generate_recommended_params(tool_name, target)),
                tool_name in ["zap", "owasp-zap", "nikto", "sqlmap"],
            ]
        ):
            reasons.append("Well-suited for thorough assessment")
        elif assessment_type == "quick" and any(
            [
                tool_name == "nmap"
                and "-F" in str(self._generate_recommended_params(tool_name, target)),
                tool_name in ["whatweb", "wafw00f"],
            ]
        ):
            reasons.append("Fast execution time for quick assessments")

        # If no specific reasons, add a generic one
        if not reasons:
            reasons.append("General-purpose tool for security assessment")

        return reasons

    def _generate_recommended_params(
        self, tool_name: str, target: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate recommended parameters for a specific tool based on the target.

        Args:
            tool_name: Name of the tool
            target: The target information

        Returns:
            Dictionary of recommended parameters for the tool
        """
        # Convert string target to dict format if needed
        if isinstance(target, str):
            target_info = {"host": target}
        else:
            target_info = target

        # Get hostname
        hostname = target_info.get("host", "")

        # Default parameters for common tools
        if tool_name == "nmap":
            return {
                "target": hostname,
                "arguments": (
                    "-sV -sC -p-" if self._is_ip_address(hostname) else "-sV -sC"
                ),
            }
        elif tool_name == "gobuster":
            return {
                "target": f"http://{hostname}" if "://" not in hostname else hostname,
                "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "extensions": "php,html,txt",
            }
        elif tool_name == "wpscan":
            return {
                "target": f"http://{hostname}" if "://" not in hostname else hostname,
                "enumerate": "u,t,p",
            }
        elif tool_name == "sqlmap":
            return {
                "target": f"http://{hostname}" if "://" not in hostname else hostname,
                "forms": True,
                "batch": True,
            }
        elif tool_name == "nikto":
            return {
                "target": f"http://{hostname}" if "://" not in hostname else hostname
            }
        elif tool_name == "sublist3r":
            return {
                "domain": hostname.split("://")[-1] if "://" in hostname else hostname
            }
        elif tool_name == "dig":
            return {
                "domain": hostname.split("://")[-1] if "://" in hostname else hostname,
                "query_type": "ANY",
            }
        elif tool_name == "whois":
            return {
                "domain": hostname.split("://")[-1] if "://" in hostname else hostname
            }
        elif tool_name == "testssl":
            return {
                "target": f"https://{hostname}" if "://" not in hostname else hostname
            }
        elif tool_name == "hydra":
            return {
                "target": hostname,
                "service": "ssh" if target_info.get("port") == 22 else "http-post-form",
                "wordlist": "/usr/share/wordlists/rockyou.txt",
            }
        else:
            # Generic parameters for other tools
            return {"target": hostname}

    def _extract_tld(self, domain: str) -> str:
        """
        Extract the top-level domain from a domain name.

        Args:
            domain: The domain name

        Returns:
            The TLD (e.g., com, org, co.uk) or empty string if none
        """
        # Handle special cases
        if domain == "localhost" or domain.startswith("localhost."):
            return ""

        # Split by dot and take the last part
        parts = domain.split(".")
        if len(parts) > 1:
            return parts[-1]
        return ""

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate the entropy of a string.

        Args:
            s: The input string

        Returns:
            The entropy of the string
        """
        # Calculate the frequency of each character
        freq = {c: s.count(c) / len(s) for c in set(s)}

        # Calculate the entropy using the formula: -sum(p * log2(p))
        entropy = -sum(p * math.log2(p) for p in freq.values())

        return entropy
