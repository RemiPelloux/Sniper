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

import os
import re
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List, Dict, Tuple, Union, Optional, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib
import logging
from ipaddress import ip_address

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
        self.tool_selector = None
        self.pattern_recognizer = None
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.scaler = StandardScaler()
        
        # Tool efficiency metrics
        self.tool_efficiency = {
            "nmap": {"speed": 0.7, "accuracy": 0.9, "resource_usage": 0.6},
            "zap": {"speed": 0.5, "accuracy": 0.85, "resource_usage": 0.8},
            "wappalyzer": {"speed": 0.9, "accuracy": 0.75, "resource_usage": 0.3},
            "dirsearch": {"speed": 0.6, "accuracy": 0.8, "resource_usage": 0.5},
            "sublist3r": {"speed": 0.8, "accuracy": 0.7, "resource_usage": 0.4}
        }
        
        # Load models if they exist
        self._load_models()
        
    def _load_models(self):
        """Load trained models if they exist."""
        tool_selector_path = os.path.join(self.model_dir, "tool_selector.joblib")
        pattern_recognizer_path = os.path.join(self.model_dir, "pattern_recognizer.joblib")
        
        if os.path.exists(tool_selector_path):
            try:
                self.tool_selector = joblib.load(tool_selector_path)
                logger.info("Loaded tool selector model")
            except Exception as e:
                logger.error(f"Error loading tool selector model: {e}")
                
        if os.path.exists(pattern_recognizer_path):
            try:
                self.pattern_recognizer = joblib.load(pattern_recognizer_path)
                logger.info("Loaded pattern recognizer model")
            except Exception as e:
                logger.error(f"Error loading pattern recognizer model: {e}")
    
    def save_models(self):
        """Save trained models to disk."""
        if self.tool_selector:
            tool_selector_path = os.path.join(self.model_dir, "tool_selector.joblib")
            joblib.dump(self.tool_selector, tool_selector_path)
            logger.info(f"Saved tool selector model to {tool_selector_path}")
            
        if self.pattern_recognizer:
            pattern_recognizer_path = os.path.join(self.model_dir, "pattern_recognizer.joblib")
            joblib.dump(self.pattern_recognizer, pattern_recognizer_path)
            logger.info(f"Saved pattern recognizer model to {pattern_recognizer_path}")
    
    def extract_target_features(self, target: str) -> Dict[str, Any]:
        """
        Extract features from a target for use in tool selection.
        
        Args:
            target: The target domain or IP address
            
        Returns:
            Dictionary of features extracted from the target
        """
        features = {}
        
        # Check if target is an IP or domain
        is_ip = self._is_ip_address(target)
        features["is_ip"] = 1 if is_ip else 0
        
        if is_ip:
            # Extract IP-specific features
            ip = ip_address(target)
            features["is_private"] = 1 if ip.is_private else 0
            features["is_global"] = 1 if ip.is_global else 0
            features["is_multicast"] = 1 if ip.is_multicast else 0
            features["ip_version"] = ip.version
        else:
            # Extract domain-specific features
            domain_parts = target.split(".")
            features["is_subdomain"] = 1 if len(domain_parts) > 2 else 0
            features["domain_length"] = len(target)
            features["num_segments"] = len(domain_parts)
            features["tld"] = domain_parts[-1]
            
            # Check for keywords in domain that might indicate purpose
            keywords = ["api", "dev", "test", "staging", "prod", "admin", "secure", "login"]
            for keyword in keywords:
                features[f"has_{keyword}"] = 1 if keyword in target.lower() else 0
        
        return features
    
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
                has_url
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
            "critical": 1.0
        }
        return severity_map.get(severity.lower(), 0.25)
    
    def _normalize_confidence(self, confidence: str) -> float:
        """Convert confidence string to numerical value."""
        confidence_map = {
            "low": 0.25,
            "medium": 0.5,
            "high": 0.75,
            "confirmed": 1.0
        }
        return confidence_map.get(confidence.lower(), 0.5)
    
    def _encode_tool(self, tool: str) -> int:
        """Encode tool name to numerical value."""
        tool_map = {
            "nmap": 1,
            "zap": 2,
            "wappalyzer": 3,
            "dirsearch": 4,
            "sublist3r": 5,
            "manual": 6
        }
        return tool_map.get(tool.lower(), 0)
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address."""
        try:
            ip_address(target)
            return True
        except ValueError:
            return False
    
    def train_tool_selector(self, targets: List[str], tool_effectiveness: List[Dict]) -> None:
        """
        Train the tool selector model based on past scans.
        
        Args:
            targets: List of targets (domains/IPs) that were scanned
            tool_effectiveness: List of dictionaries with tool effectiveness metrics
                for each target
        """
        if not targets or not tool_effectiveness or len(targets) != len(tool_effectiveness):
            logger.error("Invalid training data for tool selector")
            return
            
        # Extract features from targets
        X = []
        y = []
        
        for idx, target in enumerate(targets):
            # Extract target features
            target_features = list(self.extract_target_features(target).values())
            X.append(target_features)
            
            # Get the most effective tool for this target
            effectiveness = tool_effectiveness[idx]
            best_tool = max(effectiveness.items(), key=lambda x: x[1])
            y.append(self._encode_tool(best_tool[0]))
        
        # Train the model
        self.tool_selector = RandomForestClassifier(n_estimators=100, random_state=42)
        self.tool_selector.fit(X, y)
        logger.info("Trained tool selector model")
        
        # Save the model
        self.save_models()
    
    def train_pattern_recognizer(self, findings_groups: List[List[Dict]], labels: List[int]) -> None:
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
                np.max(findings_features[:, 0]),   # Max severity
                np.mean(findings_features[:, 1]),  # Mean confidence
                len(findings),                     # Number of findings
                np.sum(findings_features[:, 4]),   # Total CVEs
                np.mean(findings_features[:, 3])   # Average description length
            ]
            X.append(group_features)
        
        if not X:
            logger.error("No valid features extracted for pattern recognizer")
            return
            
        # Train the model
        self.pattern_recognizer = RandomForestClassifier(n_estimators=100, random_state=42)
        self.pattern_recognizer.fit(X, labels[:len(X)])
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
        feature_values = list(features.values())
        
        # If tool selector is not trained, use heuristics
        if self.tool_selector is None:
            return self._select_tools_heuristic(features)
        
        try:
            # Predict the best tool based on the model
            tool_code = self.tool_selector.predict([feature_values])[0]
            
            # Get probabilities for all tools
            probabilities = self.tool_selector.predict_proba([feature_values])[0]
            sorted_indices = np.argsort(probabilities)[::-1]  # Sort in descending order
            
            # Map tool codes back to tool names
            tool_map = {
                1: "nmap",
                2: "zap",
                3: "wappalyzer", 
                4: "dirsearch",
                5: "sublist3r",
                6: "manual"
            }
            
            # Select top 3 tools
            selected_tools = []
            for idx in sorted_indices[:3]:
                if idx < len(tool_map) and probabilities[idx] > 0.1:  # Only add if probability > 10%
                    selected_tools.append(tool_map.get(idx + 1, "unknown"))
            
            # Always ensure at least one tool is selected
            if not selected_tools:
                selected_tools.append(tool_map.get(tool_code, "nmap"))
                
            return selected_tools
            
        except Exception as e:
            logger.error(f"Error selecting tools with model: {e}")
            return self._select_tools_heuristic(features)
    
    def _select_tools_heuristic(self, features: Dict[str, Any]) -> List[str]:
        """
        Select tools based on heuristics when no model is available.
        
        Args:
            features: Target features dictionary
            
        Returns:
            List of recommended tools
        """
        selected_tools = []
        
        # For IP addresses
        if features.get("is_ip", 0) == 1:
            selected_tools.append("nmap")  # Always use nmap for IPs
            
            # If it's a public IP, also use ZAP
            if features.get("is_private", 0) == 0:
                selected_tools.append("zap")
        
        # For domains
        else:
            # For all domains, check technology stack
            selected_tools.append("wappalyzer")
            
            # For all domains, check subdomains
            selected_tools.append("sublist3r")
            
            # If domain might have a web interface
            if "api" not in features and "has_admin" in features:
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
            np.max(findings_features[:, 0]),   # Max severity
            np.mean(findings_features[:, 1]),  # Mean confidence
            len(findings),                     # Number of findings
            np.sum(findings_features[:, 4]),   # Total CVEs
            np.mean(findings_features[:, 3])   # Average description length
        ]
        
        # If pattern recognizer is not trained, use heuristics
        if self.pattern_recognizer is None:
            return self._recognize_patterns_heuristic(findings, group_features)
        
        try:
            # Predict if this is a vulnerability pattern
            probability = self.pattern_recognizer.predict_proba([group_features])[0][1]
            
            # Identify specific patterns if probability is high enough
            patterns = []
            if probability > 0.5:
                patterns = self._identify_specific_patterns(findings)
                
            return {
                "probability": float(probability),
                "patterns": patterns
            }
            
        except Exception as e:
            logger.error(f"Error recognizing patterns with model: {e}")
            return self._recognize_patterns_heuristic(findings, group_features)
    
    def _recognize_patterns_heuristic(self, findings: List[Dict], features) -> Dict[str, Any]:
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
        probability = (mean_severity * 0.3) + (max_severity * 0.5) + (min(num_findings / 10, 0.2))
        
        # Identify specific patterns
        patterns = self._identify_specific_patterns(findings)
        
        return {
            "probability": float(probability),
            "patterns": patterns
        }
    
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
        sql_injection_findings = [f for f in findings if "sql injection" in f.get("description", "").lower()]
        if sql_injection_findings:
            patterns.append({
                "name": "SQL Injection",
                "confidence": len(sql_injection_findings) / len(findings),
                "findings": [f.get("id", "") for f in sql_injection_findings]
            })
        
        # Check for XSS pattern
        xss_findings = [f for f in findings if "cross-site scripting" in f.get("description", "").lower() 
                        or "xss" in f.get("description", "").lower()]
        if xss_findings:
            patterns.append({
                "name": "Cross-Site Scripting (XSS)",
                "confidence": len(xss_findings) / len(findings),
                "findings": [f.get("id", "") for f in xss_findings]
            })
        
        # Check for authentication bypass pattern
        auth_findings = [f for f in findings if "authentication" in f.get("description", "").lower() 
                         or "auth bypass" in f.get("description", "").lower()]
        if auth_findings:
            patterns.append({
                "name": "Authentication Bypass",
                "confidence": len(auth_findings) / len(findings),
                "findings": [f.get("id", "") for f in auth_findings]
            })
        
        # Check for information disclosure pattern
        info_findings = [f for f in findings if "information disclosure" in f.get("description", "").lower() 
                         or "sensitive data" in f.get("description", "").lower()]
        if info_findings:
            patterns.append({
                "name": "Information Disclosure",
                "confidence": len(info_findings) / len(findings),
                "findings": [f.get("id", "") for f in info_findings]
            })
        
        # Check for outdated software pattern
        outdated_findings = [f for f in findings if "outdated" in f.get("description", "").lower() 
                            or "vulnerable version" in f.get("description", "").lower()]
        if outdated_findings:
            patterns.append({
                "name": "Outdated Software",
                "confidence": len(outdated_findings) / len(findings),
                "findings": [f.get("id", "") for f in outdated_findings]
            })
        
        return patterns
    
    def adapt_similar_case(self, target: str, similar_cases: List[Dict]) -> Dict[str, Any]:
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
                "confidence": 0.0
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
            
            similarities.append({
                "case": case,
                "score": similarity
            })
        
        # Sort by similarity score
        similarities.sort(key=lambda x: x["score"], reverse=True)
        
        # If no similar cases, fall back to regular tool selection
        if not similarities:
            return {
                "recommended_tools": self.select_tools(target),
                "expected_patterns": [],
                "confidence": 0.0
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
            "similar_target": case.get("target", "")
        }
    
    def optimize_scan_strategy(self, target: str, previous_findings: List[Dict] = None) -> Dict[str, Any]:
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
            "wappalyzer": {"timeout": 30}
        }
        
        # Optimizations based on target features
        target_features = self.extract_target_features(target)
        
        # For IP targets
        if target_features.get("is_ip", 0) == 1:
            # Expand port range for nmap
            scan_params["nmap"]["port_range"] = "1-65535"
            
            # If private IP, adjust parameters
            if target_features.get("is_private", 0) == 1:
                scan_params["nmap"]["scan_type"] = "TCP Connect"
        
        # For domain targets
        else:
            # If likely a large domain (many segments)
            if target_features.get("num_segments", 0) > 3:
                scan_params["dirsearch"]["wordlist"] = "large"
                scan_params["sublist3r"]["threads"] = 10
            
            # If likely a development domain
            if target_features.get("has_dev", 0) == 1 or target_features.get("has_test", 0) == 1:
                scan_params["zap"]["spider_depth"] = 5
                scan_params["dirsearch"]["extensions"] = "php,html,js,bak,txt,sql,zip"
        
        # Further optimization based on previous findings
        if previous_findings:
            # Analyze previous findings
            pattern_results = self.recognize_patterns(previous_findings)
            patterns = pattern_results.get("patterns", [])
            
            # Adjust scan based on patterns
            for pattern in patterns:
                pattern_name = pattern.get("name", "")
                
                if "SQL Injection" in pattern_name:
                    # Focus on web parameters
                    scan_params["zap"]["active_scan"] = True
                    scan_params["zap"]["scan_policy"] = "sql-injection"
                
                elif "Cross-Site Scripting" in pattern_name:
                    # Focus on XSS vulnerabilities
                    scan_params["zap"]["active_scan"] = True
                    scan_params["zap"]["scan_policy"] = "xss"
                
                elif "Authentication Bypass" in pattern_name:
                    # Focus on auth endpoints
                    scan_params["dirsearch"]["wordlist"] = "auth-focused"
                    scan_params["dirsearch"]["extensions"] = "php,jsp,asp,aspx"
                
                elif "Information Disclosure" in pattern_name:
                    # Look for sensitive files
                    scan_params["dirsearch"]["wordlist"] = "sensitive-files"
                    scan_params["dirsearch"]["extensions"] = "bak,old,txt,sql,conf,config,xml"
        
        return {
            "recommended_tools": recommended_tools,
            "scan_parameters": {tool: params for tool, params in scan_params.items() if tool in recommended_tools},
            "priority": "high" if previous_findings and len(previous_findings) > 5 else "medium"
        }
    
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
                "critical": 0
            },
            "tool_effectiveness": {
                "nmap": {"findings": 0, "targets": 0},
                "zap": {"findings": 0, "targets": 0},
                "wappalyzer": {"findings": 0, "targets": 0},
                "dirsearch": {"findings": 0, "targets": 0},
                "sublist3r": {"findings": 0, "targets": 0}
            },
            "common_vulnerabilities": {}
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
            sorted(stats["common_vulnerabilities"].items(), 
                   key=lambda item: item[1], 
                   reverse=True)[:10]
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
            "Race Condition"
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