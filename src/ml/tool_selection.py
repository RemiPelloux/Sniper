"""
Tool Selection ML Module for Sniper.

This module provides machine learning capabilities for intelligent
selection of security tools based on target characteristics, previous scan results,
and historical performance data.

Features:
- Smart reconnaissance tool selection based on target type
- Automated decision making for which tools to use in different scenarios
- Learning from previous scan results to optimize future scans
- Performance tracking of tools across different target types
- Recommendations for scan depth and tool configuration

Dependencies:
- numpy
- pandas
- scikit-learn
- joblib

Usage:
    from src.ml.tool_selection import ToolSelector

    # Initialize the tool selector
    selector = ToolSelector()

    # Get recommended tools for a target
    recommended_tools = selector.recommend_tools(target_info)
"""

import json
import logging
import math
import os
import re
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Set up logging
logger = logging.getLogger(__name__)


class ToolSelector:
    """
    ToolSelector class provides machine learning capabilities for intelligent
    selection of security tools based on target characteristics.
    """

    def __init__(self, model_dir: str = None, performance_history_size: int = 1000):
        """
        Initialize the ToolSelector class.

        Args:
            model_dir: Directory to store trained models
            performance_history_size: Maximum number of historical performance records to keep
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)

        # Tool categories and their respective tools
        self.tool_categories = {
            "reconnaissance": ["nmap", "sublist3r", "amass"],
            "web_scanning": ["owasp_zap", "nikto", "sqlmap"],
            "vulnerability_scanning": ["nessus", "openvas", "wappalyzer"],
            "content_discovery": ["dirsearch", "gobuster", "ffuf"],
            "brute_force": ["hydra", "medusa", "patator"],
        }

        # All available tools (flattened list)
        self.all_tools = [
            tool for tools in self.tool_categories.values() for tool in tools
        ]

        # Initialize models
        self.models = {}
        for category in self.tool_categories:
            self.models[category] = None

        # Tool performance history
        self.performance_history = defaultdict(list)
        self.performance_history_size = performance_history_size

        # Load existing models and history
        self._load_models()
        self._load_performance_history()

    def _load_models(self):
        """Load trained models if they exist."""
        for category in self.tool_categories:
            model_path = os.path.join(
                self.model_dir, f"{category}_tool_selector.joblib"
            )
            if os.path.exists(model_path):
                try:
                    self.models[category] = joblib.load(model_path)
                    logger.info(f"Loaded tool selection model for {category}")
                except Exception as e:
                    logger.error(f"Error loading model for {category}: {e}")

    def _save_models(self):
        """Save trained models to disk."""
        for category, model in self.models.items():
            if model is not None:
                model_path = os.path.join(
                    self.model_dir, f"{category}_tool_selector.joblib"
                )
                try:
                    joblib.dump(model, model_path)
                    logger.info(
                        f"Saved tool selection model for {category} to {model_path}"
                    )
                except Exception as e:
                    logger.error(f"Error saving model for {category}: {e}")

    def _load_performance_history(self):
        """Load tool performance history if it exists."""
        history_path = os.path.join(self.model_dir, "tool_performance_history.json")
        if os.path.exists(history_path):
            try:
                with open(history_path, "r") as f:
                    history_data = json.load(f)
                    for tool, records in history_data.items():
                        self.performance_history[tool] = records[
                            -self.performance_history_size :
                        ]
                logger.info("Loaded tool performance history")
            except Exception as e:
                logger.error(f"Error loading performance history: {e}")

    def _save_performance_history(self):
        """Save tool performance history to disk."""
        history_path = os.path.join(self.model_dir, "tool_performance_history.json")
        try:
            # Convert defaultdict to regular dict for JSON serialization
            history_dict = {k: v for k, v in self.performance_history.items()}
            with open(history_path, "w") as f:
                json.dump(history_dict, f)
            logger.info(f"Saved tool performance history to {history_path}")
        except Exception as e:
            logger.error(f"Error saving performance history: {e}")

    def _extract_target_features(self, target_info: Dict) -> Dict:
        """
        Extract features from target information.

        Args:
            target_info: Dictionary containing target information

        Returns:
            Dictionary of extracted features
        """
        features = {}

        # Basic target info
        features["target_type"] = target_info.get("type", "unknown").lower()
        features["is_web_application"] = int(
            "web" in features["target_type"]
            or target_info.get("has_web_interface", False)
        )
        features["is_api"] = int(
            "api" in features["target_type"] or target_info.get("has_api", False)
        )
        features["is_mobile"] = int("mobile" in features["target_type"])
        features["is_network"] = int(
            "network" in features["target_type"]
            or target_info.get("has_network_services", False)
        )

        # Web-specific features
        features["has_login"] = int(target_info.get("has_login", False))
        features["has_forms"] = int(target_info.get("has_forms", False))
        features["has_file_upload"] = int(target_info.get("has_file_upload", False))
        features["uses_javascript"] = int(target_info.get("uses_javascript", False))

        # Network-specific features
        features["open_ports_count"] = len(target_info.get("open_ports", []))
        features["has_http_ports"] = int(
            80 in target_info.get("open_ports", [])
            or 443 in target_info.get("open_ports", [])
        )
        features["has_db_ports"] = int(
            any(
                port in target_info.get("open_ports", [])
                for port in [3306, 5432, 1433, 27017, 6379]
            )
        )

        # Domain-specific features
        features["has_subdomains"] = int(target_info.get("has_subdomains", False))
        features["subdomain_count"] = len(target_info.get("subdomains", []))

        # Scope and constraints
        features["max_scan_depth"] = target_info.get("max_scan_depth", 2)
        features["time_constraint"] = target_info.get(
            "time_constraint", 0
        )  # In minutes, 0 means no constraint

        return features

    def _get_tool_effectiveness_score(self, tool: str, target_features: Dict) -> float:
        """
        Calculate the effectiveness score for a tool based on historical performance.

        Args:
            tool: Name of the tool
            target_features: Dictionary of target features

        Returns:
            Effectiveness score between 0 and 1
        """
        if not self.performance_history.get(tool):
            # No history, return default score
            return 0.5

        # Extract relevant features for similarity comparison
        target_type = target_features.get("target_type", "unknown")
        is_web = target_features.get("is_web_application", 0)
        is_network = target_features.get("is_network", 0)

        # Calculate weighted score based on similar targets in history
        total_weight = 0
        weighted_score = 0

        for record in self.performance_history[tool]:
            # Calculate similarity between current target and historical target
            similarity = 0.0

            # Target type similarity (most important)
            if record.get("target_type") == target_type:
                similarity += 0.5

            # Web/Network similarity
            if record.get("is_web_application") == is_web:
                similarity += 0.2
            if record.get("is_network") == is_network:
                similarity += 0.2

            # Additional feature similarity can be added here

            # Add time decay factor - more recent results have higher weight
            time_factor = 1.0
            if "timestamp" in record:
                age_days = (time.time() - record["timestamp"]) / (24 * 3600)
                time_factor = math.exp(-0.05 * age_days)  # Decay factor

            weight = similarity * time_factor
            if weight > 0:
                total_weight += weight
                weighted_score += weight * record.get("effectiveness", 0.5)

        if total_weight > 0:
            return weighted_score / total_weight
        else:
            return 0.5  # Default score

    def train(self, training_data: List[Dict], save_models: bool = True) -> Dict:
        """
        Train the tool selection models on historical data.

        Args:
            training_data: List of dictionaries containing target info and tool performance
            save_models: Whether to save trained models to disk

        Returns:
            Dictionary with training results
        """
        if not training_data:
            return {"error": "No training data provided"}

        try:
            # Process training data
            category_datasets = {category: [] for category in self.tool_categories}

            for entry in training_data:
                if "target_info" not in entry or "tool_results" not in entry:
                    continue

                # Extract features from target info
                features = self._extract_target_features(entry["target_info"])

                # Process tool results for each category
                for category, tools in self.tool_categories.items():
                    best_tool = None
                    best_score = -1

                    for tool in tools:
                        if tool in entry["tool_results"]:
                            tool_result = entry["tool_results"][tool]
                            effectiveness = tool_result.get("effectiveness", 0)
                            if effectiveness > best_score:
                                best_score = effectiveness
                                best_tool = tool

                    if best_tool and best_score > 0:
                        # Add to category dataset
                        category_datasets[category].append(
                            {"features": features, "best_tool": best_tool}
                        )

                        # Add to performance history
                        self.performance_history[best_tool].append(
                            {
                                **features,
                                "effectiveness": best_score,
                                "timestamp": entry.get("timestamp", time.time()),
                            }
                        )
                        # Trim history if needed
                        if (
                            len(self.performance_history[best_tool])
                            > self.performance_history_size
                        ):
                            self.performance_history[best_tool] = (
                                self.performance_history[best_tool][
                                    -self.performance_history_size :
                                ]
                            )

            # Train a model for each category if enough data
            models_trained = 0
            for category, dataset in category_datasets.items():
                if len(dataset) >= 10:  # Minimum samples to train
                    X = []
                    y = []

                    for item in dataset:
                        # Convert features dict to list
                        feature_values = list(item["features"].values())
                        X.append(feature_values)
                        y.append(item["best_tool"])

                    # Train random forest classifier
                    clf = RandomForestClassifier(n_estimators=100, random_state=42)
                    clf.fit(X, y)

                    self.models[category] = clf
                    models_trained += 1

            # Save models and history
            if save_models:
                self._save_models()
                self._save_performance_history()

            return {
                "status": "success",
                "models_trained": models_trained,
                "training_entries": len(training_data),
                "performance_records": sum(
                    len(records) for records in self.performance_history.values()
                ),
            }

        except Exception as e:
            logger.error(f"Error training tool selection models: {e}")
            return {"error": f"Failed to train models: {str(e)}"}

    def record_tool_performance(
        self, tool: str, target_info: Dict, performance_metrics: Dict
    ) -> None:
        """
        Record the performance of a tool on a target.

        Args:
            tool: Name of the tool
            target_info: Dictionary containing target information
            performance_metrics: Dictionary with performance metrics
        """
        try:
            # Extract features from target info
            features = self._extract_target_features(target_info)

            # Calculate effectiveness score (0-1) based on provided metrics
            effectiveness = 0.5  # Default

            if "finding_count" in performance_metrics:
                # More findings is generally better
                finding_count = performance_metrics["finding_count"]
                # Normalize to 0-1 scale with diminishing returns
                finding_score = min(
                    1.0, finding_count / 10
                )  # Assume 10+ findings is good
                effectiveness = max(effectiveness, finding_score)

            if (
                "true_positives" in performance_metrics
                and "false_positives" in performance_metrics
            ):
                # Calculate precision
                tp = performance_metrics["true_positives"]
                fp = performance_metrics["false_positives"]
                if tp + fp > 0:
                    precision = tp / (tp + fp)
                    effectiveness = max(effectiveness, precision)

            if (
                "execution_time" in performance_metrics
                and "time_limit" in performance_metrics
            ):
                # Faster is better (as long as it's effective)
                time_limit = performance_metrics["time_limit"]
                exec_time = performance_metrics["execution_time"]
                if time_limit > 0:
                    time_score = 1.0 - min(1.0, exec_time / time_limit)
                    # Weight time less than finding quality
                    effectiveness = 0.7 * effectiveness + 0.3 * time_score

            # Add to performance history
            self.performance_history[tool].append(
                {
                    **features,
                    "effectiveness": effectiveness,
                    "timestamp": time.time(),
                    "metrics": performance_metrics,
                }
            )

            # Trim history if needed
            if len(self.performance_history[tool]) > self.performance_history_size:
                self.performance_history[tool] = self.performance_history[tool][
                    -self.performance_history_size :
                ]

            # Save updated history
            self._save_performance_history()

            logger.info(
                f"Recorded performance for {tool}: effectiveness={effectiveness:.2f}"
            )

        except Exception as e:
            logger.error(f"Error recording tool performance: {e}")

    def recommend_tools(
        self, target_info: Dict, max_tools: int = 3
    ) -> Dict[str, List[Dict]]:
        """
        Recommend tools for scanning a target based on its characteristics.

        Args:
            target_info: Dictionary containing target information
            max_tools: Maximum number of tools to recommend per category

        Returns:
            Dictionary with tool recommendations by category
        """
        try:
            # Extract features from target info
            features = self._extract_target_features(target_info)
            feature_values = list(features.values())

            recommendations = {}

            # Consider each tool category
            for category, tools in self.tool_categories.items():
                # First try to use trained model if available
                if self.models.get(category) is not None:
                    try:
                        # Get probabilities for each class
                        proba = self.models[category].predict_proba([feature_values])[0]
                        # Get top tools based on probability
                        tool_probs = list(zip(self.models[category].classes_, proba))
                        tool_probs.sort(key=lambda x: x[1], reverse=True)

                        recommended_tools = []
                        for tool, prob in tool_probs[:max_tools]:
                            if prob > 0.1:  # Minimum probability threshold
                                recommended_tools.append(
                                    {
                                        "name": tool,
                                        "confidence": float(prob),
                                        "reason": f"ML model prediction with {prob:.2f} confidence",
                                    }
                                )

                        if recommended_tools:
                            recommendations[category] = recommended_tools
                            continue
                    except Exception as e:
                        logger.warning(f"Error using ML model for {category}: {e}")

                # Fallback to heuristic approach
                recommended_tools = []

                for tool in tools:
                    # Calculate effectiveness score based on historical performance
                    effectiveness = self._get_tool_effectiveness_score(tool, features)

                    # Apply heuristic rules based on target type and features
                    score = effectiveness
                    reason = "Based on historical performance"

                    # Apply tool-specific heuristics
                    if tool == "nmap" and features["is_network"] == 1:
                        score += 0.2
                        reason = "Recommended for network targets"
                    elif tool == "owasp_zap" and features["is_web_application"] == 1:
                        score += 0.2
                        reason = "Recommended for web applications"
                    elif tool == "sublist3r" and features["has_subdomains"] == 1:
                        score += 0.3
                        reason = "Recommended for subdomain enumeration"
                    elif tool == "dirsearch" and features["is_web_application"] == 1:
                        score += 0.15
                        reason = "Recommended for web content discovery"
                    elif tool == "sqlmap" and features["has_forms"] == 1:
                        score += 0.25
                        reason = "Recommended for testing web forms"
                    elif tool == "wappalyzer" and features["is_web_application"] == 1:
                        score += 0.1
                        reason = "Recommended for technology fingerprinting"

                    # Time constraint adjustments
                    if features["time_constraint"] > 0:
                        if (
                            tool in ["nmap", "owasp_zap"]
                            and features["time_constraint"] < 30
                        ):
                            score -= 0.1
                            reason += " (may be slow for tight time constraints)"

                    recommended_tools.append(
                        {"name": tool, "confidence": min(1.0, score), "reason": reason}
                    )

                # Sort by confidence and limit
                recommended_tools.sort(key=lambda x: x["confidence"], reverse=True)
                recommendations[category] = recommended_tools[:max_tools]

            return recommendations

        except Exception as e:
            logger.error(f"Error recommending tools: {e}")
            return {"error": f"Failed to recommend tools: {str(e)}"}

    def optimize_tool_configuration(self, tool: str, target_info: Dict) -> Dict:
        """
        Recommend optimal configuration for a specific tool based on target characteristics.

        Args:
            tool: Name of the tool
            target_info: Dictionary containing target information

        Returns:
            Dictionary with recommended configuration options
        """
        try:
            # Extract features from target info
            features = self._extract_target_features(target_info)

            # Default configurations
            default_configs = {
                "nmap": {
                    "scan_type": "-sV -sC",  # Version detection and scripts
                    "timing": "-T4",  # Aggressive timing
                    "ports": "default",  # Default port range
                },
                "owasp_zap": {
                    "scan_mode": "passive",  # Passive or active
                    "alert_threshold": "medium",
                    "attack_strength": "medium",
                },
                "dirsearch": {
                    "wordlist": "medium",  # Small, medium, large
                    "extensions": "php,html,js",
                    "recursive": False,
                },
                "sublist3r": {
                    "engines": "all",  # Search engines to use
                    "threads": 40,
                    "verbose": True,
                },
                "wappalyzer": {"depth": 1, "max_urls": 10},
            }

            if tool not in default_configs:
                return {"error": f"No configuration template available for {tool}"}

            # Start with default configuration
            config = default_configs[tool].copy()

            # Adjust based on target features
            if tool == "nmap":
                # Adjust timing based on time constraints
                if features["time_constraint"] > 0:
                    if features["time_constraint"] < 15:
                        config["timing"] = "-T5"  # Insane timing
                        config["scan_type"] = "-sT"  # Connect scan only
                    elif features["time_constraint"] < 30:
                        config["timing"] = "-T4"  # Aggressive

                # Adjust ports based on target type
                if features["is_web_application"] == 1:
                    config["ports"] = "80,443,8080,8443"
                elif features["has_db_ports"] == 1:
                    config["ports"] = "common,3306,5432,1433,27017,6379"

                # Adjust scan type based on depth
                if features["max_scan_depth"] >= 3:
                    config["scan_type"] = "-sV -sC -O"  # Add OS detection

            elif tool == "owasp_zap":
                # Adjust scan mode based on time constraints
                if features["time_constraint"] > 0 and features["time_constraint"] < 30:
                    config["scan_mode"] = "passive"
                else:
                    config["scan_mode"] = "active"

                # Adjust attack strength based on scan depth
                if features["max_scan_depth"] >= 3:
                    config["attack_strength"] = "high"
                    config["alert_threshold"] = "low"
                elif features["max_scan_depth"] <= 1:
                    config["attack_strength"] = "low"

            elif tool == "dirsearch":
                # Adjust wordlist size based on time constraints and depth
                if features["time_constraint"] > 0 and features["time_constraint"] < 15:
                    config["wordlist"] = "small"
                elif features["max_scan_depth"] >= 3:
                    config["wordlist"] = "large"

                # Enable recursion for deeper scans
                if features["max_scan_depth"] >= 2:
                    config["recursive"] = True

                # Adjust extensions based on target
                if features["uses_javascript"] == 1:
                    config["extensions"] += ",json,api"

            # Add explanation for configuration choices
            reasons = {
                "nmap": {
                    "timing": "Based on time constraints",
                    "scan_type": "Based on desired scan depth",
                    "ports": "Based on target services",
                },
                "owasp_zap": {
                    "scan_mode": "Based on time constraints",
                    "attack_strength": "Based on scan depth",
                    "alert_threshold": "Based on scan depth",
                },
                "dirsearch": {
                    "wordlist": "Based on time constraints and depth",
                    "recursive": "Based on scan depth",
                    "extensions": "Based on target technologies",
                },
            }

            return {
                "tool": tool,
                "configuration": config,
                "reasons": reasons.get(tool, {}),
            }

        except Exception as e:
            logger.error(f"Error optimizing tool configuration: {e}")
            return {"error": f"Failed to optimize configuration: {str(e)}"}

    def plan_scan_sequence(
        self, target_info: Dict, selected_tools: List[str]
    ) -> List[Dict]:
        """
        Plan the optimal sequence for running selected tools.

        Args:
            target_info: Dictionary containing target information
            selected_tools: List of selected tools to run

        Returns:
            List of tools in recommended execution order with rationale
        """
        try:
            if not selected_tools:
                return []

            # Define tool dependencies and optimal order
            tool_dependencies = {
                "nmap": [],  # No dependencies
                "sublist3r": [],
                "amass": [],
                "wappalyzer": ["nmap"],  # Better to run after port scan
                "owasp_zap": ["nmap", "wappalyzer"],  # Better after fingerprinting
                "nikto": ["nmap"],
                "sqlmap": [
                    "owasp_zap"
                ],  # Better after finding potential injection points
                "dirsearch": ["nmap"],
                "gobuster": ["nmap"],
                "ffuf": ["nmap"],
                "hydra": ["nmap", "dirsearch"],  # Better after finding login pages
            }

            # Define tool categories for sequential planning
            tool_phases = {
                "reconnaissance": ["nmap", "sublist3r", "amass"],
                "fingerprinting": ["wappalyzer"],
                "scanning": ["owasp_zap", "nikto"],
                "content_discovery": ["dirsearch", "gobuster", "ffuf"],
                "targeted_testing": ["sqlmap", "hydra"],
            }

            # Filter to only include selected tools
            available_tools = set(selected_tools)

            # Build execution plan
            execution_plan = []
            remaining_tools = set(selected_tools)

            # First run tools with no dependencies
            for phase, phase_tools in tool_phases.items():
                phase_tools_to_run = []

                for tool in phase_tools:
                    if tool in remaining_tools:
                        # Check if all dependencies are satisfied
                        deps = [
                            dep
                            for dep in tool_dependencies.get(tool, [])
                            if dep in available_tools
                        ]
                        deps_satisfied = all(dep not in remaining_tools for dep in deps)

                        if not deps or deps_satisfied:
                            phase_tools_to_run.append(tool)

                # Add tools from this phase to the plan
                for tool in phase_tools_to_run:
                    reason = f"Scheduled during {phase} phase"
                    if tool in tool_dependencies and tool_dependencies[tool]:
                        deps = [
                            dep
                            for dep in tool_dependencies[tool]
                            if dep in available_tools
                        ]
                        if deps:
                            reason += f" after {', '.join(deps)}"

                    execution_plan.append(
                        {"tool": tool, "phase": phase, "reason": reason}
                    )
                    remaining_tools.remove(tool)

            # Add any remaining tools
            for tool in remaining_tools:
                # Find appropriate phase
                tool_phase = "unknown"
                for phase, phase_tools in tool_phases.items():
                    if tool in phase_tools:
                        tool_phase = phase
                        break

                execution_plan.append(
                    {
                        "tool": tool,
                        "phase": tool_phase,
                        "reason": f"Added to execution plan (dependency order could not be determined)",
                    }
                )

            return execution_plan

        except Exception as e:
            logger.error(f"Error planning scan sequence: {e}")
            return [{"error": f"Failed to plan scan sequence: {str(e)}"}]
