"""
Risk Scoring ML Module for Sniper Tool.

This module provides advanced machine learning capabilities for risk scoring
and vulnerability prioritization. It analyzes security findings from various
tools to determine real risk level, assign prioritization scores, and
help users focus on the most critical vulnerabilities first.

Features:
- Advanced contextual risk scoring based on multiple factors
- Vulnerability prioritization and ranking
- Risk trend analysis over time
- Integration of CVSS scores with contextual data
- Customizable scoring based on environment-specific factors

Dependencies:
- numpy
- pandas
- scikit-learn
- datetime

Usage:
    from src.ml.risk_scoring import RiskScorer

    # Initialize the risk scorer
    scorer = RiskScorer()

    # Score a single finding
    risk_score = scorer.score_finding(finding)

    # Score and prioritize multiple findings
    prioritized_findings = scorer.prioritize_findings(findings)
"""

import json
import logging
import math
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler

# Set up logging
logger = logging.getLogger(__name__)


class RiskScorer:
    """
    RiskScorer class provides advanced machine learning capabilities for
    risk analysis and prioritization of security findings.
    """

    def __init__(self, model_dir: Optional[str] = None) -> None:
        """
        Initialize the RiskScorer class.

        Args:
            model_dir: Directory to store trained models
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)

        # Initialize models
        self.risk_model: Optional[Any] = None
        self.scaler: Optional[StandardScaler] = None

        # CVSS scoring components and weights
        self.cvss_weights = {
            "base_score": 0.6,
            "temporal_score": 0.25,
            "environmental_score": 0.15,
        }

        # Environmental factors and weights
        self.env_factors = {
            "internet_facing": 1.5,  # Multiply risk if asset is exposed to internet
            "contains_pii": 1.4,  # Multiply risk if asset contains personal data
            "business_critical": 1.3,  # Multiply risk if asset is business critical
            "regulatory_compliance": 1.2,  # Multiply risk if asset has compliance requirements
        }

        # Load models if they exist
        self._load_models()

    def _load_models(self):
        """Load trained models if they exist."""
        risk_model_path = os.path.join(self.model_dir, "risk_model.joblib")
        scaler_path = os.path.join(self.model_dir, "risk_scaler.joblib")

        if os.path.exists(risk_model_path):
            try:
                self.risk_model = joblib.load(risk_model_path)
                logger.info("Loaded risk scoring model")
            except Exception as e:
                logger.error(f"Error loading risk scoring model: {e}")

        if os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded feature scaler")
            except Exception as e:
                logger.error(f"Error loading feature scaler: {e}")

    def save_models(self):
        """Save trained models to disk."""
        if self.risk_model:
            risk_model_path = os.path.join(self.model_dir, "risk_model.joblib")
            joblib.dump(self.risk_model, risk_model_path)
            logger.info(f"Saved risk scoring model to {risk_model_path}")

        scaler_path = os.path.join(self.model_dir, "risk_scaler.joblib")
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Saved feature scaler to {scaler_path}")

    def _extract_features(self, finding: Dict) -> np.ndarray:
        """
        Extract features from a finding for risk scoring.

        Args:
            finding: Finding dictionary

        Returns:
            Numpy array of features
        """
        features = []

        # Severity numerical value
        severity = self._normalize_severity(finding.get("severity", "medium"))
        features.append(severity)

        # Confidence numerical value
        confidence = self._normalize_confidence(finding.get("confidence", "medium"))
        features.append(confidence)

        # Description length (normalized)
        description = finding.get("description", "")
        desc_length = min(len(description) / 1000.0, 1.0)  # Normalize to 0-1
        features.append(desc_length)

        # Has CVE mentioned
        has_cve = 1.0 if "CVE-" in description else 0.0
        features.append(has_cve)

        # Has proof of concept
        has_poc = (
            1.0
            if "POC" in description or "proof of concept" in description.lower()
            else 0.0
        )
        features.append(has_poc)

        # Has exploit available
        has_exploit = 1.0 if "exploit" in description.lower() else 0.0
        features.append(has_exploit)

        # Extract CVSS score if available
        cvss_score = self._extract_cvss_score(description)
        features.append(cvss_score)

        # Has URL/endpoint information
        has_url = (
            1.0 if ("http://" in description or "https://" in description) else 0.0
        )
        features.append(has_url)

        # Is recent finding (if timestamp available)
        timestamp = finding.get("timestamp")
        is_recent = 0.0
        if timestamp:
            try:
                finding_date = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                now = datetime.now()
                days_old = (now - finding_date).days
                is_recent = 1.0 if days_old < 30 else (0.5 if days_old < 90 else 0.0)
            except (ValueError, TypeError):
                pass
        features.append(is_recent)

        # Tool reliability factor
        tool = finding.get("source", "unknown").lower()
        tool_reliability = self._get_tool_reliability(tool)
        features.append(tool_reliability)

        return np.array(features, dtype=np.float32).reshape(1, -1)

    def _normalize_severity(self, severity: str) -> float:
        """Convert severity string to numerical value."""
        severity_map = {
            "info": 0.0,
            "low": 0.25,
            "medium": 0.5,
            "high": 0.75,
            "critical": 1.0,
        }
        return severity_map.get(severity.lower(), 0.5)

    def _normalize_confidence(self, confidence: str) -> float:
        """Convert confidence string to numerical value."""
        confidence_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "confirmed": 1.0}
        return confidence_map.get(confidence.lower(), 0.5)

    def _extract_cvss_score(self, text: str) -> float:
        """
        Extract CVSS score from text.

        Args:
            text: Text to search for CVSS score

        Returns:
            CVSS score (0-10) or 0 if not found
        """
        # Try to find CVSS v3 score pattern
        cvss_pattern = r"CVSS[:\s]*(v3)?.{0,20}?(\d+\.\d+)"
        match = re.search(cvss_pattern, text, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(2))
                if 0 <= score <= 10:
                    return score / 10.0  # Normalize to 0-1
            except (ValueError, IndexError):
                pass

        # Try to find CVE and use CVSS from NVD database
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        cve_match = re.search(cve_pattern, text)
        if cve_match:
            # Here we would ideally lookup the CVSS score from NVD
            # For now, we return a default medium score
            return 0.5

        return 0.0

    def _get_tool_reliability(self, tool: str) -> float:
        """
        Get reliability factor for a tool.

        Args:
            tool: Tool name

        Returns:
            Reliability factor (0-1)
        """
        reliability_map = {
            "zap": 0.85,
            "nmap": 0.8,
            "wappalyzer": 0.7,
            "dirsearch": 0.75,
            "sublist3r": 0.65,
            "manual": 0.9,
        }
        return reliability_map.get(tool.lower(), 0.5)

    def _heuristic_risk_score(self, features: np.ndarray) -> float:
        """
        Calculate risk score using heuristics when no model is available.

        Args:
            features: Feature array

        Returns:
            Risk score (0-1)
        """
        # Weights for heuristic calculation
        weights = [
            0.30,  # severity
            0.15,  # confidence
            0.05,  # description length
            0.10,  # has CVE
            0.10,  # has POC
            0.15,  # has exploit
            0.20,  # CVSS score
            0.05,  # has URL
            0.05,  # is recent
            0.10,  # tool reliability
        ]

        # Ensure we have the right number of features
        if len(features[0]) != len(weights):
            # Adjust weights if feature count doesn't match
            weights = [1.0 / len(features[0])] * len(features[0])

        # Calculate weighted sum
        weighted_sum = sum(f * w for f, w in zip(features[0], weights))

        # Apply a sigmoid function to keep the score between 0 and 1
        # and to emphasize differences in the middle range
        return 1.0 / (1.0 + math.exp(-5 * (weighted_sum - 0.5)))

    def score_finding(self, finding: Dict, env_context: Dict = None) -> float:
        """
        Calculate risk score for a finding.

        Args:
            finding: Finding dictionary
            env_context: Optional environmental context

        Returns:
            Risk score (0-1)
        """
        # Extract features
        features = self._extract_features(finding)

        # Calculate base risk score
        if self.risk_model is None:
            base_score = self._heuristic_risk_score(features)
        else:
            try:
                # Scale features
                features_scaled = self.scaler.transform(features)
                # Predict risk score
                base_score = self.risk_model.predict(features_scaled)[0]
                # Ensure score is between 0 and 1
                base_score = max(0.0, min(1.0, base_score))
            except Exception as e:
                logger.error(f"Error predicting risk score: {e}")
                base_score = self._heuristic_risk_score(features)

        # Apply environmental context if provided
        if env_context:
            # Start with base score
            contextualized_score = base_score

            # Apply environmental factors
            for factor, multiplier in self.env_factors.items():
                if env_context.get(factor, False):
                    contextualized_score *= multiplier

            # Ensure score is still between 0 and 1
            contextualized_score = max(0.0, min(1.0, contextualized_score))
            return contextualized_score

        return base_score

    def prioritize_findings(
        self, findings: List[Dict], env_context: Dict = None
    ) -> List[Dict]:
        """
        Score and prioritize a list of findings.

        Args:
            findings: List of finding dictionaries
            env_context: Optional environmental context

        Returns:
            List of findings with added risk scores, sorted by priority
        """
        if not findings:
            return []

        scored_findings = []
        for finding in findings:
            # Clone finding to avoid modifying original
            scored_finding = finding.copy()

            # Calculate risk score
            risk_score = self.score_finding(finding, env_context)

            # Add score to finding
            scored_finding["risk_score"] = risk_score

            # Calculate priority based on risk score
            if risk_score >= 0.8:
                priority = "critical"
            elif risk_score >= 0.6:
                priority = "high"
            elif risk_score >= 0.4:
                priority = "medium"
            elif risk_score >= 0.2:
                priority = "low"
            else:
                priority = "info"

            scored_finding["priority"] = priority
            scored_findings.append(scored_finding)

        # Sort by risk score (descending)
        scored_findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return scored_findings

    def train_risk_model(self, findings: List[Dict], risk_scores: List[float]) -> bool:
        """
        Train the risk scoring model.

        Args:
            findings: List of finding dictionaries
            risk_scores: List of validated risk scores (0-1)

        Returns:
            True if training was successful, False otherwise
        """
        if not findings or not risk_scores or len(findings) != len(risk_scores):
            logger.error("Invalid training data for risk model")
            return False

        try:
            # Extract features from findings
            X = []
            for finding in findings:
                features = self._extract_features(finding)[0]  # Extract and flatten
                X.append(features)

            X = np.array(X)
            y = np.array(risk_scores)

            # Scale features
            X_scaled = self.scaler.fit_transform(X)

            # Train model
            self.risk_model = RandomForestRegressor(n_estimators=100, random_state=42)
            self.risk_model.fit(X_scaled, y)

            # Save model
            self.save_models()

            logger.info(
                f"Successfully trained risk model with {len(findings)} examples"
            )
            return True

        except Exception as e:
            logger.error(f"Error training risk model: {e}")
            return False

    def analyze_risk_trends(self, findings_history: List[Dict]) -> Dict[str, Any]:
        """
        Analyze risk trends over time.

        Args:
            findings_history: List of findings with timestamps

        Returns:
            Dictionary with risk trend analysis
        """
        if not findings_history:
            return {"error": "No findings history provided"}

        try:
            # Extract dates and scores
            dates = []
            scores = []
            severities = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": [],
            }

            for finding in findings_history:
                timestamp = finding.get("timestamp")
                if not timestamp:
                    continue

                try:
                    date = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    risk_score = finding.get("risk_score")

                    if risk_score is None:
                        # Calculate if not present
                        risk_score = self.score_finding(finding)

                    dates.append(date)
                    scores.append(risk_score)

                    # Track by severity
                    severity = finding.get("severity", "medium").lower()
                    if severity in severities:
                        severities[severity].append((date, risk_score))

                except (ValueError, TypeError):
                    continue

            if not dates:
                return {"error": "No valid dates found in findings history"}

            # Sort by date
            sorted_data = sorted(zip(dates, scores), key=lambda x: x[0])
            dates, scores = zip(*sorted_data)

            # Calculate trend metrics
            first_date = min(dates)
            last_date = max(dates)
            time_span = (last_date - first_date).days or 1  # Avoid division by zero

            # Calculate average scores for first and last quarter
            quarter_size = max(1, len(dates) // 4)
            first_quarter_avg = (
                sum(scores[:quarter_size]) / quarter_size if scores else 0
            )
            last_quarter_avg = (
                sum(scores[-quarter_size:]) / quarter_size if scores else 0
            )

            # Trend direction
            trend_direction = (
                "improving"
                if last_quarter_avg < first_quarter_avg
                else "worsening" if last_quarter_avg > first_quarter_avg else "stable"
            )

            # Calculate trend by severity
            severity_trends = {}
            for severity, data in severities.items():
                if data:
                    # Sort by date
                    data.sort(key=lambda x: x[0])

                    # Calculate trends for each severity
                    if len(data) >= 2:
                        first_half = data[: len(data) // 2]
                        second_half = data[len(data) // 2 :]

                        first_half_avg = sum(s for _, s in first_half) / len(first_half)
                        second_half_avg = sum(s for _, s in second_half) / len(
                            second_half
                        )

                        direction = (
                            "improving"
                            if second_half_avg < first_half_avg
                            else (
                                "worsening"
                                if second_half_avg > first_half_avg
                                else "stable"
                            )
                        )
                        severity_trends[severity] = {
                            "direction": direction,
                            "change_rate": (second_half_avg - first_half_avg)
                            / (time_span / 30),  # Normalized to change per month
                        }

            return {
                "time_span_days": time_span,
                "overall_trend": {
                    "direction": trend_direction,
                    "change_rate": (last_quarter_avg - first_quarter_avg)
                    / (time_span / 30),  # Normalized to change per month
                },
                "severity_trends": severity_trends,
                "current_risk_level": last_quarter_avg,
                "findings_count": len(dates),
            }

        except Exception as e:
            logger.error(f"Error analyzing risk trends: {e}")
            return {"error": f"Failed to analyze risk trends: {str(e)}"}

    def adjust_cvss_score(
        self, cvss_base: float, temporal_factors: Dict = None, env_factors: Dict = None
    ) -> float:
        """
        Adjust CVSS base score with temporal and environmental factors.

        Args:
            cvss_base: CVSS base score (0-10)
            temporal_factors: Dictionary of temporal factors
            env_factors: Dictionary of environmental factors

        Returns:
            Adjusted CVSS score (0-10)
        """
        if cvss_base < 0 or cvss_base > 10:
            return 5.0  # Default to medium if invalid

        # Apply temporal factors if provided
        temporal_score = cvss_base
        if temporal_factors:
            # Example temporal factors (simplified)
            exploit_code = temporal_factors.get("exploit_code", 1.0)  # 0.9-1.0
            remediation_level = temporal_factors.get(
                "remediation_level", 1.0
            )  # 0.9-1.0
            report_confidence = temporal_factors.get(
                "report_confidence", 1.0
            )  # 0.9-1.0

            # Adjust temporal score (simplified CVSS formula)
            temporal_score = (
                cvss_base * exploit_code * remediation_level * report_confidence
            )

        # Apply environmental factors if provided
        env_score = temporal_score
        if env_factors:
            # Example environmental factors (simplified)
            confidentiality_req = env_factors.get(
                "confidentiality_requirement", 1.0
            )  # 0.5-1.5
            integrity_req = env_factors.get("integrity_requirement", 1.0)  # 0.5-1.5
            availability_req = env_factors.get(
                "availability_requirement", 1.0
            )  # 0.5-1.5

            # Calculate average impact of environmental requirements
            env_impact = (confidentiality_req + integrity_req + availability_req) / 3

            # Adjust environmental score (simplified formula)
            env_score = temporal_score * env_impact

        # Ensure final score is within range
        return max(0.0, min(10.0, env_score))

    def calculate_integrated_risk(
        self, findings: List[Dict], asset_value: float = 5.0, threat_level: float = 5.0
    ) -> Dict[str, Any]:
        """
        Calculate integrated risk considering findings, asset value, and threat level.

        Args:
            findings: List of finding dictionaries
            asset_value: Value of the asset (1-10)
            threat_level: Current threat level (1-10)

        Returns:
            Dictionary with integrated risk assessment
        """
        if not findings:
            return {
                "integrated_risk_score": 0.0,
                "risk_level": "none",
                "findings_count": 0,
                "highest_risk": 0.0,
            }

        # Score all findings
        scored_findings = self.prioritize_findings(findings)

        # Calculate statistics
        risk_scores = [f.get("risk_score", 0) for f in scored_findings]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        max_risk = max(risk_scores) if risk_scores else 0

        # Count by priority
        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in scored_findings:
            priority = finding.get("priority", "info")
            if priority in priority_counts:
                priority_counts[priority] += 1

        # Calculate weighted severity score
        weighted_severity = (
            priority_counts["critical"] * 1.0
            + priority_counts["high"] * 0.75
            + priority_counts["medium"] * 0.5
            + priority_counts["low"] * 0.25
            + priority_counts["info"] * 0.1
        ) / max(1, sum(priority_counts.values()))

        # Normalize asset value and threat level to 0-1
        asset_value_norm = asset_value / 10.0
        threat_level_norm = threat_level / 10.0

        # Calculate integrated risk (combination of findings risk, asset value, and threat level)
        # Formula gives more weight to higher risk findings
        integrated_risk = (
            (0.4 * max_risk)
            + (0.3 * weighted_severity)
            + (0.2 * asset_value_norm)
            + (0.1 * threat_level_norm)
        )

        # Map to risk level
        risk_level = "critical"
        if integrated_risk < 0.2:
            risk_level = "very low"
        elif integrated_risk < 0.4:
            risk_level = "low"
        elif integrated_risk < 0.6:
            risk_level = "medium"
        elif integrated_risk < 0.8:
            risk_level = "high"

        return {
            "integrated_risk_score": integrated_risk,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "findings_by_priority": priority_counts,
            "highest_risk": max_risk,
            "average_risk": avg_risk,
            "weighted_severity": weighted_severity,
            "asset_value_factor": asset_value_norm,
            "threat_level_factor": threat_level_norm,
        }
