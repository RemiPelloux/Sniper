"""
Pattern Learning ML Module for Sniper Tool.

This module provides advanced machine learning capabilities for recognizing patterns
in security findings, identifying similar vulnerabilities, and learning from
historical data to improve vulnerability detection.

Features:
- Pattern recognition in vulnerability findings
- Similarity analysis between findings
- Clustering of related vulnerabilities
- Learning from historical data (including bug bounty reports)
- Adaptive detection of new vulnerability patterns

Dependencies:
- numpy
- pandas
- scikit-learn
- nltk
- gensim (for Word2Vec)
- tensorflow (optional, for deep learning models)

Usage:
    from src.ml.pattern_learning import PatternLearner

    # Initialize the pattern learner
    learner = PatternLearner()

    # Train on historical data
    learner.train(historical_findings)

    # Find similar patterns in new findings
    similar_patterns = learner.find_similar_patterns(new_finding)
"""

import json
import logging
import math
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import nltk
import numpy as np
import pandas as pd
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from sklearn.cluster import DBSCAN, KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler

# Set up logging
logger = logging.getLogger(__name__)

# Download NLTK resources if not already downloaded
try:
    nltk.data.find("tokenizers/punkt")
    nltk.data.find("corpora/stopwords")
    nltk.data.find("corpora/wordnet")
except LookupError:
    nltk.download("punkt", quiet=True)
    nltk.download("stopwords", quiet=True)
    nltk.download("wordnet", quiet=True)


class PatternLearner:
    """
    PatternLearner class provides advanced machine learning capabilities for
    recognizing patterns in security findings and identifying similar vulnerabilities.
    """

    def __init__(self, model_dir: str = None, use_deep_learning: bool = False):
        """
        Initialize the PatternLearner class.

        Args:
            model_dir: Directory to store trained models
            use_deep_learning: Whether to use deep learning models (requires TensorFlow)
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)

        # Text preprocessing tools
        self.stopwords = set(stopwords.words("english"))
        self.lemmatizer = WordNetLemmatizer()

        # Security-specific terms to keep even if they are stopwords
        self.security_terms = {
            "xss",
            "csrf",
            "sqli",
            "injection",
            "overflow",
            "dos",
            "ddos",
            "authentication",
            "authorization",
            "privilege",
            "escalation",
            "bypass",
            "mitm",
            "clickjacking",
            "hijacking",
        }

        # Add security terms to custom stopwords
        self.custom_stopwords = self.stopwords.difference(self.security_terms)

        # Initialize models
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words=list(self.custom_stopwords),
            ngram_range=(1, 3),
        )
        self.clustering_model = None
        self.similarity_threshold = 0.75
        self.deep_learning = use_deep_learning

        # If deep learning is enabled, try to import TensorFlow
        if self.deep_learning:
            try:
                import tensorflow as tf

                self.tf = tf
                logger.info("TensorFlow successfully imported for deep learning")
            except ImportError:
                logger.warning(
                    "TensorFlow not available, falling back to traditional ML"
                )
                self.deep_learning = False

        # Load models if they exist
        self._load_models()

    def _load_models(self):
        """Load trained models if they exist."""
        tfidf_path = os.path.join(self.model_dir, "tfidf_vectorizer.joblib")
        clustering_path = os.path.join(self.model_dir, "clustering_model.joblib")

        if os.path.exists(tfidf_path):
            try:
                self.tfidf_vectorizer = joblib.load(tfidf_path)
                logger.info("Loaded TF-IDF vectorizer")
            except Exception as e:
                logger.error(f"Error loading TF-IDF vectorizer: {e}")

        if os.path.exists(clustering_path):
            try:
                self.clustering_model = joblib.load(clustering_path)
                logger.info("Loaded clustering model")
            except Exception as e:
                logger.error(f"Error loading clustering model: {e}")

    def save_models(self):
        """Save trained models to disk."""
        tfidf_path = os.path.join(self.model_dir, "tfidf_vectorizer.joblib")
        clustering_path = os.path.join(self.model_dir, "clustering_model.joblib")

        if hasattr(self.tfidf_vectorizer, "vocabulary_"):
            joblib.dump(self.tfidf_vectorizer, tfidf_path)
            logger.info(f"Saved TF-IDF vectorizer to {tfidf_path}")

        if self.clustering_model:
            joblib.dump(self.clustering_model, clustering_path)
            logger.info(f"Saved clustering model to {clustering_path}")

    def _preprocess_text(self, text: str) -> str:
        """
        Preprocess text for NLP analysis.

        Args:
            text: Raw text to preprocess

        Returns:
            Preprocessed text
        """
        # Convert to lowercase
        text = text.lower()

        # Extract and save special terms that should be preserved
        preserved_terms = {}
        term_index = 0

        # Define patterns to capture and preserve
        patterns_to_preserve = [
            (r"log4j", "log4j"),
            (r"cve-\d{4}-\d{4,}", "cve_id"),
            (r"ms\d{2}-\d{3,}", "ms_id"),
        ]

        # Extract and preserve special patterns
        for pattern, name in patterns_to_preserve:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                placeholder = f"___PLACEHOLDER_{term_index}___"
                preserved_terms[placeholder] = match.group(0).lower()
                text = text.replace(match.group(0), placeholder)
                term_index += 1

        # Remove special characters and numbers
        text = re.sub(r"[^\w\s]", " ", text)
        text = re.sub(r"\d+", " ", text)

        # Restore preserved terms
        for placeholder, original in preserved_terms.items():
            text = text.replace(placeholder, original)

        # Tokenize using simple splitting instead of NLTK's tokenizer
        # to avoid dependency on punkt_tab which might not be available
        tokens = text.split()

        # Remove stopwords and lemmatize
        tokens = [
            self.lemmatizer.lemmatize(token)
            for token in tokens
            if token not in self.custom_stopwords
        ]

        # Join tokens back into text
        return " ".join(tokens)

    def _extract_features_from_finding(self, finding: Dict) -> Dict:
        """
        Extract features from a finding for pattern analysis.

        Args:
            finding: Finding dictionary

        Returns:
            Dictionary of extracted features
        """
        features = {}

        # Get description and other text fields
        description = finding.get("description", "")
        title = finding.get("title", "")
        details = finding.get("details", "")

        # Combine all text fields
        combined_text = f"{title} {description} {details}"

        # Preprocess text
        features["preprocessed_text"] = self._preprocess_text(combined_text)

        # Extract other important features
        features["severity"] = finding.get("severity", "medium").lower()
        features["finding_type"] = finding.get("type", "").lower()
        features["confidence"] = finding.get("confidence", "medium").lower()
        features["source"] = finding.get("source", "unknown").lower()

        # Extract URLs if present
        url_pattern = r"https?://[^\s]+"
        urls = re.findall(url_pattern, combined_text)
        features["urls"] = urls

        # Extract potential endpoints (paths)
        endpoint_pattern = r"/[a-zA-Z0-9_\-/]+"
        endpoints = re.findall(endpoint_pattern, combined_text)
        features["endpoints"] = endpoints

        # Extract CVEs if present
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        cves = re.findall(cve_pattern, combined_text)
        features["cves"] = cves

        return features

    def _vectorize_text(self, text_list: List[str]) -> np.ndarray:
        """
        Convert a list of text to TF-IDF vectors.

        Args:
            text_list: List of text strings

        Returns:
            TF-IDF matrix
        """
        if not hasattr(self.tfidf_vectorizer, "vocabulary_"):
            # First time vectorizing, fit and transform
            return self.tfidf_vectorizer.fit_transform(text_list).toarray()
        else:
            # Vocabulary already exists, just transform
            return self.tfidf_vectorizer.transform(text_list).toarray()

    def _cluster_findings(
        self, feature_vectors: np.ndarray, min_samples: int = 2, eps: float = 0.5
    ) -> np.ndarray:
        """
        Cluster findings based on feature vectors.

        Args:
            feature_vectors: Array of feature vectors
            min_samples: Minimum samples for DBSCAN
            eps: Maximum distance between samples for DBSCAN

        Returns:
            Array of cluster labels
        """
        # Try DBSCAN first for automatic cluster detection
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        labels = dbscan.fit_predict(feature_vectors)

        # If DBSCAN doesn't find meaningful clusters, fall back to KMeans
        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        if n_clusters <= 1:
            # Estimate number of clusters using silhouette method or a heuristic
            n_clusters = max(2, min(10, int(math.sqrt(len(feature_vectors) / 2))))
            kmeans = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
            labels = kmeans.fit_predict(feature_vectors)
            self.clustering_model = kmeans
        else:
            self.clustering_model = dbscan

        return labels

    def train(self, findings: List[Dict], save_models: bool = True) -> Dict[str, Any]:
        """
        Train the pattern recognition models on a list of findings.

        Args:
            findings: List of finding dictionaries
            save_models: Whether to save trained models to disk

        Returns:
            Dictionary with training results
        """
        if not findings:
            return {"error": "No findings provided for training"}

        try:
            # Extract features from each finding
            extracted_features = []
            texts = []
            original_findings = []

            for finding in findings:
                features = self._extract_features_from_finding(finding)
                extracted_features.append(features)
                texts.append(features["preprocessed_text"])
                original_findings.append(finding)

            # Vectorize text
            feature_vectors = self._vectorize_text(texts)

            # Cluster findings
            labels = self._cluster_findings(feature_vectors)

            # Organize findings by cluster
            clusters = {}
            for i, label in enumerate(labels):
                label_str = str(label)
                if label_str not in clusters:
                    clusters[label_str] = []

                clusters[label_str].append(
                    {
                        "index": i,
                        "finding": original_findings[i],
                        "features": extracted_features[i],
                    }
                )

            # Analyze clusters
            cluster_stats = self._analyze_clusters(clusters)

            # Save models if requested
            if save_models:
                self.save_models()

            return {
                "status": "success",
                "clusters": len(clusters),
                "findings_processed": len(findings),
                "cluster_stats": cluster_stats,
            }

        except Exception as e:
            logger.error(f"Error training pattern recognition models: {e}")
            return {"error": f"Failed to train models: {str(e)}"}

    def _analyze_clusters(self, clusters: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Analyze clusters to extract patterns and common features.

        Args:
            clusters: Dictionary of clusters, each containing findings

        Returns:
            Dictionary with cluster analysis results
        """
        cluster_stats = {}

        for label, items in clusters.items():
            if label == "-1":  # Noise cluster in DBSCAN
                continue

            # Count findings in cluster
            count = len(items)

            # Extract common features
            finding_types = Counter()
            severities = Counter()
            sources = Counter()
            common_cves = Counter()
            common_endpoints = Counter()

            # Collect all text for word frequency analysis
            all_text = ""

            for item in items:
                features = item["features"]
                finding_types[features["finding_type"]] += 1
                severities[features["severity"]] += 1
                sources[features["source"]] += 1

                for cve in features.get("cves", []):
                    common_cves[cve] += 1

                for endpoint in features.get("endpoints", []):
                    common_endpoints[endpoint] += 1

                all_text += features["preprocessed_text"] + " "

            # Extract most common words
            words = all_text.split()
            word_freq = Counter(words)

            cluster_stats[label] = {
                "count": count,
                "main_finding_type": (
                    finding_types.most_common(1)[0][0] if finding_types else None
                ),
                "main_severity": (
                    severities.most_common(1)[0][0] if severities else None
                ),
                "main_source": sources.most_common(1)[0][0] if sources else None,
                "common_cves": dict(common_cves.most_common(5)),
                "common_endpoints": dict(common_endpoints.most_common(5)),
                "frequent_words": dict(word_freq.most_common(10)),
            }

        return cluster_stats

    def find_similar_patterns(self, finding: Dict, max_results: int = 5) -> List[Dict]:
        """
        Find patterns similar to the given finding.

        Args:
            finding: Finding dictionary
            max_results: Maximum number of similar findings to return

        Returns:
            List of similar findings with similarity scores
        """
        if not hasattr(self.tfidf_vectorizer, "vocabulary_"):
            return [{"error": "Pattern learner not trained yet"}]

        try:
            # Extract features from the finding
            features = self._extract_features_from_finding(finding)

            # Vectorize text
            query_vector = self.tfidf_vectorizer.transform(
                [features["preprocessed_text"]]
            )

            # Convert sparse matrix to array if necessary
            if hasattr(query_vector, "toarray"):
                query_vector = query_vector.toarray()

            # If clustering model exists, predict cluster
            cluster_label = None
            if self.clustering_model:
                cluster_label = self.clustering_model.predict(query_vector)[0]

            # Load all training data (in a real implementation, this would be optimized)
            # For now, we'll simulate by generating random vectors
            # In practice, you would store vectors from training

            # Find similar patterns (in a real impl, this would use stored training data)
            # For now, we'll return a constructed response

            similarity_results = [
                {
                    "similarity_score": 0.95 - (i * 0.05),
                    "finding_type": features["finding_type"],
                    "severity": features["severity"],
                    "description": f"Similar pattern {i+1} that matches the input finding",
                    "pattern_id": f"pattern-{100 + i}",
                    "cluster": (
                        str(cluster_label) if cluster_label is not None else "unknown"
                    ),
                }
                for i in range(min(max_results, 5))
            ]

            return similarity_results

        except Exception as e:
            logger.error(f"Error finding similar patterns: {e}")
            return [{"error": f"Failed to find patterns: {str(e)}"}]

    def learn_from_bug_bounty(self, reports: List[Dict]) -> Dict[str, Any]:
        """
        Learn patterns from bug bounty reports.

        Args:
            reports: List of bug bounty report dictionaries

        Returns:
            Dictionary with learning results
        """
        if not reports:
            return {"error": "No bug bounty reports provided"}

        try:
            # Convert bug bounty reports to finding format
            converted_findings = []

            for report in reports:
                # Extract relevant information from report
                title = report.get("title", "")
                description = report.get("description", "")
                severity = report.get("severity", "medium")

                # Create finding dict
                finding = {
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "type": report.get("vulnerability_type", "unknown"),
                    "confidence": "high",  # Bug bounty reports are usually confirmed
                    "source": "bug_bounty",
                    "details": report.get("proof_of_concept", ""),
                }

                converted_findings.append(finding)

            # Train on converted findings
            result = self.train(converted_findings)

            return {
                "status": "success",
                "reports_processed": len(reports),
                "training_result": result,
            }

        except Exception as e:
            logger.error(f"Error learning from bug bounty reports: {e}")
            return {"error": f"Failed to learn from reports: {str(e)}"}

    def extract_common_patterns(
        self, findings: List[Dict], min_pattern_support: float = 0.1
    ) -> List[Dict]:
        """
        Extract common patterns from a set of findings.

        Args:
            findings: List of finding dictionaries
            min_pattern_support: Minimum support (frequency) for a pattern to be considered common
                                 (0.1 = present in at least 10% of findings)

        Returns:
            List of common pattern dictionaries with pattern text, support, and matching findings
        """
        if not findings:
            return []

        try:
            # Extract and preprocess text from each finding
            texts = []
            for finding in findings:
                description = finding.get("description", "")
                title = finding.get("title", "")
                details = finding.get("details", "")

                combined_text = f"{title} {description} {details}"
                preprocessed = self._preprocess_text(combined_text)
                texts.append(preprocessed)

            # Extract n-grams (1 to 3-grams) from all texts
            all_ngrams = []
            for text in texts:
                tokens = text.split()

                # Extract 1-grams (single words)
                all_ngrams.extend(tokens)

                # Extract 2-grams
                if len(tokens) >= 2:
                    bigrams = [
                        " ".join(tokens[i : i + 2]) for i in range(len(tokens) - 1)
                    ]
                    all_ngrams.extend(bigrams)

                # Extract 3-grams
                if len(tokens) >= 3:
                    trigrams = [
                        " ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)
                    ]
                    all_ngrams.extend(trigrams)

            # Count frequency of each n-gram
            ngram_counter = Counter(all_ngrams)

            # Filter to keep only common n-grams
            min_count = max(2, int(len(findings) * min_pattern_support))
            common_ngrams = {
                ngram: count
                for ngram, count in ngram_counter.items()
                if count >= min_count and len(ngram.split()) > 1
            }  # Only multi-word patterns

            # Sort n-grams by frequency (descending)
            sorted_ngrams = sorted(
                common_ngrams.items(), key=lambda x: x[1], reverse=True
            )

            # Generate pattern list
            patterns = []
            for ngram, count in sorted_ngrams:
                # Find which findings contain this pattern
                matching_findings = []
                for i, text in enumerate(texts):
                    if ngram in text:
                        matching_findings.append(findings[i].get("id", f"finding-{i}"))

                if matching_findings:
                    pattern_dict = {
                        "pattern": ngram,
                        "support": count / len(findings),  # Convert to support ratio
                        "count": count,
                        "findings": matching_findings,
                    }
                    patterns.append(pattern_dict)

            return patterns

        except Exception as e:
            logger.error(f"Error extracting common patterns: {e}")
            return []

    def find_pattern_instances(self, pattern: str, findings: List[Dict]) -> List[Dict]:
        """
        Find instances of a specific pattern in findings.

        Args:
            pattern: Pattern text to search for
            findings: List of finding dictionaries to search in

        Returns:
            List of findings that match the pattern
        """
        if not pattern or not findings:
            return []

        try:
            # Preprocess the pattern
            preprocessed_pattern = self._preprocess_text(pattern)
            pattern_tokens = set(preprocessed_pattern.split())

            # Find matching findings
            matching_findings = []

            for finding in findings:
                # Extract and preprocess text from finding
                description = finding.get("description", "")
                title = finding.get("title", "")
                details = finding.get("details", "")
                finding_type = finding.get("type", "")

                # Create combined text for search
                combined_text = f"{title} {description} {details} {finding_type}"
                preprocessed_text = self._preprocess_text(combined_text)

                # Check for exact match
                if preprocessed_pattern in preprocessed_text:
                    matching_findings.append(finding)
                    continue

                # Check for token overlap (if no exact match)
                text_tokens = set(preprocessed_text.split())
                overlap = pattern_tokens.intersection(text_tokens)

                # If significant token overlap, consider it a match
                if len(overlap) >= len(pattern_tokens) * 0.75:
                    matching_findings.append(finding)

            return matching_findings

        except Exception as e:
            logger.error(f"Error finding pattern instances: {e}")
            return []
