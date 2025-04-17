"""
Distributed Scanning Module for Sniper Security Tool

This module enables distributed scanning capabilities, allowing security scans to be
performed across multiple nodes in parallel for improved performance and scalability.

Features:
- Master-worker architecture for coordinating distributed scans
- Work distribution algorithms for efficient load balancing
- Result aggregation and normalization from multiple nodes
- Node health monitoring and fault tolerance
- Auto-scaling capabilities based on scan workload
- Communication protocols for secure node interaction
"""

import logging
import os
from pathlib import Path

# Create module logger
logger = logging.getLogger(__name__)

# Ensure the distributed config directory exists
DISTRIBUTED_CONFIG_DIR = Path(os.path.expanduser("~/.sniper/distributed"))
DISTRIBUTED_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
