#!/usr/bin/env python3
"""
Test script to demonstrate the phase-based tool recommendation feature.
This script shows how the SmartRecon module recommends different tools 
based on the assessment phase for the same target.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional, Union

# Add the parent directory to sys.path
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

from src.ml.smart_recon import SmartRecon

# Create a simple Target class for testing purposes
class Target:
    """Simple Target class for testing purposes."""
    
    def __init__(
        self, 
        url: str, 
        ip: str, 
        ports: List[int],
        domain: str,
        technologies: List[str],
        services: Dict[str, str],
        os: str
    ):
        self.url = url
        self.ip = ip
        self.ports = ports
        self.domain = domain
        self.technologies = technologies
        self.services = services
        self.os = os
    
    def to_dict(self) -> Dict:
        """Convert Target to dictionary format for SmartRecon."""
        return {
            "host": self.domain,
            "port": self.ports[0] if self.ports else None,
            "protocol": "https" if "https" in self.services else "http",
            "services": list(self.services.keys()),
            "technologies": self.technologies,
            "ip": self.ip,
            "os": self.os
        }

def main():
    # Initialize the SmartRecon module
    smart_recon = SmartRecon()
    
    # Create a sample target
    target = Target(
        url="https://example.com",
        ip="93.184.216.34",
        ports=[80, 443],
        domain="example.com",
        technologies=["Apache", "PHP", "MySQL"],
        services={"http": "80", "https": "443"},
        os="Unknown"
    )
    
    # Get recommendations for different phases
    phases = ["reconnaissance", "vulnerability scanning", "exploitation"]
    
    print("\n=== Phase-Based Tool Recommendations ===\n")
    
    # Test each phase with the same target
    for phase in phases:
        print(f"\nPhase: {phase.upper()}")
        print("-" * 50)
        
        # Get recommendations for this phase
        recommendations = smart_recon.recommend_tools(
            target=target.to_dict(),
            context={"assessment_phase": phase, "max_recommendations": 5}
        )
        
        # Print the recommendations
        for i, recommendation in enumerate(recommendations, 1):
            tool = recommendation.get("tool_name", "Unknown")
            confidence = recommendation.get("confidence", 0.0)
            reasons = recommendation.get("reasons", [])
            reasons_str = "; ".join(reasons) if reasons else "No specific reason provided"
            
            print(f"{i}. {tool} (confidence: {confidence:.2f})")
            print(f"   Reason: {reasons_str}")
    
    print("\n=== Comparison of Top Recommendations ===\n")
    
    # Compare top recommendations for each phase
    results = {}
    for phase in phases:
        recommendations = smart_recon.recommend_tools(
            target=target.to_dict(),
            context={"assessment_phase": phase, "max_recommendations": 2}
        )
        results[phase] = [rec.get("tool_name", "Unknown") for rec in recommendations]
    
    # Print a summary table
    print(f"{'Phase':<25} {'Top Recommendations'}")
    print("-" * 60)
    for phase, tools in results.items():
        print(f"{phase:<25} {', '.join(tools)}")

if __name__ == "__main__":
    main() 