"""
Base Integration Module

This module defines the base classes for tool integrations used in the scanner.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

# Import the BaseFinding model
from src.results.types import BaseFinding

# Placeholder for future structured results
# from src.results.models import ScanResult


class ToolIntegrationError(Exception):
    """Exception raised when a tool integration fails"""
    pass


class ToolIntegration(ABC):
    """Abstract base class for tool integrations"""
    
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the tool"""
        pass
    
    @abstractmethod
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met for using this tool
        
        Returns:
            True if all prerequisites are met, False otherwise
        """
        pass
    
    @abstractmethod
    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run the tool against the target
        
        Args:
            target: The target to scan (URL, domain, IP, etc.)
            options: Additional options for the scan
            
        Returns:
            Dictionary with scan results
            
        Raises:
            ToolIntegrationError: If the scan fails
        """
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: Dict[str, Any]) -> Optional[List[BaseFinding]]:
        """Parse the raw output of the tool into normalized findings
        
        Args:
            raw_output: The raw output from the run method
            
        Returns:
            List of BaseFinding objects or None if parsing fails
        """
        pass
