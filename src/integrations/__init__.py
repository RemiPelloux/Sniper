"""Integration modules for external security tools."""

# Import base classes for easy access
from src.integrations.base import ToolIntegration, ToolIntegrationError

# Import specific integrations
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.executors import BaseExecutor, ExecutionResult, SubprocessExecutor
from src.integrations.nmap import NmapIntegration
from src.integrations.owasp_zap import ZapIntegration
from src.integrations.sublist3r import Sublist3rIntegration
from src.integrations.wappalyzer import WappalyzerIntegration

__all__ = [
    # Base classes
    "ToolIntegration",
    "ToolIntegrationError",
    "BaseExecutor",
    "ExecutionResult",
    "SubprocessExecutor",
    # Tool integrations
    "DirsearchIntegration",
    "NmapIntegration",
    "Sublist3rIntegration",
    "WappalyzerIntegration",
    "ZapIntegration",
]
