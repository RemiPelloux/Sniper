"""Integration modules for external security tools."""

# Import base classes for easy access
from src.integrations.base import ToolIntegration, ToolIntegrationError

# Import specific integrations
from src.integrations.dirsearch import DirsearchIntegration
from src.integrations.docker_utils import (
    check_and_ensure_tools,
    ensure_tool_available,
    is_docker_available,
    is_docker_compose_available,
)
from src.integrations.executors import BaseExecutor, ExecutionResult, SubprocessExecutor
from src.integrations.nmap import NmapIntegration
from src.integrations.owasp_zap import ZapIntegration
from src.integrations.subfinder import SubfinderIntegration
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
    "SubfinderIntegration",
    "WappalyzerIntegration",
    "ZapIntegration",
    # Docker utilities
    "ensure_tool_available",
    "check_and_ensure_tools",
    "is_docker_available",
    "is_docker_compose_available",
]
