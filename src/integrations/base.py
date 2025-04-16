from abc import ABC, abstractmethod
from typing import Any

# Import the BaseFinding model
from src.results.types import BaseFinding

# Placeholder for future structured results
# from src.results.models import ScanResult


class ToolIntegrationError(Exception):
    """Base exception for tool integration errors."""

    pass


class ToolIntegration(ABC):
    """Abstract base class for all security tool integrations."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the official name of the integrated tool."""
        pass

    @abstractmethod
    def check_prerequisites(self) -> bool:
        """Check if the tool is installed and prerequisites are met.

        Returns:
            True if prerequisites are met, False otherwise.
        """
        pass

    @abstractmethod
    def run(self, target: str, options: dict[str, Any] | None = None) -> Any:
        """
        Run the tool against the specified target with given options.

        Args:
            target: The target URL or host.
            options: Tool-specific options dictionary.

        Returns:
            Raw output from the tool (e.g., stdout, file path, API response).
            The exact type depends on the tool and execution strategy.

        Raises:
            ToolIntegrationError: If the tool execution fails.
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: Any) -> list[BaseFinding] | None:
        """
        Parse the raw output from the tool into a standardized list of findings.

        Args:
            raw_output: The raw output from the 'run' method.

        Returns:
            A list of BaseFinding objects, or None if parsing fails or yields
            no results.

        Raises:
            ToolIntegrationError: If parsing fails due to an unexpected error.
        """
        pass
