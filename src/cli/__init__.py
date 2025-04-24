"""
Sniper Security Tool CLI

This package provides the command-line interface for the Sniper Security Tool.
"""

from src.cli.main import app as sniper_app
from src.cli.ml import ml
from src.cli.report import app as report_app
from src.cli.scan import app as scan_app
from src.cli.tools import tools_app

try:
    from src.cli.distributed_typer import distributed_app
except ImportError:
    # Distributed scanning architecture might not be available
    pass

__all__ = ["sniper_app", "ml", "scan_app", "report_app", "tools_app", "distributed_app"]
