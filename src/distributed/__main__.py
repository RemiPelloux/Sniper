"""
Main entry point for the distributed module.

This allows running the distributed CLI using:
python -m src.distributed
"""

from src.cli.distributed_typer import distributed_app

if __name__ == "__main__":
    distributed_app() 