import typer

# Import the validator
from src.core.validation import validate_target_url

# from pydantic import HttpUrl # No longer used


app = typer.Typer(name="scan", help="Perform security scans on targets.")


@app.command("run")
def run_scan(
    target: str = typer.Argument(
        ...,
        help="Target URL to scan (must include scheme, e.g., https://example.com).",
        callback=validate_target_url,  # Use the validator here
    )
) -> None:
    """Run a security scan on the specified target."""
    # target is now a validated string
    print(f"Initiating scan on validated target: {target}")
    # TODO: Implement scan logic
