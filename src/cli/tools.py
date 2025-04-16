import typer

app = typer.Typer(name="tools", help="Manage integrated security tools.")


@app.command("list")
def list_tools() -> None:
    """List available integrated tools."""
    print("Listing available tools...")
    # TODO: Implement tool listing logic
