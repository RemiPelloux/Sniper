from typer.testing import CliRunner

from src import __version__
from src.cli.main import app

runner = CliRunner()


def test_version_option() -> None:
    """Test the --version option."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
    assert "Sniper CLI" in result.stdout  # Check for app name


def test_help_option() -> None:
    """Test the --help option."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # Check for presence of commands
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "tools" in result.stdout
    assert "ml" in result.stdout
