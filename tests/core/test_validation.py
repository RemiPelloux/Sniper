import pytest
import typer

from src.core.validation import validate_target_url

# from pydantic import HttpUrl # No longer used


@pytest.mark.parametrize(
    "url_string, expected_valid",
    [
        ("https://example.com", True),
        ("http://example.com", True),
        ("http://example.com:8080", True),
        ("https://user:pass@example.com/path?query=1#fragment", True),
        ("ftp://example.com", False),  # Invalid scheme
        ("example.com", False),  # No scheme
        ("http://", False),  # No host
        ("invalid-url", False),
        ("", False),
    ],
)
def test_validate_target_url(url_string: str, expected_valid: bool) -> None:
    """Test the validate_target_url function with various inputs."""
    if expected_valid:
        result = validate_target_url(url_string)
        assert isinstance(result, str)
        # Simple string comparison is fine now
        assert result == url_string
    else:
        with pytest.raises(typer.BadParameter):
            validate_target_url(url_string)
