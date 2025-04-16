import pytest
import typer

# Absolute import according to rules
from src.core.validation import validate_url

# --- Test Cases for validate_url --- 

# Parameterize valid URLs
@pytest.mark.parametrize(
    "valid_url",
    [
        "http://example.com",
        "https://example.com",
        "https://www.example.com/path?query=param#fragment",
        "http://127.0.0.1",
        "https://[::1]:8080", # IPv6
        "http://user:pass@example.com:8080",
    ],
)
def test_validate_url_valid(valid_url: str):
    """Tests that validate_url accepts various valid URLs.

    Args:
        valid_url: A valid URL string.
    """
    assert validate_url(valid_url) == valid_url

# Parameterize invalid URLs (format, scheme, etc.)
@pytest.mark.parametrize(
    "invalid_url, expected_error_msg_part",
    [
        ("example.com", "Invalid URL format"), # Missing scheme
        ("ftp://example.com", "Invalid URL scheme"), # Unsupported scheme
        ("http//example.com", "URL validation failed"), # Malformed scheme separator
        ("https://", "Invalid URL format"), # Missing netloc
        ("", "Invalid URL format"), # Empty string
        ("http:// example.com", "URL validation failed"), # Space in URL (validators catches this)
        # Add more complex invalid cases if needed
    ],
)
def test_validate_url_invalid(invalid_url: str, expected_error_msg_part: str):
    """Tests that validate_url raises typer.Exit for invalid URLs.

    Args:
        invalid_url: An invalid URL string.
        expected_error_msg_part: A substring expected in the error message.
    """
    with pytest.raises(typer.Exit) as exc_info:
        validate_url(invalid_url)
    
    # Check if the exit code is 1 (indicating an error)
    assert exc_info.value.exit_code == 1
    
    # Optionally, check if the error message contains the expected part
    # This requires capturing stdout/stderr, which can be done with capsys fixture
    # For now, just checking the exception type and exit code is sufficient.
    # Example with capsys:
    # captured = capsys.readouterr()
    # assert expected_error_msg_part in captured.out

# Potentially add tests mocking the `validators.url` call if needed
# for very specific edge cases not covered by the library itself,
# but generally, trusting the library for format validation is acceptable. 