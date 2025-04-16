import validators
import typer # Used only for typer.Exit
from urllib.parse import urlparse


def validate_url(url: str) -> str:
    """Validates the format and scheme of a given URL.

    Args:
        url: The URL string to validate.

    Returns:
        The validated URL string if valid.

    Raises:
        typer.Exit: If the URL is invalid.
    """
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print(f"Error: Invalid URL format: {url}. Must include scheme (e.g., 'https://').")
        raise typer.Exit(code=1)

    if parsed_url.scheme not in ["http", "https"]:
        print(f"Error: Invalid URL scheme: {parsed_url.scheme}. Only 'http' and 'https' are supported.")
        raise typer.Exit(code=1)

    # Use the validators library for a more robust format check
    validation_result = validators.url(url)
    if validation_result is not True: # validators returns True or ValidationError
        # The library might raise ValidationError, but we catch it broadly here
        # and provide a simpler error message.
        print(f"Error: URL validation failed: {url}")
        # We could potentially log `validation_result` for debugging
        raise typer.Exit(code=1)

    # Consider adding a basic connectivity check here (optional, could slow down CLI startup)
    # e.g., using requests.head(url, timeout=5) in a try-except block.
    # For now, we only validate the format.

    return url 