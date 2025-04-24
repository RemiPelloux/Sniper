# from typing import Annotated # No longer used

import re
from typing import Optional
from urllib.parse import urlparse

import typer
from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator


class Target(BaseModel):
    # Accept str, but ensure it validates to HttpUrl
    url: str = Field(
        ..., description="The target URL to scan, must include scheme (http/https)."
    )

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        # Use HttpUrl for validation during Pydantic's process
        try:
            HttpUrl(v)  # Try parsing/validating as HttpUrl
            return v  # Return original string if valid
        except ValidationError as e:
            raise ValueError(f"Invalid URL format: {e}") from e


def validate_target_url(url: str, auto_add_scheme: bool = False) -> Optional[str]:
    """Validate and normalize target URL.

    Args:
        url: The URL to validate
        auto_add_scheme: If True, automatically add http:// to URLs without a scheme

    Returns:
        Normalized URL if valid, None if invalid and auto_add_scheme is True

    Raises:
        typer.BadParameter: If URL is invalid and not a CLI context
        TypeError: If url is None

    Examples:
        >>> validate_target_url("https://example.com")
        'https://example.com'
        >>> validate_target_url("example.com", auto_add_scheme=True)
        'http://example.com'
    """
    # Check for None value
    if url is None:
        raise TypeError("URL cannot be None")

    if not url:
        if auto_add_scheme:
            return None
        else:
            raise typer.BadParameter("URL cannot be empty")

    # Handle URLs without scheme based on the auto_add_scheme flag
    if not url.startswith(("http://", "https://")):
        if auto_add_scheme:
            url = f"http://{url}"
        else:
            raise typer.BadParameter(
                f"Missing scheme (http:// or https://) in URL: {url}"
            )

    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            if auto_add_scheme:
                return None
            else:
                raise typer.BadParameter(
                    f"Invalid URL: {url} - Missing scheme or netloc"
                )

        # Extract domain without port or authentication info for validation
        domain = result.netloc
        # Remove authentication info if present
        if "@" in domain:
            domain = domain.split("@")[1]
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        # Basic domain validation
        domain_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        )
        if not re.match(domain_pattern, domain):
            if auto_add_scheme:
                return None
            else:
                raise typer.BadParameter(f"Invalid domain in URL: {url}")

        return url

    except typer.BadParameter:
        raise
    except Exception as e:
        if auto_add_scheme:
            return None
        else:
            raise typer.BadParameter(f"Invalid URL format: {url} - {str(e)}")
