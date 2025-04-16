# from typing import Annotated # No longer used

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


def validate_target_url(url_string: str) -> str:
    """
    Validates if the provided string is a valid HTTP/HTTPS URL.

    Args:
        url_string: The URL string to validate.

    Returns:
        The validated URL string.

    Raises:
        typer.BadParameter: If the URL is invalid.
    """
    try:
        # Validate using the Pydantic model
        validated_target = Target(url=url_string)
        # Return the validated *string*, not HttpUrl object for consistency
        return validated_target.url
    except ValidationError as e:
        # Extract a simpler error message if possible
        try:
            error_details = e.errors()[0]["ctx"]["error"]
            if isinstance(error_details, Exception):
                error_details = str(error_details)
        except (KeyError, IndexError, TypeError):
            error_details = str(e)

        raise typer.BadParameter(
            f"Invalid target URL: '{url_string}'. Error: {error_details}"
        ) from e
