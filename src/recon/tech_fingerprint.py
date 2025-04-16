import logging
import httpx
from typing import Optional, List

# Absolute import for data types
from src.recon.types import TechInfo

logger = logging.getLogger(__name__)

# Define common headers we are interested in (lowercase for case-insensitive comparison)
TECH_HEADERS = {
    "server": "Server",
    "x-powered-by": "Powered By",
    # Add others like x-aspnet-version, etc. if needed
}

async def fingerprint_technology(target_url: str) -> Optional[TechInfo]:
    """Performs basic technology fingerprinting based on HTTP headers.

    Args:
        target_url: The target URL (including scheme).

    Returns:
        A TechInfo object or None if the request fails or no info is found.
    """
    logger.info(f"Starting technology fingerprinting for: {target_url}")
    tech_info = TechInfo()
    
    try:
        # Use httpx.AsyncClient for async operation
        # Follow redirects, verify SSL by default
        async with httpx.AsyncClient(follow_redirects=True, verify=True, timeout=10.0) as client:
            response = await client.get(target_url)
            
            # Check if request was successful (status code 2xx)
            response.raise_for_status() # Raise exception for 4xx/5xx

            logger.debug(f"Received headers for {target_url}: {response.headers}")

            # Extract relevant headers (case-insensitive lookup)
            tech_info.server_header = response.headers.get("server")
            tech_info.powered_by_header = response.headers.get("x-powered-by")
            
            # Basic detection based on headers (can be expanded significantly)
            if tech_info.server_header:
                server = tech_info.server_header.lower()
                if "nginx" in server:
                    tech_info.detected_technologies.append("Nginx")
                if "apache" in server:
                    tech_info.detected_technologies.append("Apache")
                if "iis" in server:
                    tech_info.detected_technologies.append("IIS")
            
            if tech_info.powered_by_header:
                powered_by = tech_info.powered_by_header.lower()
                if "php" in powered_by:
                    tech_info.detected_technologies.append("PHP")
                if "asp.net" in powered_by:
                     tech_info.detected_technologies.append("ASP.NET")
            
            # TODO: Add content-based checks (e.g., generator meta tags, specific JS files)

            logger.info(f"Finished technology fingerprinting for: {target_url}")
            return tech_info

    except httpx.RequestError as exc:
        # Covers connection errors, timeouts, too many redirects, etc.
        logger.warning(f"HTTP request failed for {target_url} during tech fingerprinting: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        # Handle non-2xx status codes (e.g., 404 Not Found, 500 Server Error)
        logger.warning(f"HTTP status error for {target_url}: {exc.response.status_code} - {exc}")
        # Still might try to return header info if available, but likely not useful
        # For now, return None on status errors.
        return None
    except Exception as e:
        logger.error(f"Unexpected error during tech fingerprinting for {target_url}: {e}", exc_info=True)
        return None

# Example Usage (requires async context)
async def main_example():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
    target = "https://google.com"
    info = await fingerprint_technology(target)
    
    print(f"\n--- Tech Info for {target} ---")
    if info:
        print(f"Server: {info.server_header}")
        print(f"X-Powered-By: {info.powered_by_header}")
        print(f"Detected: {info.detected_technologies}")
    else:
        print("Could not retrieve technology information.")

if __name__ == '__main__':
    import asyncio
    asyncio.run(main_example()) 