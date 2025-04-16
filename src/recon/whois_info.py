import logging
import whois
from typing import Optional, List, Any # Import Any for flexible date handling
from datetime import datetime

# Absolute import for data types
from src.recon.types import WhoisInfo

logger = logging.getLogger(__name__)

def get_whois_info(domain: str) -> Optional[WhoisInfo]:
    """Retrieves and parses WHOIS information for a domain.

    Args:
        domain: The domain name to query.

    Returns:
        A WhoisInfo object containing the parsed data, or None if an error occurs.
    """
    logger.info(f"Starting WHOIS lookup for: {domain}")
    try:
        w = whois.whois(domain)
        
        # Check if WHOIS query returned substantial data
        # The library returns a whois.Domain object, check its attributes
        if not w or not w.domain_name:
            logger.warning(f"WHOIS query for {domain} returned no significant data.")
            return None
            
        # Helper function to handle potentially list-based date fields
        def _parse_date(date_field: Any) -> Optional[str]:
            if not date_field:
                return None
            # Handle cases where the library returns a list of datetimes
            if isinstance(date_field, list):
                # Use the first date if multiple are returned
                date_val = date_field[0] if date_field else None
            else:
                date_val = date_field
            
            if isinstance(date_val, datetime):
                return date_val.isoformat()
            return str(date_val) # Fallback to string representation

        # Helper to normalize name server lists
        def _parse_name_servers(ns_field: Any) -> List[str]:
            if not ns_field:
                return []
            if isinstance(ns_field, list):
                # Convert all items to lowercase strings
                return [str(ns).lower() for ns in ns_field]
            # Handle single string case
            return [str(ns_field).lower()]

        # Extract data safely, handling potential None values or lists
        registrar = w.get('registrar')
        creation_date_str = _parse_date(w.get('creation_date'))
        expiration_date_str = _parse_date(w.get('expiration_date'))
        name_servers = _parse_name_servers(w.get('name_servers'))
        
        info = WhoisInfo(
            registrar=str(registrar) if registrar else None,
            creation_date=creation_date_str,
            expiration_date=expiration_date_str,
            name_servers=name_servers,
        )
        logger.info(f"Successfully retrieved WHOIS info for: {domain}")
        logger.debug(f"WHOIS Data for {domain}: {info}")
        return info

    except whois.parser.PywhoisError as e:
        # Specific error from the library (e.g., no WHOIS server found)
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return None
    except Exception as e:
        # Catch broader errors (network issues, unexpected data format)
        logger.error(f"Unexpected error during WHOIS lookup for {domain}: {e}", exc_info=True)
        return None

# Example Usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
    target = "google.com" # Use a domain likely to have WHOIS info
    info = get_whois_info(target)
    
    print(f"\n--- WHOIS Info for {target} ---")
    if info:
        print(f"Registrar: {info.registrar}")
        print(f"Creation Date: {info.creation_date}")
        print(f"Expiration Date: {info.expiration_date}")
        print(f"Name Servers: {info.name_servers}")
    else:
        print("Could not retrieve WHOIS information.")
        
    target_nx = "domain-that-does-not-exist-qwerty.invalid"
    info_nx = get_whois_info(target_nx)
    print(f"\n--- WHOIS Info for {target_nx} ---")
    if info_nx:
        print("Retrieved info (unexpected)")
    else:
        print("Could not retrieve WHOIS information (as expected).") 