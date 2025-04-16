import logging
import socket
import ssl
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime

# Absolute import for data types
from src.recon.types import SslCertInfo

logger = logging.getLogger(__name__)

# Default HTTPS port
DEFAULT_SSL_PORT = 443

def _parse_rdn_sequence(rdn_sequence: Tuple[Tuple[Tuple[str, str]]]) -> Dict[str, str]:
    """Parses the RDNSequence structure into a simple dictionary."""
    # Example input: ((('commonName', 'example.com'),), (('organizationName', 'Example Inc'),))
    parsed: Dict[str, str] = {}
    for rdn_set in rdn_sequence:
        for rdn in rdn_set:
            # rdn is a tuple like ('commonName', 'value')
            if len(rdn) == 2:
                attr_type, attr_value = rdn
                parsed[attr_type] = attr_value
    return parsed

def _format_date(date_str: Optional[str]) -> Optional[str]:
    """Formats the SSL date string (e.g., 'Sep 15 04:00:00 1997 GMT') to ISO format."""
    if not date_str:
        return None
    try:
        # Use the specific format required by ssl.getpeercert
        dt_obj = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        return dt_obj.isoformat()
    except ValueError:
        logger.warning(f"Could not parse certificate date string: {date_str}")
        return date_str # Return original string if parsing fails

def get_ssl_info(domain: str, port: int = DEFAULT_SSL_PORT) -> Optional[SslCertInfo]:
    """Retrieves and parses SSL/TLS certificate information for a domain/host.

    Args:
        domain: The domain or IP address to connect to.
        port: The port to connect to (usually 443 for HTTPS).

    Returns:
        An SslCertInfo object containing parsed certificate details, or None if an error occurs.
    """
    logger.info(f"Attempting SSL/TLS connection to {domain}:{port}")
    context = ssl.create_default_context()
    
    try:
        # Establish connection and wrap socket with SSL
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get peer certificate details (binary DER format and parsed dict)
                cert_dict: Optional[Dict[str, Any]] = ssock.getpeercert()

        if not cert_dict:
            logger.warning(f"Could not retrieve peer certificate from {domain}:{port}")
            return None

        logger.debug(f"Raw certificate dict for {domain}: {cert_dict}")

        # Parse relevant fields
        issuer_dict = _parse_rdn_sequence(cert_dict.get('issuer', (())))
        subject_dict = _parse_rdn_sequence(cert_dict.get('subject', (())))
        valid_from_str = _format_date(cert_dict.get('notBefore'))
        valid_until_str = _format_date(cert_dict.get('notAfter'))
        
        # Extract Subject Alternative Names (SANs)
        sans_list: List[str] = []
        san_tuples = cert_dict.get('subjectAltName', [])
        for san_type, san_value in san_tuples:
            # We are typically interested in DNS names
            if san_type == 'DNS':
                sans_list.append(san_value)
            # Could also include IP addresses if needed (san_type == 'IP Address')

        info = SslCertInfo(
            # Convert dicts to string representations for simplicity
            issuer=str(issuer_dict) if issuer_dict else None,
            subject=str(subject_dict) if subject_dict else None,
            valid_from=valid_from_str,
            valid_until=valid_until_str,
            sans=sans_list
        )
        
        logger.info(f"Successfully retrieved SSL/TLS info for: {domain}:{port}")
        return info

    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL Certificate Verification Error for {domain}:{port}: {e}")
        # Depending on policy, might want to return partial info or None
        return None 
    except socket.timeout:
        logger.warning(f"Connection timed out when connecting to {domain}:{port} for SSL info.")
        return None
    except socket.gaierror:
        logger.warning(f"Could not resolve hostname {domain} for SSL info.")
        return None
    except ConnectionRefusedError:
        logger.warning(f"Connection refused by {domain}:{port} for SSL info.")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting SSL info for {domain}:{port}: {e}", exc_info=True)
        return None

# Example Usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
    target = "google.com"
    ssl_info = get_ssl_info(target)
    
    print(f"\n--- SSL/TLS Info for {target} ---")
    if ssl_info:
        print(f"Issuer: {ssl_info.issuer}")
        print(f"Subject: {ssl_info.subject}")
        print(f"Valid From: {ssl_info.valid_from}")
        print(f"Valid Until: {ssl_info.valid_until}")
        print(f"SANs: {ssl_info.sans}")
    else:
        print("Could not retrieve SSL/TLS information.")

    target_nx = "domain-that-does-not-exist-qwerty.invalid"
    ssl_info_nx = get_ssl_info(target_nx)
    print(f"\n--- SSL/TLS Info for {target_nx} ---")
    if ssl_info_nx:
        print("Retrieved info (unexpected)")
    else:
        print("Could not retrieve SSL/TLS information (as expected).") 