import logging
from typing import List
import dns.resolver
import dns.exception
from urllib.parse import urlparse

# Absolute import for data types
from src.recon.types import DnsRecord, DnsResults

logger = logging.getLogger(__name__)

# Common DNS record types to query
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


def get_domain_from_url(target_url: str) -> str:
    """Extracts the network location (domain or IP address) from a URL."""
    try:
        parsed_url = urlparse(target_url)
        domain = parsed_url.hostname # Use hostname, which handles IPv6 brackets correctly
        if not domain:
            logger.error(f"Could not extract domain/hostname from URL: {target_url}")
            raise ValueError(f"Invalid URL for domain/hostname extraction: {target_url}")
        # Optional: Add validation here if needed (e.g., using validators.domain or validators.ipv6)
        return domain
    except Exception as e:
        logger.error(f"Error parsing URL {target_url} for domain/hostname extraction: {e}")
        raise ValueError(f"Could not parse URL: {target_url}")

def enumerate_dns(domain: str, record_types: List[str] = DEFAULT_RECORD_TYPES) -> DnsResults:
    """Performs DNS enumeration for specified record types on a domain.

    Args:
        domain: The domain name to query.
        record_types: A list of DNS record types to query (e.g., ["A", "MX"]).

    Returns:
        A DnsResults object containing the found records.
    """
    logger.info(f"Starting DNS enumeration for domain: {domain}")
    dns_results = DnsResults(domain=domain)
    resolver = dns.resolver.Resolver()
    # Configure resolver (optional: specify nameservers, timeout, etc.)
    # resolver.nameservers = ['8.8.8.8']
    # resolver.timeout = 2
    # resolver.lifetime = 5

    for r_type in record_types:
        try:
            logger.debug(f"Querying {r_type} records for {domain}")
            answers = resolver.resolve(domain, r_type)
            
            # Dynamically get the list attribute in DnsResults based on r_type
            # Ensure attribute exists before accessing
            attr_name = f"{r_type.lower()}_records"
            if not hasattr(dns_results, attr_name):
                logger.warning(f"DnsResults has no attribute {attr_name}, skipping record type {r_type}")
                continue
                
            result_list: List[DnsRecord] = getattr(dns_results, attr_name)

            for rdata in answers:
                # Handle different record types appropriately to get string value
                value = str(rdata)
                if r_type == "MX":
                    # MX records have preference and exchange
                    value = f"{rdata.preference} {rdata.exchange}"
                elif r_type == "TXT":
                    # TXT records can be bytes, decode them
                    # Also handle potential multiple strings in one TXT record
                    value = ' '.join(t.decode('utf-8', errors='replace') for t in rdata.strings)
                # Add more specific handling for other types if needed (SOA, SRV, etc.)
                
                record = DnsRecord(record_type=r_type, value=value)
                result_list.append(record)
                logger.debug(f"Found {r_type} record: {value}")

        except dns.resolver.NoAnswer:
            logger.debug(f"No {r_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain not found (NXDOMAIN): {domain}")
            # Stop further lookups for this domain if it doesn't exist
            break 
        except dns.exception.Timeout:
            logger.warning(f"DNS query timed out for {r_type} record at {domain}")
        except Exception as e:
            # Catch other potential dnspython exceptions or general errors
            logger.error(f"Error querying {r_type} for {domain}: {e}", exc_info=True)

    logger.info(f"Finished DNS enumeration for domain: {domain}")
    return dns_results

# Example Usage (for testing or direct calls)
if __name__ == '__main__':
    # Configure basic logging for standalone execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
    
    target_domain = "example.com"
    try:
        results = enumerate_dns(target_domain)
        print(f"\n--- DNS Results for {target_domain} ---")
        print(f"A Records: {results.a_records}")
        print(f"AAAA Records: {results.aaaa_records}")
        print(f"MX Records: {results.mx_records}")
        print(f"NS Records: {results.ns_records}")
        print(f"TXT Records: {results.txt_records}")
    except ValueError as e:
        print(f"Error: {e}")
    
    # Example with URL
    target_url = "https://www.google.com/search?q=dns"
    try:
        domain_from_url = get_domain_from_url(target_url)
        print(f"\nExtracted domain: {domain_from_url}")
        url_results = enumerate_dns(domain_from_url)
        print(f"\n--- DNS Results for {domain_from_url} ---")
        # ... print results ...
    except ValueError as e:
        print(f"Error: {e}")
