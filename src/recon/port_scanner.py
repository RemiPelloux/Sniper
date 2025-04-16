import logging
import nmap # type: ignore # Ignore type hinting error for nmap module if necessary
from typing import Optional, List, Dict, Any

# Absolute import for data types
from src.recon.types import PortInfo, HostScanResults

logger = logging.getLogger(__name__)

# Default nmap arguments for a basic scan (Top 1000 TCP ports + Service Version)
# Adjust as needed (e.g., add -sU for UDP, -p- for all ports, -T4 for timing)
DEFAULT_NMAP_ARGS = "-sV -T4 --top-ports 1000"

def scan_ports(target_host: str, arguments: str = DEFAULT_NMAP_ARGS) -> Optional[HostScanResults]:
    """Performs a port scan on the target host using python-nmap.

    Requires nmap to be installed on the system.

    Args:
        target_host: The domain name or IP address to scan.
        arguments: Nmap command-line arguments (e.g., "-sV -p 1-1024").

    Returns:
        A HostScanResults object containing scan details, or None if scan fails or host is down.
    """
    logger.info(f"Starting Nmap port scan for: {target_host} with args: '{arguments}'")
    results = HostScanResults(host=target_host, status="unknown", open_ports=[])
    scan_data: Dict[str, Any] = {} # Initialize scan_data
    
    try:
        nm = nmap.PortScanner()
        # The scan() method takes hosts and arguments
        # It can raise PortScannerError if nmap is not found
        scan_data = nm.scan(hosts=target_host, arguments=arguments)
        
        logger.debug(f"Raw nmap scan data for {target_host}: {scan_data}")

        # Check if host was scanned and is up
        # nmap data structure: scan_data['scan'][ip_address]
        scanned_ips = list(scan_data.get('scan', {}).keys())
        if not scanned_ips:
            logger.warning(f"Nmap scan did not return results for host: {target_host}")
            results.status = "down" # Assume down if no scan results
            return results # Return results even if down, but with no ports

        # Assume the first IP is our target (nmap might resolve domain to IP)
        ip_address = scanned_ips[0]
        host_data = scan_data['scan'][ip_address]
        
        results.host = ip_address # Update host to the actual IP scanned
        results.status = host_data.get('status', {}).get('state', 'unknown')

        if results.status != "up":
            logger.info(f"Host {target_host} ({ip_address}) is reported as '{results.status}'. No open ports expected.")
            return results

        # Iterate through scanned protocols (tcp, udp, etc.)
        # Focusing on TCP for now as specified in DEFAULT_NMAP_ARGS implicitly
        tcp_ports_data = host_data.get('tcp', {})
        for port_num_str, port_data in tcp_ports_data.items():
            try:
                port_num = int(port_num_str)
                port_info = PortInfo(
                    port_number=port_num,
                    protocol="tcp",
                    state=port_data.get('state', 'unknown'),
                    service_name=port_data.get('name', None),
                    service_version=port_data.get('version', None),
                    # Add other fields like 'product', 'extrainfo' if needed
                )
                # Only add ports that are explicitly open
                if port_info.state == 'open':
                    results.open_ports.append(port_info)
                    logger.debug(f"Found open port: {port_info}")
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse port data for {ip_address}: {port_num_str} -> {port_data}. Error: {e}")
                continue

        logger.info(f"Finished Nmap scan for {target_host} ({ip_address}). Status: {results.status}, Open TCP Ports: {len(results.open_ports)}")
        return results

    except nmap.PortScannerError as e:
        logger.error(f"Nmap execution error: {e}. Is nmap installed and in PATH?")
        return None
    except KeyError as e:
        # Use scan_data in the error message if available
        raw_data_str = f"Raw data: {scan_data}" if scan_data else "Raw data unavailable."
        logger.error(f"Error parsing Nmap results for {target_host}: Missing key {e}. {raw_data_str}")
        return None # Or return partial results if appropriate
    except Exception as e:
        logger.error(f"Unexpected error during Nmap scan for {target_host}: {e}", exc_info=True)
        return None

# Example Usage
if __name__ == '__main__':
    # IMPORTANT: Running this example requires nmap installed!
    # Scan localhost as an example (use with caution on other hosts)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
    target = "127.0.0.1" 
    # target = "scanme.nmap.org" # Nmap test host
    
    scan_results = scan_ports(target)
    
    print(f"\n--- Nmap Scan Results for {target} ---")
    if scan_results:
        print(f"Host: {scan_results.host}")
        print(f"Status: {scan_results.status}")
        print("Open Ports:")
        if scan_results.open_ports:
            for port in scan_results.open_ports:
                version = f" ({port.service_version})" if port.service_version else ""
                print(f"  - Port {port.port_number}/{port.protocol}: {port.state} ({port.service_name}{version})")
        else:
            print("  (No open TCP ports found with current scan options)")
    else:
        print("Nmap scan failed or could not be executed.")
