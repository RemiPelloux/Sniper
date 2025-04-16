import pytest
from unittest.mock import patch, MagicMock
import nmap # For exception type

# Absolute imports
from src.recon.port_scanner import scan_ports, DEFAULT_NMAP_ARGS
from src.recon.types import HostScanResults, PortInfo

# --- Mock Nmap Scan Data ---

MOCK_SCAN_RESULT_UP_OPEN_PORTS = {
    'scan': {
        '127.0.0.1': {
            'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
            'addresses': {'ipv4': '127.0.0.1'},
            'status': {'state': 'up', 'reason': 'localhost-response'},
            'tcp': {
                22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.9p1 Ubuntu 3ubuntu0.1', 'extrainfo': 'protocol 2.0', 'conf': '10', 'cpe': 'cpe:/a:openbsd:openssh:8.9p1'},
                80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.52 ((Ubuntu))', 'conf': '10', 'cpe': 'cpe:/a:apache:http_server:2.4.52'},
                631: {'state': 'closed', 'reason': 'reset', 'name': 'ipp', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}
            }
        }
    },
    'nmap': {'command_line': f'nmap -oX - -sV -T4 --top-ports 1000 127.0.0.1', 'scaninfo': {},'scanstats': {'timestr': '...', 'elapsed': '...', 'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}}
}

MOCK_SCAN_RESULT_DOWN = {
    'scan': {
        '192.0.2.1': {
             'status': {'state': 'down', 'reason': 'no-response'}
         }
     },
     'nmap': {'scanstats': {'uphosts': '0', 'downhosts': '1', 'totalhosts': '1'}}
}

MOCK_SCAN_RESULT_UP_NO_OPEN = {
    'scan': {
        '192.0.2.2': {
            'status': {'state': 'up', 'reason': 'echo-reply'},
            'tcp': { # No open ports in the default top 1000
                 80: {'state': 'closed', 'reason': 'reset'},
                 443: {'state': 'closed', 'reason': 'reset'}
            }
        }
    },
    'nmap': {'scanstats': {'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}}
}

# --- Test Cases for scan_ports ---

@patch('src.recon.port_scanner.nmap.PortScanner')
def test_scan_ports_success_open(mock_port_scanner_cls):
    """Tests successful scan with open ports found."""
    target_host = "127.0.0.1"
    mock_scanner_instance = MagicMock()
    mock_scanner_instance.scan.return_value = MOCK_SCAN_RESULT_UP_OPEN_PORTS
    mock_port_scanner_cls.return_value = mock_scanner_instance
    
    result = scan_ports(target_host)
    
    assert isinstance(result, HostScanResults)
    assert result.host == "127.0.0.1" # Nmap scan uses IP
    assert result.status == "up"
    assert len(result.open_ports) == 2
    
    # Check details of the first open port (ssh)
    ssh_port = next((p for p in result.open_ports if p.port_number == 22), None)
    assert ssh_port is not None
    assert ssh_port.protocol == "tcp"
    assert ssh_port.state == "open"
    assert ssh_port.service_name == "ssh"
    assert ssh_port.service_version == "8.9p1 Ubuntu 3ubuntu0.1"
    
    # Check details of the second open port (http)
    http_port = next((p for p in result.open_ports if p.port_number == 80), None)
    assert http_port is not None
    assert http_port.protocol == "tcp"
    assert http_port.state == "open"
    assert http_port.service_name == "http"
    assert http_port.service_version == "2.4.52 ((Ubuntu))"
    
    mock_scanner_instance.scan.assert_called_once_with(hosts=target_host, arguments=DEFAULT_NMAP_ARGS)

@patch('src.recon.port_scanner.nmap.PortScanner')
def test_scan_ports_host_down(mock_port_scanner_cls):
    """Tests scan where the host is reported as down."""
    target_host = "192.0.2.1"
    mock_scanner_instance = MagicMock()
    # Simulate nmap returning scan data but with status 'down'
    mock_scanner_instance.scan.return_value = MOCK_SCAN_RESULT_DOWN
    mock_port_scanner_cls.return_value = mock_scanner_instance
    
    result = scan_ports(target_host)
    
    assert isinstance(result, HostScanResults)
    # Host might remain the original if IP resolution failed, or updated if it resolved
    # assert result.host == target_host or result.host == '192.0.2.1'
    assert result.host == '192.0.2.1' # Based on mock data structure
    assert result.status == "down"
    assert len(result.open_ports) == 0
    
    mock_scanner_instance.scan.assert_called_once_with(hosts=target_host, arguments=DEFAULT_NMAP_ARGS)

@patch('src.recon.port_scanner.nmap.PortScanner')
def test_scan_ports_up_no_open(mock_port_scanner_cls):
    """Tests scan where host is up but no common ports are open."""
    target_host = "192.0.2.2"
    mock_scanner_instance = MagicMock()
    mock_scanner_instance.scan.return_value = MOCK_SCAN_RESULT_UP_NO_OPEN
    mock_port_scanner_cls.return_value = mock_scanner_instance
    
    result = scan_ports(target_host)
    
    assert isinstance(result, HostScanResults)
    assert result.host == "192.0.2.2"
    assert result.status == "up"
    assert len(result.open_ports) == 0 # No open ports found
    
    mock_scanner_instance.scan.assert_called_once_with(hosts=target_host, arguments=DEFAULT_NMAP_ARGS)

@patch('src.recon.port_scanner.nmap.PortScanner')
def test_scan_ports_nmap_error(mock_port_scanner_cls, caplog):
    """Tests handling of PortScannerError (e.g., nmap not found)."""
    target_host = "error.com"
    error_message = "nmap program was not found in path"
    mock_port_scanner_cls.side_effect = nmap.PortScannerError(error_message)
    
    result = scan_ports(target_host)
    
    assert result is None
    # Check for key parts of the log message
    assert "Nmap execution error" in caplog.text
    assert error_message in caplog.text
    assert "Is nmap installed and in PATH?" in caplog.text

@patch('src.recon.port_scanner.nmap.PortScanner')
def test_scan_ports_key_error(mock_port_scanner_cls, caplog):
    """Tests handling when scan data lacks expected keys (e.g., 'tcp')."""
    target_host = "keyerror.com"
    ip_address = "1.2.3.4"
    # Simulate scan data where the host is up but the 'tcp' key is missing
    malformed_data = {'scan': {ip_address: {'status': {'state': 'up'}}}}
    mock_scanner_instance = MagicMock()
    mock_scanner_instance.scan.return_value = malformed_data
    mock_port_scanner_cls.return_value = mock_scanner_instance
    
    result = scan_ports(target_host)
    
    # The code handles missing 'tcp' gracefully by iterating over an empty dict
    # It should return the HostScanResults with status 'up' and no open ports.
    # The KeyError exception handler is for deeper parsing errors.
    assert isinstance(result, HostScanResults)
    assert result.host == ip_address
    assert result.status == 'up'
    assert len(result.open_ports) == 0
    # Ensure no KeyError was logged in this specific scenario
    assert "Error parsing Nmap results" not in caplog.text 
    assert "Missing key" not in caplog.text 