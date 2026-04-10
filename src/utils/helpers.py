"""
Utility Helper Functions
Common utility functions for NIDS
"""

import yaml
import json
import logging
import os
import sys

logger = logging.getLogger(__name__)


def load_config(config_file='config/config.yaml'):
    """
    Load configuration from YAML file

    Args:
        config_file (str): Path to configuration file

    Returns:
        dict: Configuration dictionary
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logger.critical("Configuration file not found: %s", config_file)
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.critical("Error parsing configuration file: %s", e)
        sys.exit(1)


def check_privileges():
    """
    Check if running with sufficient privileges for packet capture

    Returns:
        bool: True if running with root/admin privileges
    """
    if os.name == 'posix':
        # Unix/Linux/macOS
        if os.geteuid() != 0:
            logger.error("This program requires root privileges to capture packets.")
            logger.error("Please run with sudo: sudo python3 main.py")
            return False
    elif os.name == 'nt':
        # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.error("This program requires administrator privileges.")
                logger.error("Please run as administrator.")
                return False
        except (ImportError, AttributeError, OSError):
            pass

    return True


def get_available_interfaces():
    """
    Get list of available network interfaces

    Returns:
        list: List of network interface names
    """
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        logger.error("Error getting network interfaces: %s", e)
        return []


def print_banner():
    """Print NIDS banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   Network Intrusion Detection System (NIDS)              ║
    ║   Python-based Network Security Monitoring Tool          ║
    ║                                                           ║
    ║   Features:                                               ║
    ║   • Signature-based attack detection                     ║
    ║   • Anomaly-based behavioral analysis                    ║
    ║   • Real-time traffic monitoring                         ║
    ║   • Comprehensive alerting system                        ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def format_bytes(bytes_value):
    """
    Format bytes into human-readable format

    Args:
        bytes_value (int): Number of bytes

    Returns:
        str: Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def validate_ip(ip_address):
    """
    Validate IP address format

    Args:
        ip_address (str): IP address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def create_directory_structure():
    """Create necessary directories for NIDS"""
    directories = ['logs', 'rules', 'config']

    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def get_protocol_name(protocol_number):
    """
    Get protocol name from number

    Args:
        protocol_number (int): Protocol number

    Returns:
        str: Protocol name
    """
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        89: 'OSPF'
    }
    return protocols.get(protocol_number, f'Unknown ({protocol_number})')


def save_state(state_data, filename='nids_state.json'):
    """
    Save NIDS state to file

    Args:
        state_data (dict): State data to save
        filename (str): Output filename
    """
    try:
        with open(filename, 'w') as f:
            json.dump(state_data, f, indent=2)
        logger.info("State saved to %s", filename)
    except Exception as e:
        logger.error("Error saving state: %s", e)


def load_state(filename='nids_state.json'):
    """
    Load NIDS state from file

    Args:
        filename (str): State file to load

    Returns:
        dict: State data or None if error
    """
    try:
        with open(filename, 'r') as f:
            state_data = json.load(f)
        logger.info("State loaded from %s", filename)
        return state_data
    except FileNotFoundError:
        logger.warning("State file not found: %s", filename)
        return None
    except Exception as e:
        logger.error("Error loading state: %s", e)
        return None
