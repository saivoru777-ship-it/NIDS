"""Shared fixtures for NIDS tests"""

import os
import sys
import pytest
from datetime import datetime

# Add src to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


@pytest.fixture
def base_config():
    """Minimal config for testing"""
    return {
        'network': {'interface': 'lo0', 'promiscuous_mode': False, 'packet_count': 0},
        'signature_detection': {
            'enabled': True,
            'rules_file': os.path.join(os.path.dirname(__file__), '..', 'rules', 'signatures.json'),
            'port_scan': {'enabled': True, 'threshold': 20, 'time_window': 60},
            'syn_flood': {'enabled': True, 'threshold': 100, 'time_window': 10},
            'icmp_flood': {'enabled': True, 'threshold': 50, 'time_window': 5},
        },
        'anomaly_detection': {
            'enabled': True,
            'baseline_collection_time': 1,
            'baseline_refresh_interval': 3600,
            'traffic_volume': {'enabled': True, 'std_deviation_threshold': 3},
            'protocol_distribution': {'enabled': True, 'deviation_threshold': 0.3},
            'connection_pattern': {'enabled': True, 'unusual_port_threshold': 0.05},
        },
        'logging': {'enabled': True, 'log_directory': '/tmp/nids_test_logs', 'log_format': 'json', 'log_level': 'DEBUG'},
        'alerts': {'console_output': False, 'file_output': False},
        'analysis': {'top_talkers_count': 5, 'statistics_interval': 9999},
    }


@pytest.fixture
def make_packet_info():
    """Factory for creating packet_info dicts"""
    def _make(protocol='TCP', src_ip='10.0.0.1', dst_ip='10.0.0.2',
              src_port=12345, dst_port=80, tcp_flags=None, payload=None,
              packet_size=64, timestamp=None, **extra):
        info = {
            'timestamp': timestamp or datetime.now(),
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'tcp_flags': tcp_flags,
            'packet_size': packet_size,
            'payload': payload,
        }
        info.update(extra)
        return info
    return _make
