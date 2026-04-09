"""
Anomaly-Based Detection Module
Detects network anomalies using statistical analysis and behavioral profiling
"""

import numpy as np
from collections import defaultdict, Counter
from datetime import datetime, timedelta


class AnomalyDetector:
    """Detects anomalies in network traffic based on statistical analysis"""

    def __init__(self, config, alert_callback):
        """
        Initialize anomaly detector

        Args:
            config (dict): Configuration dictionary
            alert_callback (function): Callback function for alerts
        """
        self.config = config
        self.alert_callback = alert_callback

        # Baseline collection
        self.baseline_collection_time = config.get('anomaly_detection', {}).get(
            'baseline_collection_time', 300
        )
        self.baseline_start_time = datetime.now()
        self.is_baseline_established = False

        # Traffic metrics for baseline
        self.baseline_traffic_volume = []  # packets per minute
        self.baseline_protocol_dist = Counter()
        self.baseline_port_usage = Counter()
        self.baseline_packet_sizes = []
        self.baseline_connections = defaultdict(int)

        # Current window metrics
        self.current_window_start = datetime.now()
        self.current_packets_count = 0
        self.current_protocol_dist = Counter()
        self.current_port_usage = Counter()
        self.current_packet_sizes = []
        self.current_connections = defaultdict(int)

        # Statistics
        self.baseline_stats = {}
        self.anomaly_count = 0

    def analyze_packet(self, packet_info):
        """
        Analyze packet for anomalies

        Args:
            packet_info (dict): Packet information dictionary
        """
        if not self.config.get('anomaly_detection', {}).get('enabled', True):
            return

        current_time = packet_info['timestamp']

        # Check if we're still collecting baseline
        if not self.is_baseline_established:
            self.collect_baseline(packet_info)
            time_elapsed = (current_time - self.baseline_start_time).total_seconds()
            if time_elapsed >= self.baseline_collection_time:
                self.establish_baseline()
        else:
            # Perform anomaly detection
            self.update_current_window(packet_info)
            self.detect_anomalies(packet_info)

    def collect_baseline(self, packet_info):
        """
        Collect baseline traffic data

        Args:
            packet_info (dict): Packet information
        """
        self.current_packets_count += 1

        # Collect protocol distribution
        if packet_info['protocol']:
            self.baseline_protocol_dist[packet_info['protocol']] += 1

        # Collect port usage
        if packet_info['dst_port']:
            self.baseline_port_usage[packet_info['dst_port']] += 1

        # Collect packet sizes
        if packet_info['packet_size']:
            self.baseline_packet_sizes.append(packet_info['packet_size'])

        # Collect connection patterns
        if packet_info['src_ip'] and packet_info['dst_ip']:
            conn_key = f"{packet_info['src_ip']}->{packet_info['dst_ip']}"
            self.baseline_connections[conn_key] += 1

        # Update traffic volume per minute
        current_time = packet_info['timestamp']
        time_diff = (current_time - self.current_window_start).total_seconds()
        if time_diff >= 60:  # 1 minute window
            self.baseline_traffic_volume.append(self.current_packets_count)
            self.current_packets_count = 0
            self.current_window_start = current_time

    def establish_baseline(self):
        """Establish baseline statistics from collected data"""
        print("\n[*] Establishing baseline from collected data...")

        # Calculate traffic volume statistics
        if self.baseline_traffic_volume:
            self.baseline_stats['traffic_volume_mean'] = np.mean(self.baseline_traffic_volume)
            self.baseline_stats['traffic_volume_std'] = np.std(self.baseline_traffic_volume)
        else:
            self.baseline_stats['traffic_volume_mean'] = 0
            self.baseline_stats['traffic_volume_std'] = 0

        # Calculate protocol distribution
        total_packets = sum(self.baseline_protocol_dist.values())
        if total_packets > 0:
            self.baseline_stats['protocol_distribution'] = {
                proto: count / total_packets
                for proto, count in self.baseline_protocol_dist.items()
            }
        else:
            self.baseline_stats['protocol_distribution'] = {}

        # Calculate port usage frequencies
        total_port_usage = sum(self.baseline_port_usage.values())
        if total_port_usage > 0:
            self.baseline_stats['port_frequencies'] = {
                port: count / total_port_usage
                for port, count in self.baseline_port_usage.items()
            }
        else:
            self.baseline_stats['port_frequencies'] = {}

        # Calculate packet size statistics
        if self.baseline_packet_sizes:
            self.baseline_stats['packet_size_mean'] = np.mean(self.baseline_packet_sizes)
            self.baseline_stats['packet_size_std'] = np.std(self.baseline_packet_sizes)
        else:
            self.baseline_stats['packet_size_mean'] = 0
            self.baseline_stats['packet_size_std'] = 0

        self.is_baseline_established = True

        # Print baseline summary
        print(f"[+] Baseline established:")
        print(f"    - Average traffic: {self.baseline_stats['traffic_volume_mean']:.2f} packets/min")
        print(f"    - Protocol distribution: {dict(self.baseline_stats['protocol_distribution'])}")
        print(f"    - Average packet size: {self.baseline_stats['packet_size_mean']:.2f} bytes")
        print(f"[*] Now monitoring for anomalies...\n")

        # Reset current window
        self.current_window_start = datetime.now()
        self.current_packets_count = 0
        self.current_protocol_dist = Counter()
        self.current_port_usage = Counter()
        self.current_packet_sizes = []

    def update_current_window(self, packet_info):
        """
        Update current monitoring window

        Args:
            packet_info (dict): Packet information
        """
        self.current_packets_count += 1

        # Update protocol distribution
        if packet_info['protocol']:
            self.current_protocol_dist[packet_info['protocol']] += 1

        # Update port usage
        if packet_info['dst_port']:
            self.current_port_usage[packet_info['dst_port']] += 1

        # Update packet sizes
        if packet_info['packet_size']:
            self.current_packet_sizes.append(packet_info['packet_size'])

    def detect_anomalies(self, packet_info):
        """
        Detect anomalies in current traffic

        Args:
            packet_info (dict): Packet information
        """
        current_time = packet_info['timestamp']
        time_diff = (current_time - self.current_window_start).total_seconds()

        # Check traffic volume anomaly every minute
        if time_diff >= 60 and self.config.get('anomaly_detection', {}).get('traffic_volume', {}).get('enabled', True):
            self.detect_traffic_volume_anomaly(current_time)

        # Check protocol distribution anomaly
        if self.config.get('anomaly_detection', {}).get('protocol_distribution', {}).get('enabled', True):
            self.detect_protocol_anomaly(packet_info)

        # Check unusual port usage
        if self.config.get('anomaly_detection', {}).get('connection_pattern', {}).get('enabled', True):
            self.detect_unusual_port(packet_info)

    def detect_traffic_volume_anomaly(self, current_time):
        """
        Detect anomalies in traffic volume

        Args:
            current_time (datetime): Current timestamp
        """
        mean = self.baseline_stats.get('traffic_volume_mean', 0)
        std = self.baseline_stats.get('traffic_volume_std', 0)

        if mean == 0:
            return

        # Calculate Z-score
        std_threshold = self.config.get('anomaly_detection', {}).get(
            'traffic_volume', {}
        ).get('std_deviation_threshold', 3)

        threshold = mean + (std_threshold * std)

        if self.current_packets_count > threshold:
            self.anomaly_count += 1
            self.alert_callback({
                'type': 'traffic_volume_anomaly',
                'severity': 'medium',
                'timestamp': current_time,
                'description': f"Traffic volume anomaly: {self.current_packets_count} packets (baseline: {mean:.0f} ± {std:.0f})",
                'details': {
                    'current_volume': self.current_packets_count,
                    'baseline_mean': mean,
                    'baseline_std': std,
                    'threshold': threshold,
                    'deviation': (self.current_packets_count - mean) / std if std > 0 else 0
                }
            })

        # Reset window
        self.current_packets_count = 0
        self.current_window_start = current_time

    def detect_protocol_anomaly(self, packet_info):
        """
        Detect anomalies in protocol distribution

        Args:
            packet_info (dict): Packet information
        """
        protocol = packet_info['protocol']
        if not protocol:
            return

        baseline_dist = self.baseline_stats.get('protocol_distribution', {})
        if not baseline_dist:
            return

        # Calculate current distribution
        total_current = sum(self.current_protocol_dist.values())
        if total_current < 100:  # Wait for enough samples
            return

        current_freq = self.current_protocol_dist[protocol] / total_current
        baseline_freq = baseline_dist.get(protocol, 0)

        # Check for significant deviation
        deviation_threshold = self.config.get('anomaly_detection', {}).get(
            'protocol_distribution', {}
        ).get('deviation_threshold', 0.3)

        if baseline_freq > 0:
            deviation = abs(current_freq - baseline_freq) / baseline_freq
            if deviation > deviation_threshold:
                self.anomaly_count += 1
                self.alert_callback({
                    'type': 'protocol_distribution_anomaly',
                    'severity': 'medium',
                    'timestamp': packet_info['timestamp'],
                    'description': f"Protocol distribution anomaly: {protocol}",
                    'details': {
                        'protocol': protocol,
                        'current_frequency': current_freq,
                        'baseline_frequency': baseline_freq,
                        'deviation': deviation
                    }
                })

    def detect_unusual_port(self, packet_info):
        """
        Detect unusual port usage

        Args:
            packet_info (dict): Packet information
        """
        dst_port = packet_info['dst_port']
        if not dst_port:
            return

        port_frequencies = self.baseline_stats.get('port_frequencies', {})
        if not port_frequencies:
            return

        # Check if port was rarely or never used in baseline
        threshold = self.config.get('anomaly_detection', {}).get(
            'connection_pattern', {}
        ).get('unusual_port_threshold', 0.95)

        baseline_freq = port_frequencies.get(dst_port, 0)

        # If port wasn't in baseline or used very rarely, it's unusual
        if baseline_freq == 0 or baseline_freq < (1 - threshold):
            # Avoid alert spam - only alert on first occurrence
            if dst_port not in self.current_port_usage or self.current_port_usage[dst_port] == 1:
                self.anomaly_count += 1
                self.alert_callback({
                    'type': 'unusual_port_usage',
                    'severity': 'low',
                    'timestamp': packet_info['timestamp'],
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"Unusual port usage detected: port {dst_port}",
                    'details': {
                        'port': dst_port,
                        'baseline_frequency': baseline_freq,
                        'protocol': packet_info['protocol']
                    }
                })

    def get_statistics(self):
        """Get anomaly detection statistics"""
        return {
            'baseline_established': self.is_baseline_established,
            'baseline_stats': self.baseline_stats,
            'anomaly_count': self.anomaly_count,
            'current_window_packets': self.current_packets_count
        }
