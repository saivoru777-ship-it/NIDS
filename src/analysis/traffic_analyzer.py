"""
Traffic Analyzer Module
Analyzes network traffic patterns and provides statistics
"""

import logging
import threading
from collections import Counter, defaultdict, deque
from datetime import datetime

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Analyzes network traffic and generates statistics"""

    def __init__(self, config):
        """
        Initialize traffic analyzer

        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self._lock = threading.Lock()

        # Traffic statistics
        self.total_packets = 0
        self.protocol_counter = Counter()
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()
        self.port_counter = Counter()
        self.packet_sizes = deque(maxlen=100000)

        # Connection tracking
        self.connections = defaultdict(int)
        self.unique_src_ips = set()
        self.unique_dst_ips = set()

        # Time-based statistics
        self.start_time = datetime.now()
        self.last_stats_time = datetime.now()

    def analyze_packet(self, packet_info):
        """
        Analyze packet and update statistics

        Args:
            packet_info (dict): Packet information dictionary
        """
        with self._lock:
            self.total_packets += 1

            # Track protocol distribution
            if packet_info['protocol']:
                self.protocol_counter[packet_info['protocol']] += 1

            # Track source IPs
            if packet_info['src_ip']:
                self.src_ip_counter[packet_info['src_ip']] += 1
                self.unique_src_ips.add(packet_info['src_ip'])

            # Track destination IPs
            if packet_info['dst_ip']:
                self.dst_ip_counter[packet_info['dst_ip']] += 1
                self.unique_dst_ips.add(packet_info['dst_ip'])

            # Track port usage
            if packet_info['dst_port']:
                self.port_counter[packet_info['dst_port']] += 1

            # Track packet sizes
            if packet_info['packet_size']:
                self.packet_sizes.append(packet_info['packet_size'])

            # Track connections
            if packet_info['src_ip'] and packet_info['dst_ip']:
                conn_key = f"{packet_info['src_ip']} -> {packet_info['dst_ip']}"
                self.connections[conn_key] += 1

            # Periodically print statistics
            current_time = packet_info['timestamp']
            stats_interval = self.config.get('analysis', {}).get('statistics_interval', 60)
            if (current_time - self.last_stats_time).total_seconds() >= stats_interval:
                self.print_statistics()
                self.last_stats_time = current_time

    def get_top_talkers(self, count=10):
        """
        Get top source IPs by packet count

        Args:
            count (int): Number of top talkers to return

        Returns:
            list: List of (IP, count) tuples
        """
        return self.src_ip_counter.most_common(count)

    def get_top_destinations(self, count=10):
        """
        Get top destination IPs by packet count

        Args:
            count (int): Number of top destinations to return

        Returns:
            list: List of (IP, count) tuples
        """
        return self.dst_ip_counter.most_common(count)

    def get_top_ports(self, count=10):
        """
        Get most commonly accessed ports

        Args:
            count (int): Number of top ports to return

        Returns:
            list: List of (port, count) tuples
        """
        return self.port_counter.most_common(count)

    def get_protocol_distribution(self):
        """
        Get protocol distribution

        Returns:
            dict: Protocol distribution with percentages
        """
        if self.total_packets == 0:
            return {}

        return {
            protocol: {
                'count': count,
                'percentage': (count / self.total_packets) * 100
            }
            for protocol, count in self.protocol_counter.items()
        }

    def get_average_packet_size(self):
        """
        Get average packet size

        Returns:
            float: Average packet size in bytes
        """
        if not self.packet_sizes:
            return 0
        return sum(self.packet_sizes) / len(self.packet_sizes)

    def get_traffic_rate(self):
        """
        Get current traffic rate

        Returns:
            float: Packets per second
        """
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        if elapsed_time == 0:
            return 0
        return self.total_packets / elapsed_time

    def print_statistics(self):
        """Print current traffic statistics"""
        elapsed_time = (datetime.now() - self.start_time).total_seconds()

        lines = [
            "", "=" * 60, "TRAFFIC STATISTICS", "=" * 60,
            f"\nTotal Packets Captured: {self.total_packets}",
            f"Elapsed Time: {elapsed_time:.2f} seconds",
            f"Traffic Rate: {self.get_traffic_rate():.2f} packets/sec",
            f"Average Packet Size: {self.get_average_packet_size():.2f} bytes",
            "\nProtocol Distribution:"
        ]

        protocol_dist = self.get_protocol_distribution()
        for protocol, stats in sorted(protocol_dist.items(), key=lambda x: x[1]['count'], reverse=True):
            lines.append(f"  {protocol:10s}: {stats['count']:6d} packets ({stats['percentage']:.2f}%)")

        lines.append("\nTop Source IPs (Top Talkers):")
        top_count = self.config.get('analysis', {}).get('top_talkers_count', 10)
        for ip, count in self.get_top_talkers(top_count):
            percentage = (count / self.total_packets) * 100
            lines.append(f"  {ip:20s}: {count:6d} packets ({percentage:.2f}%)")

        lines.append("\nTop Destination IPs:")
        for ip, count in self.get_top_destinations(top_count):
            percentage = (count / self.total_packets) * 100
            lines.append(f"  {ip:20s}: {count:6d} packets ({percentage:.2f}%)")

        lines.append("\nMost Accessed Ports:")
        for port, count in self.get_top_ports(10):
            port_name = self.get_port_name(port)
            percentage = (count / self.total_packets) * 100
            lines.append(f"  {port:6d} ({port_name:15s}): {count:6d} packets ({percentage:.2f}%)")

        lines.append("=" * 60)
        logger.info("\n".join(lines))

    def get_port_name(self, port):
        """
        Get common port name

        Args:
            port (int): Port number

        Returns:
            str: Port name or 'Unknown'
        """
        common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return common_ports.get(port, 'Unknown')

    def get_summary(self):
        """
        Get summary of traffic analysis

        Returns:
            dict: Summary statistics
        """
        return {
            'total_packets': self.total_packets,
            'unique_src_ips': len(self.unique_src_ips),
            'unique_dst_ips': len(self.unique_dst_ips),
            'traffic_rate': self.get_traffic_rate(),
            'avg_packet_size': self.get_average_packet_size(),
            'protocol_distribution': self.get_protocol_distribution(),
            'top_talkers': self.get_top_talkers(5),
            'top_ports': self.get_top_ports(5)
        }
