"""
Signature-Based Detection Module
Detects known attack patterns using signature matching
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict


class SignatureDetector:
    """Detects known attack patterns based on signatures"""

    def __init__(self, config, alert_callback):
        """
        Initialize signature detector

        Args:
            config (dict): Configuration dictionary
            alert_callback (function): Callback function for alerts
        """
        self.config = config
        self.alert_callback = alert_callback
        self.signatures = []
        self.load_signatures()

        # Tracking dictionaries for various attacks
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': None})
        self.syn_flood_tracker = defaultdict(lambda: {'syn_count': 0, 'ack_count': 0, 'first_seen': None})
        self.icmp_flood_tracker = defaultdict(lambda: {'count': 0, 'first_seen': None})
        self.connection_attempts = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'first_seen': None}))
        self.arp_cache = {}  # IP -> MAC mapping

    def load_signatures(self):
        """Load attack signatures from JSON file"""
        try:
            rules_file = self.config.get('signature_detection', {}).get('rules_file', 'rules/signatures.json')
            with open(rules_file, 'r') as f:
                data = json.load(f)
                self.signatures = data.get('signatures', [])
            print(f"[*] Loaded {len(self.signatures)} attack signatures")
        except Exception as e:
            print(f"[!] Error loading signatures: {e}")
            self.signatures = []

    def analyze_packet(self, packet_info):
        """
        Analyze packet against all signatures

        Args:
            packet_info (dict): Packet information dictionary
        """
        if not self.config.get('signature_detection', {}).get('enabled', True):
            return

        # Check for port scanning
        if self.config.get('signature_detection', {}).get('port_scan', {}).get('enabled', True):
            self.detect_port_scan(packet_info)

        # Check for SYN flood
        if self.config.get('signature_detection', {}).get('syn_flood', {}).get('enabled', True):
            self.detect_syn_flood(packet_info)

        # Check for ICMP flood
        if self.config.get('signature_detection', {}).get('icmp_flood', {}).get('enabled', True):
            self.detect_icmp_flood(packet_info)

        # Check for ARP spoofing
        self.detect_arp_spoofing(packet_info)

        # Check against loaded signatures
        self.check_signatures(packet_info)

    def detect_port_scan(self, packet_info):
        """
        Detect port scanning attempts

        Args:
            packet_info (dict): Packet information
        """
        if packet_info['protocol'] != 'TCP' or not packet_info['dst_port']:
            return

        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']

        # Track unique ports accessed by this IP
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip]['first_seen'] = current_time

        self.port_scan_tracker[src_ip]['ports'].add(dst_port)

        # Check if time window has passed
        time_window = self.config.get('signature_detection', {}).get('port_scan', {}).get('time_window', 60)
        threshold = self.config.get('signature_detection', {}).get('port_scan', {}).get('threshold', 20)

        first_seen = self.port_scan_tracker[src_ip]['first_seen']
        time_diff = (current_time - first_seen).total_seconds()

        if time_diff <= time_window:
            port_count = len(self.port_scan_tracker[src_ip]['ports'])
            if port_count >= threshold:
                self.alert_callback({
                    'type': 'port_scan',
                    'severity': 'high',
                    'timestamp': current_time,
                    'src_ip': src_ip,
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"Port scan detected: {port_count} unique ports scanned",
                    'details': {
                        'port_count': port_count,
                        'time_window': time_diff
                    }
                })
                # Reset tracker
                self.port_scan_tracker[src_ip]['ports'].clear()
                self.port_scan_tracker[src_ip]['first_seen'] = current_time
        else:
            # Reset if time window exceeded
            self.port_scan_tracker[src_ip]['ports'].clear()
            self.port_scan_tracker[src_ip]['first_seen'] = current_time

    def detect_syn_flood(self, packet_info):
        """
        Detect SYN flood attacks

        Args:
            packet_info (dict): Packet information
        """
        if packet_info['protocol'] != 'TCP' or not packet_info['tcp_flags']:
            return

        src_ip = packet_info['src_ip']
        tcp_flags = packet_info['tcp_flags']
        current_time = packet_info['timestamp']

        # Initialize tracker if needed
        if src_ip not in self.syn_flood_tracker:
            self.syn_flood_tracker[src_ip]['first_seen'] = current_time

        # Check for SYN flag (S)
        if 'S' in str(tcp_flags) and 'A' not in str(tcp_flags):
            self.syn_flood_tracker[src_ip]['syn_count'] += 1
        elif 'A' in str(tcp_flags):
            self.syn_flood_tracker[src_ip]['ack_count'] += 1

        # Check threshold
        time_window = self.config.get('signature_detection', {}).get('syn_flood', {}).get('time_window', 10)
        threshold = self.config.get('signature_detection', {}).get('syn_flood', {}).get('threshold', 100)

        first_seen = self.syn_flood_tracker[src_ip]['first_seen']
        time_diff = (current_time - first_seen).total_seconds()

        if time_diff <= time_window:
            syn_count = self.syn_flood_tracker[src_ip]['syn_count']
            ack_count = self.syn_flood_tracker[src_ip]['ack_count']

            if syn_count >= threshold and syn_count > ack_count * 2:
                self.alert_callback({
                    'type': 'syn_flood',
                    'severity': 'critical',
                    'timestamp': current_time,
                    'src_ip': src_ip,
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"SYN flood detected: {syn_count} SYN packets",
                    'details': {
                        'syn_count': syn_count,
                        'ack_count': ack_count,
                        'time_window': time_diff
                    }
                })
                # Reset tracker
                self.syn_flood_tracker[src_ip]['syn_count'] = 0
                self.syn_flood_tracker[src_ip]['ack_count'] = 0
                self.syn_flood_tracker[src_ip]['first_seen'] = current_time
        else:
            # Reset if time window exceeded
            self.syn_flood_tracker[src_ip]['syn_count'] = 0
            self.syn_flood_tracker[src_ip]['ack_count'] = 0
            self.syn_flood_tracker[src_ip]['first_seen'] = current_time

    def detect_icmp_flood(self, packet_info):
        """
        Detect ICMP flood attacks

        Args:
            packet_info (dict): Packet information
        """
        if packet_info['protocol'] != 'ICMP':
            return

        src_ip = packet_info['src_ip']
        current_time = packet_info['timestamp']

        # Initialize tracker
        if src_ip not in self.icmp_flood_tracker:
            self.icmp_flood_tracker[src_ip]['first_seen'] = current_time

        self.icmp_flood_tracker[src_ip]['count'] += 1

        # Check threshold
        time_window = self.config.get('signature_detection', {}).get('icmp_flood', {}).get('time_window', 5)
        threshold = self.config.get('signature_detection', {}).get('icmp_flood', {}).get('threshold', 50)

        first_seen = self.icmp_flood_tracker[src_ip]['first_seen']
        time_diff = (current_time - first_seen).total_seconds()

        if time_diff <= time_window:
            count = self.icmp_flood_tracker[src_ip]['count']
            if count >= threshold:
                self.alert_callback({
                    'type': 'icmp_flood',
                    'severity': 'high',
                    'timestamp': current_time,
                    'src_ip': src_ip,
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"ICMP flood detected: {count} packets",
                    'details': {
                        'packet_count': count,
                        'time_window': time_diff
                    }
                })
                # Reset tracker
                self.icmp_flood_tracker[src_ip]['count'] = 0
                self.icmp_flood_tracker[src_ip]['first_seen'] = current_time
        else:
            # Reset if time window exceeded
            self.icmp_flood_tracker[src_ip]['count'] = 0
            self.icmp_flood_tracker[src_ip]['first_seen'] = current_time

    def detect_arp_spoofing(self, packet_info):
        """
        Detect ARP spoofing attacks

        Args:
            packet_info (dict): Packet information
        """
        if packet_info['protocol'] != 'ARP':
            return

        src_ip = packet_info['src_ip']
        src_mac = packet_info.get('src_mac')

        if not src_ip or not src_mac:
            return

        # Check if we've seen this IP before with a different MAC
        if src_ip in self.arp_cache:
            if self.arp_cache[src_ip] != src_mac:
                self.alert_callback({
                    'type': 'arp_spoofing',
                    'severity': 'critical',
                    'timestamp': packet_info['timestamp'],
                    'src_ip': src_ip,
                    'description': "ARP spoofing detected: IP address with different MAC",
                    'details': {
                        'old_mac': self.arp_cache[src_ip],
                        'new_mac': src_mac
                    }
                })
        else:
            # Store IP-MAC mapping
            self.arp_cache[src_ip] = src_mac

    def check_signatures(self, packet_info):
        """
        Check packet against loaded signatures

        Args:
            packet_info (dict): Packet information
        """
        for signature in self.signatures:
            if self.match_signature(packet_info, signature):
                self.alert_callback({
                    'type': 'signature_match',
                    'severity': signature.get('severity', 'medium'),
                    'timestamp': packet_info['timestamp'],
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"{signature['name']}: {signature['description']}",
                    'details': {
                        'signature_id': signature['id'],
                        'signature_name': signature['name']
                    }
                })

    def match_signature(self, packet_info, signature):
        """
        Check if packet matches a signature

        Args:
            packet_info (dict): Packet information
            signature (dict): Signature definition

        Returns:
            bool: True if matches, False otherwise
        """
        # Check protocol
        if 'protocol' in signature:
            if packet_info['protocol'] != signature['protocol']:
                return False

        # Check ports
        if 'ports' in signature:
            if packet_info['dst_port'] not in signature['ports']:
                return False

        # Check patterns in payload
        if 'patterns' in signature and packet_info['payload']:
            try:
                payload_str = packet_info['payload'].decode('utf-8', errors='ignore').lower()
                for pattern in signature['patterns']:
                    if pattern.lower() in payload_str:
                        return True
            except:
                pass

        # Check suspicious destination port ranges
        if 'dst_port_range' in signature:
            if packet_info['dst_port'] in signature['dst_port_range']:
                return True

        return False

    def get_statistics(self):
        """Get detection statistics"""
        return {
            'signatures_loaded': len(self.signatures),
            'tracked_ips': {
                'port_scan': len(self.port_scan_tracker),
                'syn_flood': len(self.syn_flood_tracker),
                'icmp_flood': len(self.icmp_flood_tracker)
            }
        }
