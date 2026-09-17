"""
Signature-Based Detection Module
Detects known attack patterns using signature matching
"""

import json
import logging
import threading
from urllib.parse import unquote
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


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
        self._lock = threading.Lock()
        # Sliding window: store (timestamp, port) tuples instead of just a set
        self.port_scan_tracker = defaultdict(lambda: deque(maxlen=500))
        self.syn_flood_tracker = defaultdict(lambda: {'syn_count': 0, 'ack_count': 0, 'first_seen': None})
        self.icmp_flood_tracker = defaultdict(lambda: {'count': 0, 'first_seen': None})
        self.arp_cache = {}  # IP -> MAC mapping
        self._last_cleanup = datetime.now()
        # Alert deduplication: (alert_type, src_ip) -> last_alert_time
        self._alert_cooldowns = {}
        self._alert_cooldown_secs = 60  # suppress duplicate alerts within this window
        # Sliding windows for signatures that fire on a rate, not a payload:
        # (signature_id, src_ip) -> deque of timestamps
        self.signature_trackers = defaultdict(lambda: deque(maxlen=1000))

    def load_signatures(self):
        """Load attack signatures from JSON file"""
        try:
            rules_file = self.config.get('signature_detection', {}).get('rules_file', 'rules/signatures.json')
            with open(rules_file, 'r') as f:
                data = json.load(f)
                self.signatures = data.get('signatures', [])
            logger.info("Loaded %d attack signatures", len(self.signatures))
        except Exception as e:
            logger.error("Error loading signatures: %s", e)
            self.signatures = []

    def analyze_packet(self, packet_info):
        """
        Analyze packet against all signatures

        Args:
            packet_info (dict): Packet information dictionary
        """
        if not self.config.get('signature_detection', {}).get('enabled', True):
            return

        with self._lock:
            # Periodic cleanup of stale tracker entries
            self._cleanup_stale_entries(packet_info['timestamp'])

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

    def _cleanup_stale_entries(self, current_time):
        """Remove tracker entries older than 2x their time window"""
        if (current_time - self._last_cleanup).total_seconds() < 30:
            return
        self._last_cleanup = current_time

        ps_window = self.config.get('signature_detection', {}).get('port_scan', {}).get('time_window', 60) * 2
        for ip in list(self.port_scan_tracker):
            window = self.port_scan_tracker[ip]
            if not window or (current_time - window[-1][0]).total_seconds() > ps_window:
                del self.port_scan_tracker[ip]

        sf_window = self.config.get('signature_detection', {}).get('syn_flood', {}).get('time_window', 10) * 2
        for ip in list(self.syn_flood_tracker):
            if self.syn_flood_tracker[ip]['first_seen'] and \
               (current_time - self.syn_flood_tracker[ip]['first_seen']).total_seconds() > sf_window:
                del self.syn_flood_tracker[ip]

        icmp_window = self.config.get('signature_detection', {}).get('icmp_flood', {}).get('time_window', 5) * 2
        for ip in list(self.icmp_flood_tracker):
            if self.icmp_flood_tracker[ip]['first_seen'] and \
               (current_time - self.icmp_flood_tracker[ip]['first_seen']).total_seconds() > icmp_window:
                del self.icmp_flood_tracker[ip]

        # Rate-based signature windows: drop any whose newest event is long past.
        # Uses a generous 2x the largest configured window so a rule is never
        # purged mid-window.
        for key in list(self.signature_trackers):
            window = self.signature_trackers[key]
            if not window or (current_time - window[-1]).total_seconds() > 600:
                del self.signature_trackers[key]

    def _should_suppress_alert(self, alert_type, src_ip, current_time):
        """Check if this alert should be suppressed (deduplication)"""
        key = (alert_type, src_ip)
        last_time = self._alert_cooldowns.get(key)
        if last_time and (current_time - last_time).total_seconds() < self._alert_cooldown_secs:
            return True
        self._alert_cooldowns[key] = current_time
        return False

    def detect_port_scan(self, packet_info):
        """
        Detect port scanning using a sliding window approach.
        Keeps timestamped port entries and evicts those outside the window.
        """
        if packet_info['protocol'] != 'TCP' or not packet_info['dst_port']:
            return

        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        current_time = packet_info['timestamp']

        time_window = self.config.get('signature_detection', {}).get('port_scan', {}).get('time_window', 60)
        threshold = self.config.get('signature_detection', {}).get('port_scan', {}).get('threshold', 20)

        # Add current event to sliding window
        self.port_scan_tracker[src_ip].append((current_time, dst_port))

        # Evict entries outside the time window
        window = self.port_scan_tracker[src_ip]
        while window and (current_time - window[0][0]).total_seconds() > time_window:
            window.popleft()

        # Count unique ports in the current window
        unique_ports = {port for _, port in window}
        port_count = len(unique_ports)

        if port_count >= threshold:
            if not self._should_suppress_alert('port_scan', src_ip, current_time):
                self.alert_callback({
                    'type': 'port_scan',
                    'severity': 'high',
                    'timestamp': current_time,
                    'src_ip': src_ip,
                    'dst_ip': packet_info['dst_ip'],
                    'description': f"Port scan detected: {port_count} unique ports scanned",
                    'details': {
                        'port_count': port_count,
                        'time_window': time_window
                    }
                })
                window.clear()

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
            # Rules with a dedicated coded detector are skipped here so the same
            # event does not alert twice.
            if signature.get('handled_by'):
                continue

            if self.match_signature(packet_info, signature):
                # Without this, a payload signature match alerts once per packet:
                # 2000 SQLi packets produced 2000 alerts.
                if self._should_suppress_alert(signature['id'], packet_info['src_ip'],
                                               packet_info['timestamp']):
                    continue

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
        Check if packet matches a signature.

        Rules come in four shapes and each needs its own discriminator. The
        original version only ever returned True for payload patterns or a
        dst_port_range, so rules built on a threshold or a bare port list passed
        the filters and then fell through to False — they could never fire.

        Precedence after the protocol/port filters:
          1. patterns       -> payload match (SIG001/002/006/012)
          2. dst_port_range -> destination port in a suspicious set (SIG009)
          3. threshold      -> N events from one source inside time_window
                               (SIG003/004/008/010)
          4. ports only     -> the port itself is the indicator (SIG005/007)
          5. otherwise      -> no discriminator; a dedicated detector owns it

        Args:
            packet_info (dict): Packet information
            signature (dict): Signature definition

        Returns:
            bool: True if matches, False otherwise
        """
        # Protocol filter
        if 'protocol' in signature:
            if packet_info['protocol'] != signature['protocol']:
                return False

        # Port filter
        if 'ports' in signature:
            if packet_info['dst_port'] not in signature['ports']:
                return False

        # 1. Payload patterns (also URL-decoded to catch encoded attacks)
        if 'patterns' in signature:
            if not packet_info['payload']:
                return False
            try:
                payload_str = packet_info['payload'].decode('utf-8', errors='ignore').lower()
                decoded_payload = unquote(payload_str)
                for pattern in signature['patterns']:
                    pat = pattern.lower()
                    if pat in payload_str or pat in decoded_payload:
                        return True
            except (UnicodeDecodeError, AttributeError):
                pass
            return False

        # 2. Suspicious destination port ranges
        if 'dst_port_range' in signature:
            return packet_info['dst_port'] in signature['dst_port_range']

        # 3. Rate-based rules
        if 'threshold' in signature:
            return self._check_signature_threshold(packet_info, signature)

        # 4. Port-only rules: reaching here means the protocol and port filters
        #    both passed and the port is itself the indicator.
        if 'ports' in signature:
            return True

        # 5. Protocol-only rule with no discriminator. Matching every packet of
        #    that protocol would be an alert storm, so a dedicated detector owns
        #    it (see handled_by in signatures.json).
        return False

    def _check_signature_threshold(self, packet_info, signature):
        """
        Sliding-window rate check for threshold-based signatures.

        Counts events per (signature, source IP) and fires once the count inside
        time_window reaches threshold. The window is cleared on fire so one burst
        produces one alert rather than one per packet past the threshold.

        Args:
            packet_info (dict): Packet information
            signature (dict): Signature definition with threshold + time_window

        Returns:
            bool: True if the rate threshold was just crossed
        """
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return False

        threshold = signature['threshold']
        time_window = signature.get('time_window', 60)
        current_time = packet_info['timestamp']

        key = (signature['id'], src_ip)
        window = self.signature_trackers[key]
        window.append(current_time)

        # Evict events that fell out of the window
        while window and (current_time - window[0]).total_seconds() > time_window:
            window.popleft()

        if len(window) >= threshold:
            window.clear()
            return True
        return False

    def get_statistics(self):
        """Get detection statistics"""
        return {
            'signatures_loaded': len(self.signatures),
            'signatures_active': sum(1 for sig in self.signatures if not sig.get('handled_by')),
            'tracked_ips': {
                'port_scan': len(self.port_scan_tracker),
                'syn_flood': len(self.syn_flood_tracker),
                'icmp_flood': len(self.icmp_flood_tracker)
            }
        }
