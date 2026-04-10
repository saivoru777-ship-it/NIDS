"""Tests for Signature-Based Detection"""

from datetime import datetime, timedelta
from detection.signature_based import SignatureDetector


class TestPortScanDetection:
    def test_detects_port_scan_above_threshold(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Send 20 packets to unique ports (threshold = 20)
        for port in range(1, 21):
            pkt = make_packet_info(dst_port=port, timestamp=now)
            detector.analyze_packet(pkt)

        assert len(alerts) == 1
        assert alerts[0]['type'] == 'port_scan'
        assert alerts[0]['severity'] == 'high'

    def test_no_alert_below_threshold(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        for port in range(1, 10):  # Only 9 unique ports
            pkt = make_packet_info(dst_port=port, timestamp=now)
            detector.analyze_packet(pkt)

        assert len(alerts) == 0

    def test_sliding_window_evicts_old_entries(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Send 10 ports at t=0
        for port in range(1, 11):
            pkt = make_packet_info(dst_port=port, timestamp=now)
            detector.analyze_packet(pkt)

        # Send 10 more ports at t=61s (beyond 60s window)
        future = now + timedelta(seconds=61)
        for port in range(11, 21):
            pkt = make_packet_info(dst_port=port, timestamp=future)
            detector.analyze_packet(pkt)

        # Should not trigger because the first 10 were evicted
        assert len(alerts) == 0

    def test_alert_deduplication(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Trigger two port scans within cooldown window
        for port in range(1, 21):
            pkt = make_packet_info(dst_port=port, timestamp=now)
            detector.analyze_packet(pkt)

        # Second scan 5 seconds later (within 60s cooldown)
        soon = now + timedelta(seconds=5)
        for port in range(100, 120):
            pkt = make_packet_info(dst_port=port, timestamp=soon)
            detector.analyze_packet(pkt)

        # Only one alert due to deduplication
        assert len(alerts) == 1


class TestSynFloodDetection:
    def test_detects_syn_flood(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Send 100 SYN packets (threshold=100)
        for i in range(100):
            pkt = make_packet_info(tcp_flags='S', timestamp=now)
            detector.analyze_packet(pkt)

        syn_alerts = [a for a in alerts if a['type'] == 'syn_flood']
        assert len(syn_alerts) == 1
        assert syn_alerts[0]['severity'] == 'critical'

    def test_no_alert_with_balanced_syn_ack(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Alternating SYN and ACK — balanced ratio
        for i in range(200):
            flags = 'S' if i % 2 == 0 else 'A'
            pkt = make_packet_info(tcp_flags=flags, timestamp=now)
            detector.analyze_packet(pkt)

        syn_alerts = [a for a in alerts if a['type'] == 'syn_flood']
        assert len(syn_alerts) == 0


class TestIcmpFloodDetection:
    def test_detects_icmp_flood(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        for i in range(50):
            pkt = make_packet_info(protocol='ICMP', dst_port=None, src_port=None,
                                   tcp_flags=None, timestamp=now)
            detector.analyze_packet(pkt)

        icmp_alerts = [a for a in alerts if a['type'] == 'icmp_flood']
        assert len(icmp_alerts) == 1

    def test_no_alert_below_threshold(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        for i in range(10):
            pkt = make_packet_info(protocol='ICMP', dst_port=None, src_port=None,
                                   tcp_flags=None, timestamp=now)
            detector.analyze_packet(pkt)

        icmp_alerts = [a for a in alerts if a['type'] == 'icmp_flood']
        assert len(icmp_alerts) == 0


class TestArpSpoofingDetection:
    def test_detects_mac_change(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        pkt1 = make_packet_info(protocol='ARP', src_ip='192.168.1.1',
                                dst_port=None, src_port=None, tcp_flags=None,
                                src_mac='aa:bb:cc:dd:ee:ff', timestamp=now)
        detector.analyze_packet(pkt1)

        pkt2 = make_packet_info(protocol='ARP', src_ip='192.168.1.1',
                                dst_port=None, src_port=None, tcp_flags=None,
                                src_mac='11:22:33:44:55:66', timestamp=now)
        detector.analyze_packet(pkt2)

        arp_alerts = [a for a in alerts if a['type'] == 'arp_spoofing']
        assert len(arp_alerts) == 1
        assert arp_alerts[0]['severity'] == 'critical'


class TestPayloadMatching:
    def test_detects_sql_injection_pattern(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        payload = b"GET /search?q=' OR '1'='1 HTTP/1.1"
        pkt = make_packet_info(payload=payload, timestamp=now)
        detector.analyze_packet(pkt)

        sig_alerts = [a for a in alerts if a['type'] == 'signature_match']
        assert len(sig_alerts) >= 1

    def test_detects_url_encoded_attack(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # URL-encoded SQL injection: ' OR '1'='1
        payload = b"GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1"
        pkt = make_packet_info(payload=payload, timestamp=now)
        detector.analyze_packet(pkt)

        sig_alerts = [a for a in alerts if a['type'] == 'signature_match']
        assert len(sig_alerts) >= 1


class TestTrackerCleanup:
    def test_stale_entries_cleaned(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # Add a port scan tracker entry
        pkt = make_packet_info(dst_port=80, timestamp=now)
        detector.analyze_packet(pkt)

        assert len(detector.port_scan_tracker) == 1

        # Jump forward 150 seconds (2x window of 60s + 30s cleanup interval)
        future = now + timedelta(seconds=150)
        pkt2 = make_packet_info(src_ip='10.0.0.99', dst_port=443, timestamp=future)
        detector.analyze_packet(pkt2)

        # Original entry should have been cleaned up
        assert '10.0.0.1' not in detector.port_scan_tracker
