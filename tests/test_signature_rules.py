"""
Tests for the JSON signature rule engine.

Motivation: the rule file defined twelve signatures, but match_signature only
ever returned True for a payload pattern or a dst_port_range. Rules built on a
threshold or a bare port list passed the protocol/port filters and then fell
through to `return False`, so seven of the twelve could never fire. Every unit
test passed anyway, because none of them asserted that a given rule ID fired.

These tests assert per-rule, by signature ID.
"""

import json
import os
from datetime import datetime, timedelta

from detection.signature_based import SignatureDetector

RULES_PATH = os.path.join(os.path.dirname(__file__), '..', 'rules', 'signatures.json')


def _fired_ids(alerts):
    """Signature IDs present in a list of alerts."""
    return {a['details'].get('signature_id') for a in alerts
            if a.get('type') == 'signature_match'}


class TestRuleCoverage:
    def test_every_rule_is_either_matchable_or_delegated(self):
        """
        No rule may be silently dead: each one needs a discriminator the matcher
        understands, or an explicit handled_by naming the detector that owns it.
        """
        signatures = json.load(open(RULES_PATH))['signatures']
        discriminators = ('patterns', 'dst_port_range', 'threshold', 'ports')

        for sig in signatures:
            has_discriminator = any(k in sig for k in discriminators)
            delegated = bool(sig.get('handled_by'))
            assert has_discriminator or delegated, (
                f"{sig['id']} ({sig['name']}) can never fire: no discriminator "
                f"and no handled_by"
            )

    def test_statistics_report_active_rule_count(self, base_config):
        detector = SignatureDetector(base_config, lambda a: None)
        stats = detector.get_statistics()
        assert stats['signatures_loaded'] == 12
        # SIG011 is delegated to the coded ARP detector
        assert stats['signatures_active'] == 11


class TestPortOnlyRules:
    """SIG005 (Telnet/23) and SIG007 (SMB/445,139): the port is the indicator."""

    def test_telnet_access_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(protocol='TCP', dst_port=23))
        assert 'SIG005' in _fired_ids(alerts)

    def test_smb_fires_on_both_ports(self, base_config, make_packet_info):
        for port in (445, 139):
            alerts = []
            detector = SignatureDetector(base_config, lambda a: alerts.append(a))
            detector.analyze_packet(make_packet_info(protocol='TCP', dst_port=port))
            assert 'SIG007' in _fired_ids(alerts), f"SMB rule missed port {port}"

    def test_port_only_rule_does_not_fire_on_other_ports(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(protocol='TCP', dst_port=8443))
        assert 'SIG005' not in _fired_ids(alerts)
        assert 'SIG007' not in _fired_ids(alerts)

    def test_port_only_rule_is_deduplicated(self, base_config, make_packet_info):
        """A long Telnet session is one alert, not one per packet."""
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()
        for i in range(50):
            detector.analyze_packet(make_packet_info(
                protocol='TCP', dst_port=23, timestamp=now + timedelta(milliseconds=i)))
        assert len([a for a in alerts if a['details'].get('signature_id') == 'SIG005']) == 1


class TestThresholdRules:
    """SIG003 SSH, SIG004 FTP, SIG008 RDP, SIG010 ping sweep: fire on a rate."""

    def test_ssh_brute_force_fires_at_threshold(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # threshold is 5 within 60s
        for i in range(4):
            detector.analyze_packet(make_packet_info(
                protocol='TCP', dst_port=22, timestamp=now + timedelta(seconds=i)))
        assert 'SIG003' not in _fired_ids(alerts), "fired before reaching threshold"

        detector.analyze_packet(make_packet_info(
            protocol='TCP', dst_port=22, timestamp=now + timedelta(seconds=4)))
        assert 'SIG003' in _fired_ids(alerts)

    def test_threshold_rule_respects_time_window(self, base_config, make_packet_info):
        """Events spread beyond the window never accumulate to the threshold."""
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        # 5 attempts, but 30s apart => never 5 inside a 60s window
        for i in range(5):
            detector.analyze_packet(make_packet_info(
                protocol='TCP', dst_port=22, timestamp=now + timedelta(seconds=i * 30)))
        assert 'SIG003' not in _fired_ids(alerts)

    def test_threshold_rules_are_tracked_per_source_ip(self, base_config, make_packet_info):
        """Four attempts each from two hosts is not a brute force from either."""
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()

        for i in range(4):
            detector.analyze_packet(make_packet_info(
                src_ip='10.0.0.5', dst_port=22, timestamp=now + timedelta(seconds=i)))
            detector.analyze_packet(make_packet_info(
                src_ip='10.0.0.6', dst_port=22, timestamp=now + timedelta(seconds=i)))
        assert 'SIG003' not in _fired_ids(alerts)

    def test_rdp_brute_force_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()
        for i in range(5):
            detector.analyze_packet(make_packet_info(
                protocol='TCP', dst_port=3389, timestamp=now + timedelta(seconds=i)))
        assert 'SIG008' in _fired_ids(alerts)

    def test_ftp_brute_force_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()
        for i in range(5):
            detector.analyze_packet(make_packet_info(
                protocol='TCP', dst_port=21, timestamp=now + timedelta(seconds=i)))
        assert 'SIG004' in _fired_ids(alerts)

    def test_icmp_ping_sweep_fires(self, base_config, make_packet_info):
        """SIG010: 20 ICMP in 10s. Distinct from the icmp_flood detector (50 in 5s)."""
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        now = datetime.now()
        for i in range(20):
            detector.analyze_packet(make_packet_info(
                protocol='ICMP', dst_port=None, timestamp=now + timedelta(milliseconds=i * 100)))
        assert 'SIG010' in _fired_ids(alerts)


class TestDelegatedRules:
    def test_arp_rule_does_not_double_alert(self, base_config, make_packet_info):
        """
        SIG011 is handled by detect_arp_spoofing. A normal ARP packet must not
        produce a signature_match, or every ARP packet on the wire becomes a
        critical alert.
        """
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(
            protocol='ARP', src_ip='10.0.0.1', src_mac='aa:bb:cc:dd:ee:ff', dst_port=None))
        assert 'SIG011' not in _fired_ids(alerts)
        assert alerts == []

    def test_arp_spoof_still_detected_by_coded_detector(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(
            protocol='ARP', src_ip='10.0.0.1', src_mac='aa:bb:cc:dd:ee:ff', dst_port=None))
        detector.analyze_packet(make_packet_info(
            protocol='ARP', src_ip='10.0.0.1', src_mac='11:22:33:44:55:66', dst_port=None))
        assert any(a['type'] == 'arp_spoofing' for a in alerts)


class TestPatternRules:
    def test_sql_injection_still_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(
            protocol='TCP', dst_port=80, payload=b"GET /?id=1' OR '1'='1"))
        assert 'SIG001' in _fired_ids(alerts)

    def test_url_encoded_sql_injection_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(
            protocol='TCP', dst_port=80, payload=b"GET /?id=%27%20OR%20%271%27=%271"))
        assert 'SIG001' in _fired_ids(alerts)

    def test_pattern_rule_without_payload_does_not_fire(self, base_config, make_packet_info):
        """A bare SYN to port 80 is not an SQLi attempt."""
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(protocol='TCP', dst_port=80, payload=None))
        assert 'SIG001' not in _fired_ids(alerts)

    def test_suspicious_outbound_port_fires(self, base_config, make_packet_info):
        alerts = []
        detector = SignatureDetector(base_config, lambda a: alerts.append(a))
        detector.analyze_packet(make_packet_info(protocol='TCP', dst_port=4444))
        assert 'SIG009' in _fired_ids(alerts)
