"""Tests for Anomaly-Based Detection"""

from datetime import datetime, timedelta
from detection.anomaly_based import AnomalyDetector


def _feed_baseline(detector, make_packet_info, n_minutes=3, packets_per_min=50):
    """Helper: feed enough packets to establish a baseline.
    Uses n_minutes=3 to ensure we exceed the 120s collection time.
    """
    start = datetime.now()
    for minute in range(n_minutes):
        t = start + timedelta(seconds=minute * 60)
        for i in range(packets_per_min):
            ts = t + timedelta(milliseconds=i * 10)
            pkt = make_packet_info(
                protocol='TCP', dst_port=80, packet_size=100, timestamp=ts
            )
            detector.analyze_packet(pkt)
    # Send one final packet past the collection window to trigger establishment
    final_ts = start + timedelta(seconds=n_minutes * 60 + 1)
    pkt = make_packet_info(protocol='TCP', dst_port=80, packet_size=100, timestamp=final_ts)
    detector.analyze_packet(pkt)
    return final_ts


class TestBaselineEstablishment:
    def test_baseline_established_after_collection_time(self, base_config, make_packet_info):
        # baseline_collection_time = 1 second in test config
        alerts = []
        detector = AnomalyDetector(base_config, lambda a: alerts.append(a))

        now = datetime.now()
        # Send packets spanning 2 seconds
        for i in range(100):
            ts = now + timedelta(milliseconds=i * 25)
            pkt = make_packet_info(timestamp=ts)
            detector.analyze_packet(pkt)

        assert detector.is_baseline_established

    def test_baseline_not_established_before_time(self, base_config, make_packet_info):
        config = base_config.copy()
        config['anomaly_detection'] = base_config['anomaly_detection'].copy()
        config['anomaly_detection']['baseline_collection_time'] = 300

        detector = AnomalyDetector(config, lambda a: None)

        now = datetime.now()
        for i in range(10):
            pkt = make_packet_info(timestamp=now + timedelta(milliseconds=i))
            detector.analyze_packet(pkt)

        assert not detector.is_baseline_established


class TestTrafficVolumeAnomaly:
    def test_detects_volume_spike(self, base_config, make_packet_info):
        alerts = []
        config = base_config.copy()
        config['anomaly_detection'] = base_config['anomaly_detection'].copy()
        config['anomaly_detection']['baseline_collection_time'] = 120

        detector = AnomalyDetector(config, lambda a: alerts.append(a))

        # Feed baseline: 2 minutes of 50 packets/min
        after_baseline = _feed_baseline(detector, make_packet_info)

        assert detector.is_baseline_established

        # Now flood 1000 packets in one minute
        for i in range(1000):
            ts = after_baseline + timedelta(milliseconds=i * 50)
            pkt = make_packet_info(timestamp=ts)
            detector.analyze_packet(pkt)

        # Trigger the volume check by advancing past the 60s window
        trigger = after_baseline + timedelta(seconds=61)
        pkt = make_packet_info(timestamp=trigger)
        detector.analyze_packet(pkt)

        vol_alerts = [a for a in alerts if a['type'] == 'traffic_volume_anomaly']
        assert len(vol_alerts) >= 1


class TestUnusualPortDetection:
    def test_detects_unseen_port(self, base_config, make_packet_info):
        alerts = []
        config = base_config.copy()
        config['anomaly_detection'] = base_config['anomaly_detection'].copy()
        config['anomaly_detection']['baseline_collection_time'] = 120

        detector = AnomalyDetector(config, lambda a: alerts.append(a))

        # Feed baseline with only port 80
        after_baseline = _feed_baseline(detector, make_packet_info)

        assert detector.is_baseline_established

        # Access a port never seen in baseline
        pkt = make_packet_info(dst_port=31337, timestamp=after_baseline + timedelta(seconds=1))
        detector.analyze_packet(pkt)

        port_alerts = [a for a in alerts if a['type'] == 'unusual_port_usage']
        assert len(port_alerts) >= 1


class TestBaselineRefresh:
    def test_baseline_refreshes_after_interval(self, base_config, make_packet_info):
        alerts = []
        config = base_config.copy()
        config['anomaly_detection'] = base_config['anomaly_detection'].copy()
        config['anomaly_detection']['baseline_collection_time'] = 120
        config['anomaly_detection']['baseline_refresh_interval'] = 300

        detector = AnomalyDetector(config, lambda a: alerts.append(a))

        after_baseline = _feed_baseline(detector, make_packet_info)
        assert detector.is_baseline_established

        # Jump past refresh interval
        future = after_baseline + timedelta(seconds=301)
        pkt = make_packet_info(timestamp=future)
        detector.analyze_packet(pkt)

        # Should have reset baseline
        assert not detector.is_baseline_established
