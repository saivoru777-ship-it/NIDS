"""Tests for Health Monitor"""

from utils.health import HealthMonitor


class TestHealthMonitor:
    def test_initial_state(self):
        h = HealthMonitor()
        m = h.get_metrics()
        assert m['status'] == 'running'
        assert m['packets_processed'] == 0
        assert m['alerts_generated'] == 0
        assert m['errors'] == 0
        assert m['uptime_seconds'] >= 0

    def test_record_packet(self):
        h = HealthMonitor()
        for _ in range(10):
            h.record_packet()
        assert h.get_metrics()['packets_processed'] == 10

    def test_record_alert(self):
        h = HealthMonitor()
        h.record_alert()
        h.record_alert()
        assert h.get_metrics()['alerts_generated'] == 2

    def test_record_error(self):
        h = HealthMonitor()
        h.record_error()
        assert h.get_metrics()['errors'] == 1

    def test_packets_per_second(self):
        h = HealthMonitor()
        for _ in range(100):
            h.record_packet()
        m = h.get_metrics()
        # Should be > 0 since uptime is > 0
        assert m['packets_per_second'] > 0

    def test_pid_present(self):
        h = HealthMonitor()
        assert h.get_metrics()['pid'] > 0

    def test_memory_mb_nonnegative(self):
        h = HealthMonitor()
        assert h.get_metrics()['memory_mb'] >= 0
