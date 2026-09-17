"""
Entrypoint smoke tests.

Motivation: the suite had 62 passing tests while `python main.py` died instantly
with `NameError: name 'threading' is not defined`. Every test imported modules
from src/ directly; nothing ever imported or constructed the thing those modules
are assembled into. Unit coverage of components says nothing about the
composition root.

These tests construct the real NIDS object. They need no root and touch no NIC —
PacketSniffer does not open the interface until start() is called.
"""

import os
import sys
import importlib

import pytest
import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, REPO_ROOT)


@pytest.fixture
def config_file(tmp_path, base_config):
    """Write the test config to disk; main.NIDS loads config by path."""
    base_config['logging']['log_directory'] = str(tmp_path / 'logs')
    base_config['signature_detection']['rules_file'] = os.path.join(
        REPO_ROOT, 'rules', 'signatures.json')
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump(base_config))
    return str(path)


def test_main_module_imports():
    """Catches a missing import in main.py at module scope."""
    main = importlib.import_module('main')
    assert hasattr(main, 'NIDS')


def test_main_imports_threading():
    """
    Regression test for the original bug. NIDS.__init__ calls threading.Event();
    main.py used it without importing it.
    """
    main = importlib.import_module('main')
    assert hasattr(main, 'threading'), "main.py uses threading.Event() but never imports threading"


def test_nids_constructs(config_file):
    """The regression test that matters: build the object graph end to end."""
    main = importlib.import_module('main')
    nids = main.NIDS(config_file=config_file, interface='lo0')

    assert nids.signature_detector is not None
    assert nids.anomaly_detector is not None
    assert nids.traffic_analyzer is not None
    assert nids.alert_manager is not None
    assert nids.packet_sniffer is not None
    assert nids.health is not None
    assert nids.is_running is False


def test_shutdown_event_is_usable(config_file):
    """threading.Event() actually produced an Event, not just a passing import."""
    main = importlib.import_module('main')
    nids = main.NIDS(config_file=config_file, interface='lo0')
    assert nids._shutdown_event.is_set() is False
    nids._shutdown_event.set()
    assert nids._shutdown_event.is_set() is True


class TestHealthWiring:
    """
    Motivation: /api/health reported 0 packets/sec while alerts were firing.
    HealthMonitor.record_packet() and record_alert() existed and were unit
    tested, but nothing in the production path ever called them. The counters
    were only ever incremented by their own tests.
    """

    def test_processing_a_packet_increments_the_counter(self, config_file, make_packet_info):
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')

        assert nids.health.get_metrics()['packets_processed'] == 0
        nids.process_packet(make_packet_info())
        assert nids.health.get_metrics()['packets_processed'] == 1

    def test_packets_per_second_is_nonzero_after_traffic(self, config_file, make_packet_info):
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')

        for _ in range(100):
            nids.process_packet(make_packet_info())

        metrics = nids.health.get_metrics()
        assert metrics['packets_processed'] == 100
        assert metrics['packets_per_second'] > 0, "health endpoint would report 0 pkt/s"

    def test_raising_an_alert_increments_the_counter(self, config_file, make_packet_info):
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')

        # 20 unique ports from one source trips the port scan detector
        for port in range(1, 21):
            nids.process_packet(make_packet_info(dst_port=port))

        assert nids.health.get_metrics()['alerts_generated'] >= 1

    def test_detectors_route_through_the_alert_funnel(self, config_file):
        """
        Both detectors must share the counting wrapper. Passing
        alert_manager.handle_alert directly is how the counter silently drifts.
        """
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')
        assert nids.signature_detector.alert_callback == nids._on_alert
        assert nids.anomaly_detector.alert_callback == nids._on_alert

    def test_processing_error_is_counted_not_swallowed(self, config_file):
        """A malformed packet increments errors instead of killing the worker."""
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')

        nids.process_packet({'timestamp': None, 'protocol': 'TCP'})  # missing keys
        assert nids.health.get_metrics()['errors'] == 1


class TestDropAccounting:
    def test_sniffer_reports_drops(self, config_file):
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')
        stats = nids.packet_sniffer.get_stats()
        assert 'packets_dropped' in stats
        assert 'queue_depth' in stats

    def test_drop_counter_reaches_health_metrics(self, config_file):
        main = importlib.import_module('main')
        nids = main.NIDS(config_file=config_file, interface='lo0')

        nids.packet_sniffer.health_monitor.record_drop()
        metrics = nids.health.get_metrics()
        assert metrics['packets_dropped'] == 1
        assert metrics['drop_rate'] == 1.0  # 1 dropped, 0 processed
