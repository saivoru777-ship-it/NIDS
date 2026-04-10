"""Tests for Alert Manager"""

import os
import json
import tempfile
from datetime import datetime
from alerts.alert_manager import AlertManager


class TestAlertHandling:
    def test_alert_stored_and_counted(self, base_config):
        manager = AlertManager(base_config)
        manager.handle_alert({
            'type': 'port_scan',
            'severity': 'high',
            'timestamp': datetime.now(),
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'description': 'Test alert',
        })

        assert len(manager.alerts) == 1
        assert manager.alert_count['high'] == 1

    def test_severity_auto_determined(self, base_config):
        manager = AlertManager(base_config)
        manager.handle_alert({
            'type': 'syn_flood',
            'timestamp': datetime.now(),
            'description': 'Test',
        })

        assert manager.alerts[0]['severity'] == 'critical'

    def test_alert_id_increments(self, base_config):
        manager = AlertManager(base_config)
        for i in range(5):
            manager.handle_alert({
                'type': 'port_scan',
                'severity': 'high',
                'timestamp': datetime.now(),
                'description': f'Alert {i}',
            })

        ids = [a['alert_id'] for a in manager.alerts]
        assert ids == [1, 2, 3, 4, 5]

    def test_alert_deque_maxlen_enforced(self, base_config):
        manager = AlertManager(base_config)
        # deque maxlen is 10000; verify it's bounded
        assert manager.alerts.maxlen == 10000


class TestAlertSummary:
    def test_get_alert_summary(self, base_config):
        manager = AlertManager(base_config)
        manager.handle_alert({
            'type': 'port_scan', 'severity': 'high',
            'timestamp': datetime.now(), 'description': 'A',
        })
        manager.handle_alert({
            'type': 'syn_flood', 'severity': 'critical',
            'timestamp': datetime.now(), 'description': 'B',
        })

        summary = manager.get_alert_summary()
        assert summary['total_alerts'] == 2
        assert summary['by_severity']['high'] == 1
        assert summary['by_severity']['critical'] == 1

    def test_get_alerts_by_type(self, base_config):
        manager = AlertManager(base_config)
        for _ in range(3):
            manager.handle_alert({
                'type': 'port_scan', 'severity': 'high',
                'timestamp': datetime.now(), 'description': 'X',
            })
        manager.handle_alert({
            'type': 'icmp_flood', 'severity': 'high',
            'timestamp': datetime.now(), 'description': 'Y',
        })

        by_type = manager.get_alerts_by_type()
        assert by_type['port_scan'] == 3
        assert by_type['icmp_flood'] == 1

    def test_get_recent_alerts(self, base_config):
        manager = AlertManager(base_config)
        for i in range(10):
            manager.handle_alert({
                'type': 'port_scan', 'severity': 'high',
                'timestamp': datetime.now(), 'description': f'Alert {i}',
            })

        recent = manager.get_recent_alerts(3)
        assert len(recent) == 3


class TestAlertLogging:
    def test_json_logging(self, base_config):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = base_config.copy()
            config['logging'] = {'log_directory': tmpdir, 'log_format': 'json'}
            config['alerts'] = {'console_output': False, 'file_output': True}

            manager = AlertManager(config)
            manager.handle_alert({
                'type': 'port_scan', 'severity': 'high',
                'timestamp': datetime.now(),
                'description': 'Test JSON log',
            })

            # Verify log file was written
            log_files = [f for f in os.listdir(tmpdir) if f.startswith('nids_alerts')]
            assert len(log_files) == 1

            with open(os.path.join(tmpdir, log_files[0])) as f:
                line = f.readline()
                data = json.loads(line)
                assert data['type'] == 'port_scan'

    def test_csv_logging(self, base_config):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = base_config.copy()
            config['logging'] = {'log_directory': tmpdir, 'log_format': 'csv'}
            config['alerts'] = {'console_output': False, 'file_output': True}

            manager = AlertManager(config)
            manager.handle_alert({
                'type': 'syn_flood', 'severity': 'critical',
                'timestamp': datetime.now(),
                'description': 'Test CSV log',
            })

            log_files = [f for f in os.listdir(tmpdir) if f.endswith('.csv')]
            assert len(log_files) == 1
