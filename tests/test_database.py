"""Tests for SQLite Database Backend"""

import os
import tempfile
from datetime import datetime
from storage.database import AlertDatabase


class TestAlertDatabase:
    def _make_db(self):
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        return AlertDatabase(db_path=path), path

    def test_store_and_count(self):
        db, path = self._make_db()
        try:
            db.store_alert({
                'alert_id': 1,
                'type': 'port_scan',
                'severity': 'high',
                'timestamp': datetime.now(),
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'description': 'Test alert',
                'details': {'port_count': 25},
            })
            assert db.total_count() == 1
        finally:
            os.unlink(path)

    def test_query_by_severity(self):
        db, path = self._make_db()
        try:
            for sev in ['critical', 'high', 'high', 'low']:
                db.store_alert({
                    'type': 'test', 'severity': sev,
                    'timestamp': datetime.now(), 'description': f'{sev} alert',
                })

            results = db.query_alerts(severity='high')
            assert len(results) == 2

            results = db.query_alerts(severity='critical')
            assert len(results) == 1
        finally:
            os.unlink(path)

    def test_query_by_type(self):
        db, path = self._make_db()
        try:
            db.store_alert({'type': 'port_scan', 'severity': 'high',
                            'timestamp': datetime.now(), 'description': 'A'})
            db.store_alert({'type': 'syn_flood', 'severity': 'critical',
                            'timestamp': datetime.now(), 'description': 'B'})

            results = db.query_alerts(alert_type='syn_flood')
            assert len(results) == 1
            assert results[0]['type'] == 'syn_flood'
        finally:
            os.unlink(path)

    def test_query_by_src_ip(self):
        db, path = self._make_db()
        try:
            db.store_alert({'type': 'test', 'severity': 'high',
                            'timestamp': datetime.now(), 'src_ip': '1.2.3.4',
                            'description': 'A'})
            db.store_alert({'type': 'test', 'severity': 'high',
                            'timestamp': datetime.now(), 'src_ip': '5.6.7.8',
                            'description': 'B'})

            results = db.query_alerts(src_ip='1.2.3.4')
            assert len(results) == 1
        finally:
            os.unlink(path)

    def test_count_by_severity(self):
        db, path = self._make_db()
        try:
            for sev in ['critical', 'high', 'high', 'medium']:
                db.store_alert({'type': 'test', 'severity': sev,
                                'timestamp': datetime.now(), 'description': 'X'})

            counts = db.count_by_severity()
            assert counts['high'] == 2
            assert counts['critical'] == 1
            assert counts['medium'] == 1
        finally:
            os.unlink(path)

    def test_count_by_type(self):
        db, path = self._make_db()
        try:
            db.store_alert({'type': 'port_scan', 'severity': 'high',
                            'timestamp': datetime.now(), 'description': 'A'})
            db.store_alert({'type': 'port_scan', 'severity': 'high',
                            'timestamp': datetime.now(), 'description': 'B'})
            db.store_alert({'type': 'icmp_flood', 'severity': 'high',
                            'timestamp': datetime.now(), 'description': 'C'})

            counts = db.count_by_type()
            assert counts['port_scan'] == 2
            assert counts['icmp_flood'] == 1
        finally:
            os.unlink(path)

    def test_recent_alerts_ordered(self):
        db, path = self._make_db()
        try:
            for i in range(5):
                db.store_alert({
                    'type': 'test', 'severity': 'low',
                    'timestamp': datetime(2025, 1, 1, 0, i),
                    'description': f'Alert {i}',
                })

            recent = db.recent_alerts(3)
            assert len(recent) == 3
            # Most recent first
            assert 'Alert 4' in recent[0]['description']
        finally:
            os.unlink(path)

    def test_limit_respected(self):
        db, path = self._make_db()
        try:
            for i in range(20):
                db.store_alert({'type': 'test', 'severity': 'low',
                                'timestamp': datetime.now(), 'description': f'{i}'})

            results = db.query_alerts(limit=5)
            assert len(results) == 5
        finally:
            os.unlink(path)

    def test_metadata_stored_as_json(self):
        db, path = self._make_db()
        try:
            db.store_alert({
                'type': 'test', 'severity': 'high',
                'timestamp': datetime.now(), 'description': 'X',
                'details': {'key': 'value', 'count': 42},
            })

            results = db.query_alerts()
            assert results[0]['metadata'] is not None
            import json
            meta = json.loads(results[0]['metadata'])
            assert meta['key'] == 'value'
            assert meta['count'] == 42
        finally:
            os.unlink(path)
