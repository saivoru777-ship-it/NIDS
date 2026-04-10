"""
SQLite Database Backend for NIDS Alerts
Provides persistent storage and query capabilities for security alerts.
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    timestamp TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    description TEXT,
    metadata TEXT
)
"""

CREATE_INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)",
]


class AlertDatabase:
    """SQLite-backed alert storage"""

    def __init__(self, db_path='logs/nids_alerts.db'):
        os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(CREATE_TABLE_SQL)
            for idx_sql in CREATE_INDEX_SQL:
                conn.execute(idx_sql)
            conn.commit()
        logger.info("Alert database initialized at %s", self.db_path)

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def store_alert(self, alert_data):
        """Store a single alert"""
        ts = alert_data.get('timestamp', datetime.now())
        if isinstance(ts, datetime):
            ts = ts.strftime('%Y-%m-%d %H:%M:%S.%f')

        details = alert_data.get('details', {})
        metadata = json.dumps(details) if details else None

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO alerts
                       (alert_id, timestamp, type, severity, src_ip, dst_ip, description, metadata)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert_data.get('alert_id'),
                        ts,
                        alert_data.get('type', 'unknown'),
                        alert_data.get('severity', 'medium'),
                        alert_data.get('src_ip'),
                        alert_data.get('dst_ip'),
                        alert_data.get('description'),
                        metadata,
                    )
                )
                conn.commit()

    def query_alerts(self, severity=None, alert_type=None, src_ip=None,
                     start_time=None, end_time=None, limit=100):
        """Query alerts with optional filters"""
        conditions = []
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if alert_type:
            conditions.append("type = ?")
            params.append(alert_type)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        where = " AND ".join(conditions)
        sql = f"SELECT * FROM alerts{' WHERE ' + where if where else ''} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_by_severity(self):
        """Get alert counts grouped by severity"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def count_by_type(self):
        """Get alert counts grouped by type"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM alerts GROUP BY type ORDER BY cnt DESC"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def total_count(self):
        """Get total alert count"""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return row[0]

    def recent_alerts(self, count=10):
        """Get most recent alerts"""
        return self.query_alerts(limit=count)

    def close(self):
        """No persistent connection to close, but kept for interface compatibility"""
        pass
