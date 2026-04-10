"""
Health & Metrics Module
Tracks operational metrics for the NIDS system.
"""

import os
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class HealthMonitor:
    """Tracks NIDS health metrics"""

    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = datetime.now()
        self.packets_processed = 0
        self.alerts_generated = 0
        self.errors = 0

    def record_packet(self):
        with self._lock:
            self.packets_processed += 1

    def record_alert(self):
        with self._lock:
            self.alerts_generated += 1

    def record_error(self):
        with self._lock:
            self.errors += 1

    def get_metrics(self):
        """Return current metrics snapshot"""
        with self._lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            return {
                'status': 'running',
                'uptime_seconds': round(uptime, 1),
                'packets_processed': self.packets_processed,
                'alerts_generated': self.alerts_generated,
                'errors': self.errors,
                'packets_per_second': round(self.packets_processed / max(uptime, 1), 2),
                'pid': os.getpid(),
                'memory_mb': self._get_memory_mb(),
            }

    @staticmethod
    def _get_memory_mb():
        """Get current process memory usage in MB"""
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return round(usage.ru_maxrss / (1024 * 1024), 1)  # macOS returns bytes
        except (ImportError, AttributeError):
            return 0.0

    def log_metrics(self):
        """Log current metrics"""
        m = self.get_metrics()
        logger.info("Health: uptime=%.0fs, packets=%d (%.1f/s), alerts=%d, errors=%d, mem=%.1fMB",
                     m['uptime_seconds'], m['packets_processed'],
                     m['packets_per_second'], m['alerts_generated'],
                     m['errors'], m['memory_mb'])
