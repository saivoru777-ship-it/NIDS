"""
Health & Metrics Module
Tracks operational metrics for the NIDS system.
"""

import os
import sys
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
        self.packets_dropped = 0

    def record_packet(self):
        with self._lock:
            self.packets_processed += 1

    def record_alert(self):
        with self._lock:
            self.alerts_generated += 1

    def record_error(self):
        with self._lock:
            self.errors += 1

    def record_drop(self):
        """Count a packet the capture queue had to discard.

        Drops are the signal that detection is falling behind capture. Logging
        them per packet floods the log under load; a counter is what you can
        actually alert on.
        """
        with self._lock:
            self.packets_dropped += 1

    def get_metrics(self):
        """Return current metrics snapshot"""
        with self._lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            return {
                'status': 'running',
                'uptime_seconds': round(uptime, 1),
                'packets_processed': self.packets_processed,
                'packets_dropped': self.packets_dropped,
                'drop_rate': round(
                    self.packets_dropped / max(self.packets_processed + self.packets_dropped, 1), 4),
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
            # ru_maxrss units are platform-specific: bytes on macOS/BSD,
            # kilobytes on Linux. Assuming bytes everywhere under-reports
            # Linux memory by 1024x.
            divisor = (1024 * 1024) if sys.platform == 'darwin' else 1024
            return round(usage.ru_maxrss / divisor, 1)
        except (ImportError, AttributeError):
            return 0.0

    def log_metrics(self):
        """Log current metrics"""
        m = self.get_metrics()
        logger.info(
            "Health: uptime=%.0fs, packets=%d (%.1f/s), dropped=%d (%.2f%%), "
            "alerts=%d, errors=%d, mem=%.1fMB",
            m['uptime_seconds'], m['packets_processed'], m['packets_per_second'],
            m['packets_dropped'], m['drop_rate'] * 100, m['alerts_generated'],
            m['errors'], m['memory_mb'])
