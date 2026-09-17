#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
Main entry point for the NIDS application
"""

import argparse
import logging
import logging.handlers
import signal
import sys
import os
import threading

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from capture.packet_sniffer import PacketSniffer
from detection.signature_based import SignatureDetector
from detection.anomaly_based import AnomalyDetector
from analysis.traffic_analyzer import TrafficAnalyzer
from alerts.alert_manager import AlertManager
from alerts.notifier import EmailNotifier
from storage.database import AlertDatabase
from utils.health import HealthMonitor
from utils.helpers import (
    load_config,
    check_privileges,
    get_available_interfaces,
    print_banner,
    create_directory_structure
)

logger = logging.getLogger('nids')


def setup_logging(config):
    """Configure the logging system based on config.yaml settings"""
    log_level = config.get('logging', {}).get('log_level', 'INFO')
    log_dir = config.get('logging', {}).get('log_directory', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Console handler with color-friendly format
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    ))
    root_logger.addHandler(console)

    # Rotating file handler (5 MB, keep 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'nids.log'),
        maxBytes=5 * 1024 * 1024,
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    ))
    root_logger.addHandler(file_handler)


class NIDS:
    """Network Intrusion Detection System"""

    def __init__(self, config_file='config/config.yaml', interface=None):
        """
        Initialize NIDS

        Args:
            config_file (str): Path to configuration file
            interface (str): Network interface to monitor
        """
        self.config = load_config(config_file)
        self.interface = interface or self.config.get('network', {}).get('interface')
        if not self.interface:
            logger.critical("No network interface specified. Use -i flag or set network.interface in config.")
            sys.exit(1)

        # Initialize health monitor, database, notifier, and components
        self.health = HealthMonitor()
        log_dir = self.config.get('logging', {}).get('log_directory', 'logs')
        self.database = AlertDatabase(os.path.join(log_dir, 'nids_alerts.db'))
        self.notifier = EmailNotifier(self.config)
        self.alert_manager = AlertManager(self.config, database=self.database,
                                          notifier=self.notifier)
        self.signature_detector = SignatureDetector(
            self.config,
            self._on_alert
        )
        self.anomaly_detector = AnomalyDetector(
            self.config,
            self._on_alert
        )
        self.traffic_analyzer = TrafficAnalyzer(self.config)
        self.packet_sniffer = PacketSniffer(
            self.interface,
            self.process_packet,
            self.config,
            health_monitor=self.health
        )

        self.is_running = False
        self._shutdown_event = threading.Event()

    def _on_alert(self, alert_data):
        """
        Single funnel for every alert raised by any detector.

        Exists so the health metric is incremented in exactly one place: wiring
        record_alert() into each detector separately is how the counter silently
        drifts out of sync with reality.

        Args:
            alert_data (dict): Alert information
        """
        self.health.record_alert()
        return self.alert_manager.handle_alert(alert_data)

    def process_packet(self, packet_info):
        """
        Process each captured packet through detection engines

        Args:
            packet_info (dict): Packet information
        """
        # Count the packet before analysis so throughput reflects packets seen,
        # not packets that survived detection without raising an exception.
        self.health.record_packet()

        try:
            # Analyze traffic patterns
            self.traffic_analyzer.analyze_packet(packet_info)

            # Run signature-based detection
            self.signature_detector.analyze_packet(packet_info)

            # Run anomaly-based detection
            self.anomaly_detector.analyze_packet(packet_info)
        except Exception as e:
            self.health.record_error()
            logger.error("Error processing packet: %s", e, exc_info=True)

    def start(self):
        """Start the NIDS"""
        print_banner()

        # Check for required privileges
        if not check_privileges():
            sys.exit(1)

        # Display configuration
        logger.info("Network Interface: %s", self.interface)
        logger.info("Signature Detection: %s",
                     'Enabled' if self.config.get('signature_detection', {}).get('enabled') else 'Disabled')
        logger.info("Anomaly Detection: %s",
                     'Enabled' if self.config.get('anomaly_detection', {}).get('enabled') else 'Disabled')

        if self.config.get('anomaly_detection', {}).get('enabled'):
            baseline_time = self.config.get('anomaly_detection', {}).get('baseline_collection_time', 300)
            logger.info("Baseline Collection Time: %d seconds", baseline_time)

        # Start web dashboard
        dashboard_config = self.config.get('dashboard', {})
        if dashboard_config.get('enabled', True):
            # Imported here rather than at module scope: the dashboard is
            # optional, and Flask being absent should degrade to "no dashboard",
            # not stop packet capture from running.
            try:
                from dashboard.app import start_dashboard
            except ImportError as e:
                logger.warning("Dashboard unavailable (%s) — continuing without it. "
                               "Install flask to enable it.", e)
                start_dashboard = None

            if start_dashboard:
                dash_port = dashboard_config.get('port', 5000)
                start_dashboard(self.alert_manager, self.traffic_analyzer,
                                database=self.database, health_monitor=self.health,
                                port=dash_port)

        # Start packet capture
        self.is_running = True
        self.packet_sniffer.start_sniffing()

        # Keep main thread alive using event-based wait (responsive to signals)
        try:
            self._shutdown_event.wait()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop the NIDS"""
        logger.info("Shutting down NIDS...")
        self.is_running = False
        self._shutdown_event.set()
        self.packet_sniffer.stop_sniffing()

        # Print final statistics
        sniffer_stats = self.packet_sniffer.get_stats()
        logger.info("Packets Captured: %d", sniffer_stats['packet_count'])

        sig_stats = self.signature_detector.get_statistics()
        logger.info("Loaded Signatures: %d", sig_stats['signatures_loaded'])

        anom_stats = self.anomaly_detector.get_statistics()
        logger.info("Baseline Established: %s", anom_stats['baseline_established'])
        logger.info("Anomalies Detected: %d", anom_stats['anomaly_count'])

        # Alert summary
        self.alert_manager.print_summary()

        logger.info("NIDS stopped successfully")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System (NIDS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py                    # Use default interface from config
  sudo python3 main.py -i eth0            # Monitor specific interface
  sudo python3 main.py -c custom.yaml     # Use custom configuration
  sudo python3 main.py --list-interfaces  # List available interfaces

Note: Root/Administrator privileges required for packet capture
        """
    )

    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor',
        default=None
    )

    default_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'config.yaml')
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default=default_config
    )

    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )

    args = parser.parse_args()

    # List interfaces if requested
    if args.list_interfaces:
        print("Available network interfaces:")
        interfaces = get_available_interfaces()
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        sys.exit(0)

    # Create necessary directories
    create_directory_structure()

    # Load config early so we can set up logging
    config = load_config(args.config)
    setup_logging(config)

    # Initialize and start NIDS
    try:
        nids = NIDS(config_file=args.config, interface=args.interface)

        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            nids.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start NIDS
        nids.start()

    except Exception as e:
        logger.critical("Fatal error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
