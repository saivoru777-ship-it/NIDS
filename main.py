#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
Main entry point for the NIDS application
"""

import argparse
import signal
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from capture.packet_sniffer import PacketSniffer
from detection.signature_based import SignatureDetector
from detection.anomaly_based import AnomalyDetector
from analysis.traffic_analyzer import TrafficAnalyzer
from alerts.alert_manager import AlertManager
from utils.helpers import (
    load_config,
    check_privileges,
    get_available_interfaces,
    print_banner,
    create_directory_structure
)


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
        self.interface = interface or self.config.get('network', {}).get('interface', 'en0')

        # Initialize components
        self.alert_manager = AlertManager(self.config)
        self.signature_detector = SignatureDetector(
            self.config,
            self.alert_manager.handle_alert
        )
        self.anomaly_detector = AnomalyDetector(
            self.config,
            self.alert_manager.handle_alert
        )
        self.traffic_analyzer = TrafficAnalyzer(self.config)
        self.packet_sniffer = PacketSniffer(
            self.interface,
            self.process_packet,
            self.config
        )

        self.is_running = False

    def process_packet(self, packet_info):
        """
        Process each captured packet through detection engines

        Args:
            packet_info (dict): Packet information
        """
        # Analyze traffic patterns
        self.traffic_analyzer.analyze_packet(packet_info)

        # Run signature-based detection
        self.signature_detector.analyze_packet(packet_info)

        # Run anomaly-based detection
        self.anomaly_detector.analyze_packet(packet_info)

    def start(self):
        """Start the NIDS"""
        print_banner()

        # Check for required privileges
        if not check_privileges():
            sys.exit(1)

        # Display configuration
        print(f"[*] Network Interface: {self.interface}")
        print(f"[*] Signature Detection: {'Enabled' if self.config.get('signature_detection', {}).get('enabled') else 'Disabled'}")
        print(f"[*] Anomaly Detection: {'Enabled' if self.config.get('anomaly_detection', {}).get('enabled') else 'Disabled'}")

        if self.config.get('anomaly_detection', {}).get('enabled'):
            baseline_time = self.config.get('anomaly_detection', {}).get('baseline_collection_time', 300)
            print(f"[*] Baseline Collection Time: {baseline_time} seconds")

        print("")

        # Start packet capture
        self.is_running = True
        self.packet_sniffer.start_sniffing()

        # Keep main thread alive
        try:
            while self.is_running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop the NIDS"""
        print("\n[*] Shutting down NIDS...")
        self.is_running = False
        self.packet_sniffer.stop_sniffing()

        # Print final statistics
        print("\n" + "=" * 60)
        print("FINAL STATISTICS")
        print("=" * 60)

        # Sniffer stats
        sniffer_stats = self.packet_sniffer.get_stats()
        print(f"\nPackets Captured: {sniffer_stats['packet_count']}")

        # Detection stats
        sig_stats = self.signature_detector.get_statistics()
        print(f"\nSignature Detection:")
        print(f"  Loaded Signatures: {sig_stats['signatures_loaded']}")

        anom_stats = self.anomaly_detector.get_statistics()
        print(f"\nAnomaly Detection:")
        print(f"  Baseline Established: {anom_stats['baseline_established']}")
        print(f"  Anomalies Detected: {anom_stats['anomaly_count']}")

        # Alert summary
        self.alert_manager.print_summary()

        print("[*] NIDS stopped successfully")


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

    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default='config/config.yaml'
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
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
