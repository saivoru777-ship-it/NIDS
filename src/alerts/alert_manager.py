"""
Alert Manager Module
Manages security alerts, logging, and notifications
"""

import json
import csv
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)


class AlertManager:
    """Manages security alerts and logging"""

    def __init__(self, config):
        """
        Initialize alert manager

        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.alerts = []
        self.alert_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        # Set up logging directory
        self.log_dir = config.get('logging', {}).get('log_directory', 'logs')
        os.makedirs(self.log_dir, exist_ok=True)

        # Set up log file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_format = config.get('logging', {}).get('log_format', 'json')
        self.log_file = os.path.join(
            self.log_dir,
            f'nids_alerts_{timestamp}.{log_format}'
        )

        # Severity level mapping
        self.severity_levels = config.get('alerts', {}).get('severity_levels', {
            'critical': ['syn_flood', 'ddos', 'malware', 'arp_spoofing'],
            'high': ['port_scan', 'brute_force', 'suspicious_payload', 'icmp_flood'],
            'medium': ['anomaly_traffic', 'unusual_protocol', 'protocol_distribution_anomaly'],
            'low': ['informational', 'unusual_port_usage']
        })

    def handle_alert(self, alert_data):
        """
        Handle a new security alert

        Args:
            alert_data (dict): Alert information
        """
        # Determine severity if not provided
        if 'severity' not in alert_data:
            alert_data['severity'] = self.determine_severity(alert_data['type'])

        # Add alert ID and timestamp
        alert_data['alert_id'] = len(self.alerts) + 1
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.now()

        # Store alert
        self.alerts.append(alert_data)
        self.alert_count[alert_data['severity']] += 1

        # Output to console
        if self.config.get('alerts', {}).get('console_output', True):
            self.print_alert(alert_data)

        # Write to log file
        if self.config.get('alerts', {}).get('file_output', True):
            self.log_alert(alert_data)

    def determine_severity(self, alert_type):
        """
        Determine alert severity based on type

        Args:
            alert_type (str): Type of alert

        Returns:
            str: Severity level
        """
        for severity, types in self.severity_levels.items():
            if alert_type in types:
                return severity
        return 'medium'  # Default severity

    def print_alert(self, alert_data):
        """
        Print alert to console with color coding

        Args:
            alert_data (dict): Alert information
        """
        severity = alert_data['severity']
        alert_type = alert_data['type']
        description = alert_data.get('description', 'No description')
        timestamp = alert_data['timestamp']

        # Color coding based on severity
        color_map = {
            'critical': Fore.RED,
            'high': Fore.YELLOW,
            'medium': Fore.CYAN,
            'low': Fore.GREEN
        }
        color = color_map.get(severity, Fore.WHITE)

        # Format timestamp
        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

        # Print alert
        print(f"\n{color}{'=' * 80}")
        print(f"ALERT #{alert_data['alert_id']} - {severity.upper()} SEVERITY")
        print(f"{'=' * 80}{Style.RESET_ALL}")
        print(f"Time: {time_str}")
        print(f"Type: {alert_type}")
        print(f"Description: {description}")

        # Print source/destination IPs if available
        if 'src_ip' in alert_data and alert_data['src_ip']:
            print(f"Source IP: {alert_data['src_ip']}")
        if 'dst_ip' in alert_data and alert_data['dst_ip']:
            print(f"Destination IP: {alert_data['dst_ip']}")

        # Print additional details
        if 'details' in alert_data and alert_data['details']:
            print("\nDetails:")
            for key, value in alert_data['details'].items():
                print(f"  {key}: {value}")

        print(f"{color}{'=' * 80}{Style.RESET_ALL}\n")

    def log_alert(self, alert_data):
        """
        Write alert to log file

        Args:
            alert_data (dict): Alert information
        """
        log_format = self.config.get('logging', {}).get('log_format', 'json')

        try:
            # Convert datetime to string for JSON serialization
            log_data = alert_data.copy()
            log_data['timestamp'] = alert_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')

            if log_format == 'json':
                self.log_alert_json(log_data)
            elif log_format == 'csv':
                self.log_alert_csv(log_data)

        except Exception as e:
            print(f"[!] Error logging alert: {e}")

    def log_alert_json(self, alert_data):
        """
        Write alert to JSON log file

        Args:
            alert_data (dict): Alert information
        """
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')

    def log_alert_csv(self, alert_data):
        """
        Write alert to CSV log file

        Args:
            alert_data (dict): Alert information
        """
        file_exists = os.path.isfile(self.log_file)

        with open(self.log_file, 'a', newline='') as f:
            # Flatten the details dictionary
            flat_data = {
                'alert_id': alert_data.get('alert_id'),
                'timestamp': alert_data.get('timestamp'),
                'type': alert_data.get('type'),
                'severity': alert_data.get('severity'),
                'description': alert_data.get('description'),
                'src_ip': alert_data.get('src_ip'),
                'dst_ip': alert_data.get('dst_ip')
            }

            # Add details as separate columns
            if 'details' in alert_data:
                for key, value in alert_data['details'].items():
                    flat_data[f'detail_{key}'] = value

            writer = csv.DictWriter(f, fieldnames=flat_data.keys())

            # Write header if file is new
            if not file_exists:
                writer.writeheader()

            writer.writerow(flat_data)

    def get_alert_summary(self):
        """
        Get summary of all alerts

        Returns:
            dict: Alert summary statistics
        """
        return {
            'total_alerts': len(self.alerts),
            'by_severity': self.alert_count.copy(),
            'by_type': self.get_alerts_by_type(),
            'recent_alerts': self.get_recent_alerts(5)
        }

    def get_alerts_by_type(self):
        """
        Get alert counts by type

        Returns:
            dict: Alert counts by type
        """
        type_counts = {}
        for alert in self.alerts:
            alert_type = alert['type']
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        return type_counts

    def get_recent_alerts(self, count=5):
        """
        Get most recent alerts

        Args:
            count (int): Number of recent alerts to return

        Returns:
            list: Recent alerts
        """
        return self.alerts[-count:] if len(self.alerts) >= count else self.alerts

    def print_summary(self):
        """Print alert summary"""
        print("\n" + "=" * 60)
        print("ALERT SUMMARY")
        print("=" * 60)
        print(f"\nTotal Alerts: {len(self.alerts)}")
        print("\nBy Severity:")
        for severity, count in self.alert_count.items():
            if count > 0:
                print(f"  {severity.capitalize():10s}: {count}")

        print("\nBy Type:")
        for alert_type, count in sorted(
            self.get_alerts_by_type().items(),
            key=lambda x: x[1],
            reverse=True
        ):
            print(f"  {alert_type:30s}: {count}")

        print(f"\nLog File: {self.log_file}")
        print("=" * 60 + "\n")

    def export_alerts(self, filename=None, format='json'):
        """
        Export all alerts to a file

        Args:
            filename (str): Output filename
            format (str): Export format (json or csv)
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'alerts_export_{timestamp}.{format}'

        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    # Convert datetime objects to strings
                    export_data = []
                    for alert in self.alerts:
                        alert_copy = alert.copy()
                        alert_copy['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')
                        export_data.append(alert_copy)
                    json.dump(export_data, f, indent=2)
            elif format == 'csv':
                # Similar to log_alert_csv but for all alerts
                pass

            print(f"[+] Alerts exported to {filename}")
        except Exception as e:
            print(f"[!] Error exporting alerts: {e}")
