"""
Packet Sniffer Module
Captures network packets using Scapy and extracts relevant features
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import threading


class PacketSniffer:
    """Captures and processes network packets"""

    def __init__(self, interface, packet_callback, config):
        """
        Initialize packet sniffer

        Args:
            interface (str): Network interface to sniff on
            packet_callback (function): Callback function to process packets
            config (dict): Configuration dictionary
        """
        self.interface = interface
        self.packet_callback = packet_callback
        self.config = config
        self.is_running = False
        self.packet_count = 0
        self.sniff_thread = None

    def extract_packet_info(self, packet):
        """
        Extract relevant information from packet

        Args:
            packet: Scapy packet object

        Returns:
            dict: Packet information
        """
        packet_info = {
            'timestamp': datetime.now(),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'packet_size': len(packet),
            'payload': None
        }

        # Extract IP layer information
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto

            # Extract TCP information
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['tcp_flags'] = packet[TCP].flags
                packet_info['protocol'] = 'TCP'

                # Extract payload
                if packet[TCP].payload:
                    packet_info['payload'] = bytes(packet[TCP].payload)

            # Extract UDP information
            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['protocol'] = 'UDP'

                # Extract payload
                if packet[UDP].payload:
                    packet_info['payload'] = bytes(packet[UDP].payload)

            # Extract ICMP information
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type
                packet_info['icmp_code'] = packet[ICMP].code

        # Extract ARP information
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['arp_op'] = packet[ARP].op
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            packet_info['src_mac'] = packet[ARP].hwsrc
            packet_info['dst_mac'] = packet[ARP].hwdst

        return packet_info

    def process_packet(self, packet):
        """
        Process each captured packet

        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            packet_info = self.extract_packet_info(packet)

            # Call the callback function with packet info
            if self.packet_callback:
                self.packet_callback(packet_info)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_sniffing(self):
        """Start packet capture in a separate thread"""
        if self.is_running:
            print("Sniffer is already running")
            return

        self.is_running = True
        print(f"[*] Starting packet capture on interface: {self.interface}")
        print("[*] Press Ctrl+C to stop")

        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self._sniff)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff(self):
        """Internal sniffing function"""
        try:
            packet_count = self.config.get('network', {}).get('packet_count', 0)
            promisc = self.config.get('network', {}).get('promiscuous_mode', True)

            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                promisc=promisc
            )
        except PermissionError:
            print("[!] Error: Permission denied. Please run with sudo/administrator privileges")
            self.is_running = False
        except Exception as e:
            print(f"[!] Error during packet capture: {e}")
            self.is_running = False

    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
        print(f"\n[*] Stopped packet capture. Total packets captured: {self.packet_count}")

    def get_stats(self):
        """Get sniffer statistics"""
        return {
            'is_running': self.is_running,
            'packet_count': self.packet_count,
            'interface': self.interface
        }
