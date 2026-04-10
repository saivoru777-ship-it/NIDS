"""
Packet Sniffer Module
Captures network packets using Scapy and extracts relevant features.
Uses a queue to decouple capture from analysis, preventing packet loss.
"""

import logging
import queue
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

logger = logging.getLogger(__name__)


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
        self.worker_thread = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._packet_queue = queue.Queue(maxsize=10000)

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

    def _enqueue_packet(self, packet):
        """Capture callback: extract info and put on queue"""
        try:
            with self._lock:
                self.packet_count += 1
            packet_info = self.extract_packet_info(packet)
            try:
                self._packet_queue.put_nowait(packet_info)
            except queue.Full:
                logger.warning("Packet queue full — dropping packet")
        except Exception as e:
            logger.error("Error processing packet: %s", e)

    def _worker(self):
        """Worker thread: consume packets from queue and run analysis"""
        while not self._stop_event.is_set():
            try:
                packet_info = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if self.packet_callback:
                    self.packet_callback(packet_info)
            except Exception as e:
                logger.error("Error in packet analysis: %s", e)

        # Drain remaining items on shutdown
        while not self._packet_queue.empty():
            try:
                packet_info = self._packet_queue.get_nowait()
                if self.packet_callback:
                    self.packet_callback(packet_info)
            except queue.Empty:
                break
            except Exception as e:
                logger.error("Error draining packet queue: %s", e)

    def start_sniffing(self):
        """Start packet capture in a separate thread"""
        if self.is_running:
            logger.warning("Sniffer is already running")
            return

        self.is_running = True
        self._stop_event.clear()
        logger.info("Starting packet capture on interface: %s", self.interface)
        logger.info("Press Ctrl+C to stop")

        # Start worker thread for analysis
        self.worker_thread = threading.Thread(target=self._worker, name='nids-worker')
        self.worker_thread.daemon = True
        self.worker_thread.start()

        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self._sniff, name='nids-sniffer')
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff(self):
        """Internal sniffing function"""
        try:
            packet_count = self.config.get('network', {}).get('packet_count', 0)
            promisc = self.config.get('network', {}).get('promiscuous_mode', True)

            sniff(
                iface=self.interface,
                prn=self._enqueue_packet,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                promisc=promisc,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except PermissionError:
            logger.error("Permission denied. Please run with sudo/administrator privileges")
            self.is_running = False
        except Exception as e:
            logger.error("Error during packet capture: %s", e)
            self.is_running = False

    def stop_sniffing(self):
        """Stop packet capture gracefully"""
        self._stop_event.set()
        self.is_running = False

        # Wait for worker to drain queue
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)

        with self._lock:
            count = self.packet_count
        logger.info("Stopped packet capture. Total packets captured: %d", count)

    def get_stats(self):
        """Get sniffer statistics"""
        with self._lock:
            count = self.packet_count
        return {
            'is_running': self.is_running,
            'packet_count': count,
            'interface': self.interface,
            'queue_depth': self._packet_queue.qsize()
        }
