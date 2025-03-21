"""Feature extraction module for network packets."""

import time
import numpy as np
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Union, Any

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

class PacketFeatureExtractor:
    """Extract features from network packets for anomaly detection."""

    def __init__(self, window_size: int = 100, window_timeout: int = 30):
        """
        Initialize the feature extractor.

        Args:
            window_size: Number of packets to collect before feature extraction
            window_timeout: Maximum time (seconds) to wait before processing a partial window
        """
        self.window_size = window_size
        self.window_timeout = window_timeout
        self.packet_buffer = []
        self.last_extraction_time = time.time()
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'tcp_flags': Counter(),
            'protocols': Counter(),
            'port_counts': Counter()
        })

    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Process a packet and add it to the buffer.
        Extract features when buffer reaches window size or timeout.

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary of extracted features or None if buffer not yet processed
        """
        # Skip packets without IP layer
        if not packet.haslayer(IP):
            return None

        # Add packet to buffer
        self.packet_buffer.append(packet)

        # Update flow statistics
        self._update_flow_stats(packet)

        # Check if we need to extract features
        current_time = time.time()
        timeout_reached = (current_time - self.last_extraction_time) > self.window_timeout

        if len(self.packet_buffer) >= self.window_size or timeout_reached:
            return self.extract_features()

        return None

    def _update_flow_stats(self, packet):
        """Update statistics for the flow this packet belongs to."""
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            # Create a flow key (5-tuple if TCP/UDP, otherwise 3-tuple)
            if TCP in packet:
                flow_key = (ip_src, ip_dst, proto, packet[TCP].sport, packet[TCP].dport)
                flags = packet[TCP].flags
                self.flow_stats[flow_key]['tcp_flags'].update([flags])
            elif UDP in packet:
                flow_key = (ip_src, ip_dst, proto, packet[UDP].sport, packet[UDP].dport)
            else:
                flow_key = (ip_src, ip_dst, proto)

            # Update flow statistics
            flow = self.flow_stats[flow_key]

            if flow['start_time'] is None:
                flow['start_time'] = time.time()

            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)
            flow['last_time'] = time.time()

            # Track protocols
            if TCP in packet:
                flow['protocols'].update(['TCP'])
                flow['port_counts'].update([packet[TCP].dport])
            elif UDP in packet:
                flow['protocols'].update(['UDP'])
                flow['port_counts'].update([packet[UDP].dport])
            elif ICMP in packet:
                flow['protocols'].update(['ICMP'])

            if DNS in packet:
                flow['protocols'].update(['DNS'])
            elif HTTPRequest in packet:
                flow['protocols'].update(['HTTP'])

    def extract_features(self) -> Dict[str, Any]:
        """
        Extract statistical features from the current packet buffer.

        Returns:
            Dictionary of extracted features
        """
        # Record time of extraction
        self.last_extraction_time = time.time()

        if not self.packet_buffer:
            return {}

        # Calculate window timespan
        window_start_time = min(p.time for p in self.packet_buffer if hasattr(p, 'time'))
        window_end_time = max(p.time for p in self.packet_buffer if hasattr(p, 'time'))
        window_duration = window_end_time - window_start_time

        # Initialize features dictionary
        features = {
            'timestamp': datetime.now().isoformat(),
            'window_size': len(self.packet_buffer),
            'window_duration': window_duration,
            'unique_src_ips': len(set(p[IP].src for p in self.packet_buffer if IP in p)),
            'unique_dst_ips': len(set(p[IP].dst for p in self.packet_buffer if IP in p)),
            'protocol_counts': {},
            'avg_packet_size': np.mean([len(p) for p in self.packet_buffer]),
            'std_packet_size': np.std([len(p) for p in self.packet_buffer]),
            'tcp_percent': 0,
            'udp_percent': 0,
            'icmp_percent': 0,
            'dns_percent': 0,
            'http_percent': 0,
            'avg_tcp_window_size': 0,
            'syn_flag_percent': 0,
            'fin_flag_percent': 0,
            'rst_flag_percent': 0,
            'unique_ports': 0,
            'port_entropy': 0,
        }

        # Rest of the implementation as in the original code
        # Count protocol types
        protocols = Counter()
        tcp_window_sizes = []
        tcp_flags = Counter()
        all_ports = []

        for p in self.packet_buffer:
            if IP in p:
                if TCP in p:
                    protocols.update(['TCP'])
                    tcp_window_sizes.append(p[TCP].window)
                    tcp_flags.update([p[TCP].flags])
                    all_ports.append(p[TCP].dport)
                    all_ports.append(p[TCP].sport)
                elif UDP in p:
                    protocols.update(['UDP'])
                    all_ports.append(p[UDP].dport)
                    all_ports.append(p[UDP].sport)
                elif ICMP in p:
                    protocols.update(['ICMP'])

                if DNS in p:
                    protocols.update(['DNS'])
                elif HTTPRequest in p or HTTPResponse in p or HTTP in p:
                    protocols.update(['HTTP'])

        # Calculate protocol percentages
        total_packets = len(self.packet_buffer)
        features['protocol_counts'] = dict(protocols)
        features['tcp_percent'] = (protocols['TCP'] / total_packets) * 100 if total_packets > 0 else 0
        features['udp_percent'] = (protocols['UDP'] / total_packets) * 100 if total_packets > 0 else 0
        features['icmp_percent'] = (protocols['ICMP'] / total_packets) * 100 if total_packets > 0 else 0
        features['dns_percent'] = (protocols['DNS'] / total_packets) * 100 if total_packets > 0 else 0
        features['http_percent'] = (protocols['HTTP'] / total_packets) * 100 if total_packets > 0 else 0

        # TCP specific features
        if tcp_window_sizes:
            features['avg_tcp_window_size'] = np.mean(tcp_window_sizes)

        if tcp_flags:
            total_tcp = sum(tcp_flags.values())
            features['syn_flag_percent'] = (tcp_flags.get(0x02, 0) / total_tcp) * 100 if total_tcp > 0 else 0
            features['fin_flag_percent'] = (tcp_flags.get(0x01, 0) / total_tcp) * 100 if total_tcp > 0 else 0
            features['rst_flag_percent'] = (tcp_flags.get(0x04, 0) / total_tcp) * 100 if total_tcp > 0 else 0

        # Port diversity stats
        port_counts = Counter(all_ports)
        features['unique_ports'] = len(port_counts)

        # Calculate port entropy (Shannon entropy)
        if port_counts:
            total_ports = sum(port_counts.values())
            port_probabilities = [count / total_ports for count in port_counts.values()]
            features['port_entropy'] = -sum(p * np.log2(p) for p in port_probabilities)

        # Flow-level features
        features['total_flows'] = len(self.flow_stats)
        flow_durations = []
        flow_packet_counts = []
        flow_byte_counts = []

        for flow_key, flow_data in self.flow_stats.items():
            if flow_data['start_time'] is not None and flow_data['last_time'] is not None:
                flow_durations.append(flow_data['last_time'] - flow_data['start_time'])
                flow_packet_counts.append(flow_data['packet_count'])
                flow_byte_counts.append(flow_data['byte_count'])

        if flow_durations:
            features['avg_flow_duration'] = np.mean(flow_durations)
            features['max_flow_duration'] = np.max(flow_durations)

        if flow_packet_counts:
            features['avg_packets_per_flow'] = np.mean(flow_packet_counts)
            features['max_packets_per_flow'] = np.max(flow_packet_counts)

        if flow_byte_counts:
            features['avg_bytes_per_flow'] = np.mean(flow_byte_counts)
            features['max_bytes_per_flow'] = np.max(flow_byte_counts)

        # Clear buffers for next window
        self.packet_buffer = []
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'tcp_flags': Counter(),
            'protocols': Counter(),
            'port_counts': Counter()
        })

        return features