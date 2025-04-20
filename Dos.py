#!/usr/bin/env python3
# Advanced DoS Attack Detection System
# This system monitors network traffic for signs of DoS attacks using various detection algorithms

import time
import argparse
import pandas as pd
import numpy as np
from collections import defaultdict, Counter, deque
from datetime import datetime
import threading
import pickle
import os
import logging
import socket
import struct
import sys
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dos_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DoSDetector")

class NetworkStatistics:
    """Maintains various traffic statistics for DoS detection"""
    
    def __init__(self, window_size=60):
        # Time window in seconds for calculating rates
        self.window_size = window_size
        
        # Traffic counters
        self.packet_count = 0
        self.byte_count = 0
        
        # IP-based counters
        self.src_ip_packets = defaultdict(int)
        self.dst_ip_packets = defaultdict(int)
        self.connections = defaultdict(int)  # (src_ip, dst_ip, dst_port) -> count
        
        # Protocol counters
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        
        # TCP flags
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        
        # Time-based sliding window statistics
        self.packet_times = deque()
        self.bytes_window = deque()
        
        # Connection tracking for half-open detection
        self.syn_tracker = {}  # src_ip -> {dst_ip -> {port -> timestamp}}
        self.established_conns = set()  # (src_ip, dst_ip, port)
        
        # Entropy calculation data
        self.dst_ip_entropy_samples = deque(maxlen=100)
        self.src_ip_entropy_samples = deque(maxlen=100)
        self.port_entropy_samples = deque(maxlen=100)
        
        # Historical data for baseline comparison
        self.baseline = {
            'packets_per_sec': deque(maxlen=10),
            'bytes_per_sec': deque(maxlen=10),
            'tcp_ratio': deque(maxlen=10),
            'udp_ratio': deque(maxlen=10),
            'icmp_ratio': deque(maxlen=10),
            'syn_ratio': deque(maxlen=10),
            'unique_ips': deque(maxlen=10),
        }
        
        # Last calculation time
        self.last_calculation = time.time()
        
        # Current alarm state
        self.alarm_state = False
        
        # List of active alerts
        self.active_alerts = set()
        
    def update(self, packet):
        """Update statistics with a new packet"""
        current_time = time.time()
        
        # Basic packet info
        self.packet_count += 1
        packet_length = len(packet)
        self.byte_count += packet_length
        
        # Store packet timestamp for rate calculations
        self.packet_times.append(current_time)
        self.bytes_window.append(packet_length)
        
        # Clean old entries from time windows
        self._clean_old_entries(current_time)
        
        # Extract IP information if available
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.src_ip_packets[src_ip] += 1
            self.dst_ip_packets[dst_ip] += 1
            
            # Protocol specific counters
            if TCP in packet:
                self.tcp_count += 1
                tcp = packet[TCP]
                dst_port = tcp.dport
                
                # Connection tracking
                conn_tuple = (src_ip, dst_ip, dst_port)
                self.connections[conn_tuple] += 1
                
                # TCP flag analysis
                if tcp.flags & 0x02:  # SYN flag
                    self.syn_count += 1
                    # Track SYN packets for half-open connection detection
                    if src_ip not in self.syn_tracker:
                        self.syn_tracker[src_ip] = {}
                    if dst_ip not in self.syn_tracker[src_ip]:
                        self.syn_tracker[src_ip][dst_ip] = {}
                    self.syn_tracker[src_ip][dst_ip][dst_port] = current_time
                
                if tcp.flags & 0x10:  # ACK flag
                    self.ack_count += 1
                    # If SYN-ACK, mark as established
                    if tcp.flags & 0x02:  # SYN flag also set
                        self.established_conns.add((dst_ip, src_ip, tcp.sport))
                
                if tcp.flags & 0x01:  # FIN flag
                    self.fin_count += 1
                    if (src_ip, dst_ip, dst_port) in self.established_conns:
                        self.established_conns.remove((src_ip, dst_ip, dst_port))
                
                if tcp.flags & 0x04:  # RST flag
                    self.rst_count += 1
                    if (src_ip, dst_ip, dst_port) in self.established_conns:
                        self.established_conns.remove((src_ip, dst_ip, dst_port))
                
                if tcp.flags & 0x08:  # PSH flag
                    self.psh_count += 1
                
                if tcp.flags & 0x20:  # URG flag
                    self.urg_count += 1
                
            elif UDP in packet:
                self.udp_count += 1
                dst_port = packet[UDP].dport
                conn_tuple = (src_ip, dst_ip, dst_port)
                self.connections[conn_tuple] += 1
                
            elif ICMP in packet:
                self.icmp_count += 1
                
            else:
                self.other_count += 1
        
        # Calculate statistics periodically to reduce computational load
        if current_time - self.last_calculation > 2:  # Calculate every 2 seconds
            self._calculate_statistics()
            self.last_calculation = current_time
            
    def _clean_old_entries(self, current_time):
        """Remove entries older than window_size from tracking data structures"""
        cutoff_time = current_time - self.window_size
        
        # Clean packet times
        while self.packet_times and self.packet_times[0] < cutoff_time:
            self.packet_times.popleft()
            
        # Clean bytes window
        while self.bytes_window and len(self.packet_times) < len(self.bytes_window):
            self.bytes_window.popleft()
            
        # Clean half-open connection tracking
        for src_ip in list(self.syn_tracker.keys()):
            for dst_ip in list(self.syn_tracker[src_ip].keys()):
                for port in list(self.syn_tracker[src_ip][dst_ip].keys()):
                    if self.syn_tracker[src_ip][dst_ip][port] < cutoff_time:
                        del self.syn_tracker[src_ip][dst_ip][port]
                
                if not self.syn_tracker[src_ip][dst_ip]:
                    del self.syn_tracker[src_ip][dst_ip]
            
            if not self.syn_tracker[src_ip]:
                del self.syn_tracker[src_ip]
                
    def _calculate_statistics(self):
        """Calculate derived statistics and check for attack patterns"""
        if not self.packet_times:
            return
        
        current_time = time.time()
        window_duration = current_time - self.packet_times[0] if self.packet_times else self.window_size
        
        # Avoid division by zero
        if window_duration == 0:
            window_duration = 1
            
        if self.packet_count == 0:
            return
            
        # Calculate rates
        packets_per_sec = len(self.packet_times) / window_duration
        bytes_per_sec = sum(self.bytes_window) / window_duration
        
        # Protocol ratios
        total_protocol_packets = self.tcp_count + self.udp_count + self.icmp_count + self.other_count
        tcp_ratio = self.tcp_count / max(1, total_protocol_packets)
        udp_ratio = self.udp_count / max(1, total_protocol_packets)
        icmp_ratio = self.icmp_count / max(1, total_protocol_packets)
        
        # TCP flag ratios
        total_tcp = max(1, self.tcp_count)
        syn_ratio = self.syn_count / total_tcp
        fin_ratio = self.fin_count / total_tcp
        rst_ratio = self.rst_count / total_tcp
        psh_ratio = self.psh_count / total_tcp
        ack_ratio = self.ack_count / total_tcp
        
        # Count unique IPs
        unique_src_ips = len(self.src_ip_packets)
        unique_dst_ips = len(self.dst_ip_packets)
        
        # Calculate IP distribution entropy
        src_ip_entropy = self._calculate_entropy(self.src_ip_packets)
        dst_ip_entropy = self._calculate_entropy(self.dst_ip_packets)
        
        # Store entropy samples
        self.src_ip_entropy_samples.append(src_ip_entropy)
        self.dst_ip_entropy_samples.append(dst_ip_entropy)
        
        # Store baseline metrics
        self.baseline['packets_per_sec'].append(packets_per_sec)
        self.baseline['bytes_per_sec'].append(bytes_per_sec)
        self.baseline['tcp_ratio'].append(tcp_ratio)
        self.baseline['udp_ratio'].append(udp_ratio)
        self.baseline['icmp_ratio'].append(icmp_ratio)
        self.baseline['syn_ratio'].append(syn_ratio)
        self.baseline['unique_ips'].append(unique_src_ips)
        
        # Now check for various attack patterns
        self._detect_attacks(packets_per_sec, bytes_per_sec, tcp_ratio, udp_ratio, 
                           icmp_ratio, syn_ratio, unique_src_ips, unique_dst_ips,
                           src_ip_entropy, dst_ip_entropy)
        
    def _calculate_entropy(self, counter_dict):
        """Calculate Shannon entropy of the given distribution"""
        total = sum(counter_dict.values())
        if total == 0:
            return 0
            
        entropy = 0
        for count in counter_dict.values():
            probability = count / total
            entropy -= probability * np.log2(probability) if probability > 0 else 0
            
        return entropy
        
    def _detect_attacks(self, packets_per_sec, bytes_per_sec, tcp_ratio, udp_ratio, 
                       icmp_ratio, syn_ratio, unique_src_ips, unique_dst_ips,
                       src_ip_entropy, dst_ip_entropy):
        """Detect various DoS attack patterns"""
        alerts = set()
        
        # Get baseline values
        baseline_packets_per_sec = np.mean(self.baseline['packets_per_sec']) if self.baseline['packets_per_sec'] else 0
        baseline_bytes_per_sec = np.mean(self.baseline['bytes_per_sec']) if self.baseline['bytes_per_sec'] else 0
        baseline_tcp_ratio = np.mean(self.baseline['tcp_ratio']) if self.baseline['tcp_ratio'] else 0
        baseline_udp_ratio = np.mean(self.baseline['udp_ratio']) if self.baseline['udp_ratio'] else 0
        baseline_icmp_ratio = np.mean(self.baseline['icmp_ratio']) if self.baseline['icmp_ratio'] else 0
        baseline_syn_ratio = np.mean(self.baseline['syn_ratio']) if self.baseline['syn_ratio'] else 0
        baseline_unique_ips = np.mean(self.baseline['unique_ips']) if self.baseline['unique_ips'] else 0
        
        # Apply detection rules
        
        # 1. SYN Flood detection
        if (syn_ratio > 0.8 and self.syn_count > 100 and 
            syn_ratio > 1.5 * baseline_syn_ratio and 
            len(self.syn_tracker) > 0):
            
            # Check for half-open connections
            half_open_count = sum(len(ports) for src in self.syn_tracker.values() 
                               for dst in src.values() 
                               for ports in [dst])
                               
            if half_open_count > 50:
                alerts.add(("SYN FLOOD", f"Detected {half_open_count} half-open connections with SYN ratio: {syn_ratio:.2f}"))
        
        # 2. UDP Flood detection
        if (udp_ratio > 0.8 and self.udp_count > 100 and 
            udp_ratio > 1.5 * baseline_udp_ratio and
            packets_per_sec > 1.5 * baseline_packets_per_sec):
            alerts.add(("UDP FLOOD", f"High UDP traffic detected: {packets_per_sec:.2f} packets/sec, UDP ratio: {udp_ratio:.2f}"))
        
        # 3. ICMP Flood detection
        if (icmp_ratio > 0.5 and self.icmp_count > 50 and 
            icmp_ratio > 1.5 * baseline_icmp_ratio):
            alerts.add(("ICMP FLOOD", f"High ICMP traffic detected: {self.icmp_count} ICMP packets, ICMP ratio: {icmp_ratio:.2f}"))
        
        # 4. HTTP Flood detection (lots of TCP connections to common HTTP ports)
        http_ports = {80, 443, 8080, 8443}
        http_conns = sum(1 for (_, _, port), count in self.connections.items() 
                        if port in http_ports and count > 0)
        
        if http_conns > 100 and tcp_ratio > 0.8:
            alerts.add(("HTTP FLOOD", f"Potential HTTP flood: {http_conns} connections to HTTP ports"))
        
        # 5. Volumetric attack detection
        if (packets_per_sec > 3 * baseline_packets_per_sec and packets_per_sec > 1000) or \
           (bytes_per_sec > 3 * baseline_bytes_per_sec and bytes_per_sec > 1000000):  # > 1 MB/s
            alerts.add(("VOLUMETRIC ATTACK", f"High traffic volume: {packets_per_sec:.2f} packets/sec, {bytes_per_sec/1000000:.2f} MB/sec"))
        
        # 6. Distributed attack detection (based on source IP entropy)
        src_entropy_mean = np.mean(self.src_ip_entropy_samples) if self.src_ip_entropy_samples else 0
        if (src_ip_entropy > 4.0 and unique_src_ips > 30 and 
            unique_src_ips > 2 * baseline_unique_ips):
            alerts.add(("DISTRIBUTED ATTACK", f"High source IP entropy: {src_ip_entropy:.2f}, unique IPs: {unique_src_ips}"))
        
        # 7. Targeted attack detection (based on destination IP entropy)
        if (dst_ip_entropy < 1.0 and unique_dst_ips < 5 and 
            packets_per_sec > baseline_packets_per_sec):
            alerts.add(("TARGETED ATTACK", f"Low destination IP entropy: {dst_ip_entropy:.2f}, unique dest IPs: {unique_dst_ips}"))
        
        # 8. Port scanning detection
        port_counts = Counter(port for (_, _, port), _ in self.connections.items())
        unique_ports = len(port_counts)
        most_common_port_count = port_counts.most_common(1)[0][1] if port_counts else 0
        port_ratio = most_common_port_count / max(1, sum(port_counts.values()))
        
        if unique_ports > 100 and port_ratio < 0.1:
            alerts.add(("PORT SCAN", f"Possible port scan: {unique_ports} unique ports accessed"))
        
        # Update active alerts
        self.active_alerts = alerts
        
        # Log new alerts
        for alert_type, alert_msg in alerts - self._previous_alerts():
            logger.warning(f"ALERT: {alert_type} - {alert_msg}")
            
        # Log resolved alerts
        for alert_type, alert_msg in self._previous_alerts() - alerts:
            logger.info(f"RESOLVED: {alert_type}")
        
        # Set alarm state if any alerts are active
        self.alarm_state = len(alerts) > 0
        
    def _previous_alerts(self):
        """Return the previous set of active alerts"""
        return self.active_alerts
        
    def get_summary(self):
        """Get a summary of current network statistics and alert status"""
        window_duration = time.time() - self.packet_times[0] if self.packet_times else self.window_size
        
        # Avoid division by zero
        if window_duration == 0:
            window_duration = 1
            
        if self.packet_count == 0:
            return {
                "status": "No traffic monitored yet",
                "alerts": []
            }
            
        # Calculate rates
        packets_per_sec = len(self.packet_times) / window_duration
        bytes_per_sec = sum(self.bytes_window) / window_duration
        
        # Protocol distribution
        total_protocol_packets = self.tcp_count + self.udp_count + self.icmp_count + self.other_count
        
        summary = {
            "status": "ALERT" if self.alarm_state else "Normal",
            "traffic": {
                "packets_per_sec": round(packets_per_sec, 2),
                "bytes_per_sec": round(bytes_per_sec, 2),
                "total_packets": self.packet_count,
                "unique_src_ips": len(self.src_ip_packets),
                "unique_dst_ips": len(self.dst_ip_packets),
                "protocol_distribution": {
                    "tcp": round(self.tcp_count / max(1, total_protocol_packets) * 100, 2),
                    "udp": round(self.udp_count / max(1, total_protocol_packets) * 100, 2),
                    "icmp": round(self.icmp_count / max(1, total_protocol_packets) * 100, 2),
                    "other": round(self.other_count / max(1, total_protocol_packets) * 100, 2)
                }
            },
            "alerts": [{"type": alert_type, "message": msg} for alert_type, msg in self.active_alerts]
        }
        
        return summary


class DoSDetector:
    """Main DoS detection system class"""
    
    def __init__(self, interface=None, pcap_file=None, output_file="dos_detection_results.json", 
                 baseline_file="baseline.pkl", window_size=60, alert_threshold=0.7, 
                 mitigation_enabled=False):
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.baseline_file = baseline_file
        self.window_size = window_size
        self.alert_threshold = alert_threshold
        self.mitigation_enabled = mitigation_enabled
        
        # Initialize statistics tracker
        self.stats = NetworkStatistics(window_size=window_size)
        
        # Setup for output writing
        self.last_write = time.time()
        self.write_interval = 5  # Write results every 5 seconds
        
        # Load baseline if available
        self._load_baseline()
        
        # Flag for stopping the detector
        self.running = True
        
    def _load_baseline(self):
        """Load baseline statistics if available"""
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, 'rb') as f:
                    baseline_data = pickle.load(f)
                    
                # Update the statistics object with baseline data
                logger.info(f"Loaded baseline from {self.baseline_file}")
                
                # TODO: Apply baseline data to stats object
                
            except Exception as e:
                logger.error(f"Failed to load baseline: {str(e)}")
                
    def _save_baseline(self):
        """Save current baseline statistics"""
        try:
            with open(self.baseline_file, 'wb') as f:
                # Save current baseline data
                baseline_data = {
                    'packets_per_sec': list(self.stats.baseline['packets_per_sec']),
                    'bytes_per_sec': list(self.stats.baseline['bytes_per_sec']),
                    'tcp_ratio': list(self.stats.baseline['tcp_ratio']),
                    'udp_ratio': list(self.stats.baseline['udp_ratio']),
                    'icmp_ratio': list(self.stats.baseline['icmp_ratio']),
                    'syn_ratio': list(self.stats.baseline['syn_ratio']),
                    'unique_ips': list(self.stats.baseline['unique_ips']),
                    'timestamp': time.time()
                }
                pickle.dump(baseline_data, f)
                logger.info(f"Saved baseline to {self.baseline_file}")
        except Exception as e:
            logger.error(f"Failed to save baseline: {str(e)}")
                
    def _write_results(self):
        """Write detection results to file"""
        # Skip if not enough time has passed
        current_time = time.time()
        if current_time - self.last_write < self.write_interval:
            return
            
        self.last_write = current_time
        
        try:
            summary = self.stats.get_summary()
            summary['timestamp'] = datetime.now().isoformat()
            
            with open(self.output_file, 'w') as f:
                json.dump(summary, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to write results: {str(e)}")
            
    def _packet_handler(self, packet):
        """Process a single packet"""
        if not self.running:
            return
            
        try:
            # Update statistics with the new packet
            self.stats.update(packet)
            
            # Write results periodically
            self._write_results()
            
            # Check if we should apply mitigation
            if self.mitigation_enabled and self.stats.alarm_state:
                self._apply_mitigation()
                
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            
    def _apply_mitigation(self):
        """Apply mitigation strategies for detected attacks"""
        # This would integrate with firewalls, routers, etc.
        # Here we just log what we would do
        
        for alert_type, alert_msg in self.stats.active_alerts:
            if alert_type == "SYN FLOOD":
                logger.info("Mitigation: Would apply SYN cookies and rate limiting")
            elif alert_type == "UDP FLOOD":
                logger.info("Mitigation: Would apply UDP rate limiting")
            elif alert_type == "ICMP FLOOD":
                logger.info("Mitigation: Would block ICMP traffic temporarily")
            elif alert_type == "HTTP FLOOD":
                logger.info("Mitigation: Would apply HTTP request rate limiting and captcha")
            elif alert_type == "VOLUMETRIC ATTACK":
                logger.info("Mitigation: Would divert traffic through scrubbing center")
            elif alert_type == "DISTRIBUTED ATTACK":
                logger.info("Mitigation: Would apply dynamic IP reputation filtering")
            elif alert_type == "TARGETED ATTACK":
                logger.info("Mitigation: Would apply additional protection to target hosts")
            elif alert_type == "PORT SCAN":
                logger.info("Mitigation: Would block scanning IP addresses")
                
    def start(self):
        """Start the DoS detection system"""
        try:
            logger.info("Starting DoS Detection System")
            
            if self.pcap_file:
                logger.info(f"Reading from PCAP file: {self.pcap_file}")
                sniff(offline=self.pcap_file, prn=self._packet_handler, store=0)
                logger.info("Finished processing PCAP file")
                
            elif self.interface:
                logger.info(f"Capturing on interface: {self.interface}")
                sniff(iface=self.interface, prn=self._packet_handler, store=0)
                
            else:
                logger.info("Capturing on default interface")
                sniff(prn=self._packet_handler, store=0)
                
        except KeyboardInterrupt:
            logger.info("Detection stopped by user")
            
        except Exception as e:
            logger.error(f"Error in detection system: {str(e)}")
            
        finally:
            self.running = False
            self._save_baseline()
            logger.info("DoS Detection System stopped")
            
    def stop(self):
        """Stop the DoS detection system"""
        self.running = False
        logger.info("Stopping DoS Detection System")


def main():
    """Main function to run the DoS Detection system"""
    parser = argparse.ArgumentParser(description='Advanced DoS Attack Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-p', '--pcap', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', default='dos_detection_results.json', 
                        help='Output file for detection results')
    parser.add_argument('-b', '--baseline', default='baseline.pkl',
                        help='Baseline file for normal traffic patterns')
    parser.add_argument('-w', '--window', type=int, default=60,
                        help='Time window size in seconds for traffic analysis')
    parser.add_argument('-t', '--threshold', type=float, default=0.7,
                        help='Alert threshold (0.0-1.0)')
    parser.add_argument('-m', '--mitigate', action='store_true',
                        help='Enable automatic mitigation responses')
    
    args = parser.parse_args()
    
    detector = DoSDetector(
        interface=args.interface,
        pcap_file=args.pcap,
        output_file=args.output,
        baseline_file=args.baseline,
        window_size=args.window,
        alert_threshold=args.threshold,
        mitigation_enabled=args.mitigate
    )
    
    try:
        detector.start()
    except KeyboardInterrupt:
        detector.stop()

if __name__ == "__main__":
    main()