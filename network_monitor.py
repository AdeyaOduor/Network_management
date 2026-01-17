#!/usr/bin/env python3
"""
Enhanced Network Monitoring Tool
Version: 2.0.0
Optimized for production deployment with comprehensive monitoring capabilities

# Ubuntu/Debian
sudo apt-get install python3-pip python3-dev libpcap-dev tcpdump

# RHEL/CentOS
sudo yum install python3-pip python3-devel libpcap-devel tcpdump

# macOS
brew install python3 libpcap tcpdump

pip install -r requirements.txt

===================================================================================
#!/bin/bash
 deploy_network_monitor.sh
# Comprehensive deployment script for the Enhanced Network Monitoring Tool
chmod +x deploy_network_monitor.sh
./deploy_network_monitor.sh 
====================================================================================
# Monitor hosts
python network_monitor.py monitor google.com 8.8.8.8 --interval 10

# Scan ports
python network_monitor.py scan 192.168.1.1 --ports 1-1024,3389,8080

# Monitor bandwidth
python network_monitor.py bandwidth --interface eth0 --graph

# Analyze traffic
sudo python network_monitor.py traffic --count 1000 --protocol tcp

# Show system info
python network_monitor.py info

=====================================================================================
Common Issues

    Permission denied for packet capture
    bash

# Linux
sudo setcap cap_net_raw=eip $(which python3)

# Or run with sudo
sudo python network_monitor.py traffic

Missing dependencies
bash

pip install -r requirements.txt --upgrade

========================================================================================
"""

#!/usr/bin/env python3
"""
Enhanced Network Monitoring Tool
Version: 2.0.0
Optimized for production deployment with comprehensive monitoring capabilities
"""

import os
import sys
import platform
import subprocess
import time
import socket
import threading
import queue
import signal
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json

# Third-party imports with fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Install with: pip install psutil")
    print("Bandwidth monitoring will be disabled.")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")
    print("Packet analysis will be disabled.")

try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not installed. Install with: pip install matplotlib")
    print("Real-time graphing will be disabled.")

import argparse
import logging
import configparser
from concurrent.futures import ThreadPoolExecutor, as_completed

# Constants
DEFAULT_CONFIG_PATH = 'config.ini'
DEFAULT_LOG_FILE = 'network_monitor.log'
MAX_WORKERS = 10
BUFFER_SIZE = 1000
SOCKET_TIMEOUT = 2

class Severity(Enum):
    """Log severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class ScanResult:
    """Structure for scan results"""
    host: str
    port: int
    status: bool
    service: str = ""
    response_time: float = 0.0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class TrafficStats:
    """Structure for traffic statistics"""
    timestamp: datetime
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    error_in: int
    error_out: int
    drop_in: int
    drop_out: int

class EnhancedLogger:
    """Enhanced logging with rotation and multiple handlers"""
    
    def __init__(self, log_file: str = DEFAULT_LOG_FILE, log_level: str = "INFO"):
        self.logger = logging.getLogger('NetworkMonitor')
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # File handler with rotation
        try:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
        except (ImportError, OSError):
            file_handler = logging.FileHandler(log_file)
        
        file_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log(self, message: str, severity: Severity = Severity.INFO, exc_info: bool = False):
        """Log message with specified severity"""
        log_method = getattr(self.logger, severity.value.lower())
        log_method(message, exc_info=exc_info)
    
    def info(self, message: str):
        self.log(message, Severity.INFO)
    
    def warning(self, message: str):
        self.log(message, Severity.WARNING)
    
    def error(self, message: str, exc_info: bool = False):
        self.log(message, Severity.ERROR, exc_info)
    
    def critical(self, message: str, exc_info: bool = False):
        self.log(message, Severity.CRITICAL, exc_info)

class ConfigManager:
    """Configuration management with validation"""
    
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.logger = EnhancedLogger()
        self.load_config()
    
    def load_config(self):
        """Load and validate configuration"""
        if not os.path.exists(self.config_path):
            self.create_default_config()
        
        try:
            self.config.read(self.config_path)
            self.validate_config()
            self.logger.info(f"Configuration loaded from {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['DEFAULT'] = {
            'log_level': 'INFO',
            'max_workers': '10',
            'ping_timeout': '2',
            'scan_timeout': '1',
            'bandwidth_interval': '1',
            'traffic_buffer_size': '1000',
            'enable_alerts': 'true',
            'alert_threshold': '80'
        }
        
        self.config['Monitoring'] = {
            'default_hosts': 'google.com,8.8.8.8,localhost',
            'scan_ports': '1-1024,3389,8080,8443'
        }
        
        self.config['Email'] = {
            'enabled': 'false',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'sender': '',
            'password': '',
            'recipients': ''
        }
        
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)
        
        self.logger.info(f"Default configuration created at {self.config_path}")
    
    def validate_config(self):
        """Validate configuration values"""
        required_sections = ['DEFAULT', 'Monitoring']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required section: {section}")
    
    def get(self, section: str, key: str, fallback: Any = None):
        """Get configuration value with fallback"""
        try:
            return self.config.get(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

class NetworkMonitor:
    """Main network monitoring class"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.logger = EnhancedLogger(
            log_level=config.get('DEFAULT', 'log_level', 'INFO')
        )
        self.running = False
        self.stats_queue = queue.Queue(maxsize=BUFFER_SIZE)
        self.packet_queue = queue.Queue(maxsize=BUFFER_SIZE)
        self.executor = ThreadPoolExecutor(
            max_workers=int(config.get('DEFAULT', 'max_workers', MAX_WORKERS))
        )
        
        # Signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.info("Network Monitor initialized")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.executor.shutdown(wait=False)
        sys.exit(0)
    
    def ping_host(self, host: str, timeout: int = None) -> Tuple[bool, float]:
        """Ping a host with timeout and return success status and response time"""
        if timeout is None:
            timeout = int(self.config.get('DEFAULT', 'ping_timeout', 2))
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '1'
        
        try:
            # Use system ping command
            cmd = ['ping', param, count, '-W', str(timeout * 1000), host] if platform.system().lower() == 'linux' else \
                  ['ping', param, count, '-w', str(timeout * 1000), host] if platform.system().lower() == 'windows' else \
                  ['ping', param, count, '-t', str(timeout), host]
            
            start_time = time.time()
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout + 1
            )
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            success = result.returncode == 0
            if success:
                self.logger.info(f"Ping to {host} successful ({response_time:.2f}ms)")
            else:
                self.logger.warning(f"Ping to {host} failed")
            
            return success, response_time
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping to {host} timed out")
            return False, timeout * 1000
        except Exception as e:
            self.logger.error(f"Error pinging {host}: {e}")
            return False, 0.0
    
    def monitor_hosts(self, hosts: List[str], interval: int = 5, duration: int = None):
        """Monitor multiple hosts with concurrent pinging"""
        self.logger.info(f"Starting host monitoring for {len(hosts)} hosts")
        self.running = True
        
        start_time = time.time()
        results = {}
        
        try:
            while self.running:
                current_time = time.time()
                
                # Check duration limit
                if duration and (current_time - start_time) > duration:
                    self.logger.info("Monitoring duration reached, stopping...")
                    break
                
                futures = {}
                with ThreadPoolExecutor(max_workers=min(len(hosts), MAX_WORKERS)) as executor:
                    for host in hosts:
                        future = executor.submit(self.ping_host, host)
                        futures[future] = host
                
                # Process results as they complete
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        success, response_time = future.result()
                        results[host] = {
                            'status': 'UP' if success else 'DOWN',
                            'response_time': response_time,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Print status update
                        status_icon = "✅" if success else "❌"
                        print(f"{status_icon} {host}: {response_time:.2f}ms")
                        
                    except Exception as e:
                        self.logger.error(f"Error processing ping result for {host}: {e}")
                
                # Generate summary report
                self._generate_monitoring_report(results)
                
                # Wait for next interval
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
        finally:
            self.running = False
            self._generate_final_report(results)
    
    def _generate_monitoring_report(self, results: Dict):
        """Generate periodic monitoring report"""
        if not results:
            return
        
        up_count = sum(1 for r in results.values() if r['status'] == 'UP')
        down_count = len(results) - up_count
        
        print(f"\n{'='*50}")
        print(f"Monitoring Report - {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*50}")
        print(f"Hosts UP: {up_count}/{len(results)}")
        print(f"Hosts DOWN: {down_count}/{len(results)}")
        
        if up_count > 0:
            avg_response = sum(r['response_time'] for r in results.values() if r['status'] == 'UP') / up_count
            print(f"Average Response Time: {avg_response:.2f}ms")
        print(f"{'='*50}\n")
    
    def _generate_final_report(self, results: Dict):
        """Generate final monitoring report"""
        print(f"\n{'='*50}")
        print(f"FINAL MONITORING REPORT")
        print(f"{'='*50}")
        
        for host, data in results.items():
            status_icon = "✅" if data['status'] == 'UP' else "❌"
            print(f"{status_icon} {host:20} {data['status']:10} {data['response_time']:8.2f}ms")
        
        print(f"{'='*50}")
    
    def scan_ports(self, host: str, ports: List[Tuple[int, int]], timeout: int = None) -> List[ScanResult]:
        """Scan multiple port ranges on a host"""
        if timeout is None:
            timeout = int(self.config.get('DEFAULT', 'scan_timeout', 1))
        
        self.logger.info(f"Starting port scan on {host} for {len(ports)} port ranges")
        
        scan_results = []
        port_queue = queue.Queue()
        
        # Expand port ranges into individual ports
        for start, end in ports:
            for port in range(start, end + 1):
                port_queue.put(port)
        
        total_ports = port_queue.qsize()
        scanned_ports = 0
        
        def scan_worker():
            while not port_queue.empty() and self.running:
                try:
                    port = port_queue.get_nowait()
                    result = self._scan_single_port(host, port, timeout)
                    scan_results.append(result)
                    
                    nonlocal scanned_ports
                    scanned_ports += 1
                    
                    # Progress update every 10%
                    if scanned_ports % max(1, total_ports // 10) == 0:
                        progress = (scanned_ports / total_ports) * 100
                        print(f"Scan progress: {progress:.1f}% ({scanned_ports}/{total_ports})")
                    
                except queue.Empty:
                    break
        
        # Start worker threads
        workers = []
        for _ in range(min(MAX_WORKERS, total_ports)):
            worker = threading.Thread(target=scan_worker)
            worker.start()
            workers.append(worker)
        
        # Wait for all workers to complete
        for worker in workers:
            worker.join()
        
        # Filter open ports and sort by port number
        open_ports = [r for r in scan_results if r.status]
        open_ports.sort(key=lambda x: x.port)
        
        self.logger.info(f"Port scan completed. Found {len(open_ports)} open ports")
        
        return open_ports
    
    def _scan_single_port(self, host: str, port: int, timeout: int) -> ScanResult:
        """Scan a single port"""
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Try to connect
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000
            
            # Determine service based on port
            service = self._get_service_name(port)
            
            scan_result = ScanResult(
                host=host,
                port=port,
                status=result == 0,
                service=service,
                response_time=response_time
            )
            
            sock.close()
            return scan_result
            
        except socket.timeout:
            return ScanResult(host=host, port=port, status=False, response_time=timeout*1000)
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            return ScanResult(host=host, port=port, status=False, response_time=0.0)
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port"""
        common_services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
            143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
            465: "SMTPS", 587: "SMTP", 631: "IPP", 993: "IMAPS",
            995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
            1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB", 28017: "MongoDB HTTP"
        }
        return common_services.get(port, "Unknown")
    
    def monitor_bandwidth(self, interface: str = None, interval: int = 1, duration: int = None):
        """Monitor network bandwidth usage"""
        if not PSUTIL_AVAILABLE:
            self.logger.error("psutil not available. Bandwidth monitoring disabled.")
            return
        
        self.logger.info(f"Starting bandwidth monitoring (interval: {interval}s)")
        self.running = True
        
        stats_history = []
        start_time = time.time()
        
        try:
            while self.running:
                current_time = time.time()
                
                # Check duration limit
                if duration and (current_time - start_time) > duration:
                    self.logger.info("Bandwidth monitoring duration reached")
                    break
                
                # Get network statistics
                try:
                    if interface:
                        # Get stats for specific interface
                        net_io = psutil.net_io_counters(pernic=True).get(interface)
                        if not net_io:
                            self.logger.error(f"Interface {interface} not found")
                            break
                    else:
                        # Get overall stats
                        net_io = psutil.net_io_counters()
                    
                    if net_io:
                        stats = TrafficStats(
                            timestamp=datetime.now(),
                            bytes_sent=net_io.bytes_sent,
                            bytes_recv=net_io.bytes_recv,
                            packets_sent=net_io.packets_sent,
                            packets_recv=net_io.packets_recv,
                            error_in=net_io.errin,
                            error_out=net_io.errout,
                            drop_in=net_io.dropin,
                            drop_out=net_io.dropout
                        )
                        
                        stats_history.append(stats)
                        
                        # Keep only last 100 entries
                        if len(stats_history) > 100:
                            stats_history.pop(0)
                        
                        # Print current stats
                        self._display_bandwidth_stats(stats, interface)
                        
                        # Update graph if matplotlib is available
                        if MATPLOTLIB_AVAILABLE and len(stats_history) > 1:
                            self._update_bandwidth_graph(stats_history)
                
                except Exception as e:
                    self.logger.error(f"Error getting bandwidth stats: {e}")
                
                # Wait for next interval
                time.sleep(interval)
        
        except KeyboardInterrupt:
            self.logger.info("Bandwidth monitoring interrupted")
        finally:
            self.running = False
            if MATPLOTLIB_AVAILABLE:
                plt.ioff()
                plt.show()
    
    def _display_bandwidth_stats(self, stats: TrafficStats, interface: str = None):
        """Display formatted bandwidth statistics"""
        interface_str = f" on {interface}" if interface else ""
        
        # Convert bytes to human-readable format
        def format_bytes(bytes_value):
            for unit in ['B', 'KB', 'MB', 'GB']:
                if bytes_value < 1024.0:
                    return f"{bytes_value:.2f} {unit}"
                bytes_value /= 1024.0
            return f"{bytes_value:.2f} TB"
        
        print(f"\n{'='*60}")
        print(f"Bandwidth Statistics{interface_str} - {stats.timestamp.strftime('%H:%M:%S')}")
        print(f"{'='*60}")
        print(f"Sent:      {format_bytes(stats.bytes_sent):>15}")
        print(f"Received:  {format_bytes(stats.bytes_recv):>15}")
        print(f"Packets:   {stats.packets_sent:>7} sent, {stats.packets_recv:>7} received")
        print(f"Errors:    {stats.error_in:>7} in,    {stats.error_out:>7} out")
        print(f"Drops:     {stats.drop_in:>7} in,    {stats.drop_out:>7} out")
        print(f"{'='*60}")
    
    def _update_bandwidth_graph(self, stats_history: List[TrafficStats]):
        """Update real-time bandwidth graph"""
        if not MATPLOTLIB_AVAILABLE or len(stats_history) < 2:
            return
        
        try:
            # Clear previous plot
            plt.clf()
            
            # Prepare data
            timestamps = [s.timestamp for s in stats_history]
            sent_data = [s.bytes_sent for s in stats_history]
            recv_data = [s.bytes_recv for s in stats_history]
            
            # Calculate rates (bytes per second)
            sent_rate = []
            recv_rate = []
            for i in range(1, len(stats_history)):
                time_diff = (stats_history[i].timestamp - stats_history[i-1].timestamp).total_seconds()
                if time_diff > 0:
                    sent_rate.append((stats_history[i].bytes_sent - stats_history[i-1].bytes_sent) / time_diff)
                    recv_rate.append((stats_history[i].bytes_recv - stats_history[i-1].bytes_recv) / time_diff)
            
            # Create subplots
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
            
            # Plot 1: Total bytes
            ax1.plot(timestamps, sent_data, 'b-', label='Bytes Sent', linewidth=2)
            ax1.plot(timestamps, recv_data, 'g-', label='Bytes Received', linewidth=2)
            ax1.set_xlabel('Time')
            ax1.set_ylabel('Bytes')
            ax1.set_title('Network Traffic - Total Bytes')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot 2: Transfer rate
            if sent_rate and recv_rate:
                rate_timestamps = timestamps[1:]
                ax2.plot(rate_timestamps, sent_rate, 'b-', label='Send Rate', linewidth=2)
                ax2.plot(rate_timestamps, recv_rate, 'g-', label='Receive Rate', linewidth=2)
                ax2.set_xlabel('Time')
                ax2.set_ylabel('Bytes/Second')
                ax2.set_title('Network Traffic - Transfer Rate')
                ax2.legend()
                ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.pause(0.01)
            
        except Exception as e:
            self.logger.error(f"Error updating graph: {e}")
    
    def analyze_traffic(self, packet_count: int = 100, 
                       filter_protocol: str = None,
                       src_ip: str = None,
                       dst_ip: str = None,
                       interface: str = None):
        """Analyze network traffic with packet capture"""
        if not SCAPY_AVAILABLE:
            self.logger.error("scapy not available. Traffic analysis disabled.")
            return
        
        self.logger.info(f"Starting traffic analysis (count: {packet_count})")
        
        protocol_map = {
            'tcp': 6,
            'udp': 17,
            'icmp': 1,
            'http': 80,
            'https': 443
        }
        
        def packet_callback(packet):
            """Callback for processing captured packets"""
            try:
                if IP in packet:
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    proto = packet[IP].proto
                    
                    # Apply filters
                    if filter_protocol:
                        proto_num = protocol_map.get(filter_protocol.lower(), filter_protocol)
                        if str(proto) != str(proto_num):
                            return
                    
                    if src_ip and ip_src != src_ip:
                        return
                    
                    if dst_ip and ip_dst != dst_ip:
                        return
                    
                    # Extract packet information
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'source': ip_src,
                        'destination': ip_dst,
                        'protocol': proto,
                        'size': len(packet),
                        'summary': packet.summary()
                    }
                    
                    # Add protocol-specific details
                    if TCP in packet:
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                        packet_info['flags'] = str(packet[TCP].flags)
                    
                    elif UDP in packet:
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport
                    
                    elif ICMP in packet:
                        packet_info['type'] = packet[ICMP].type
                        packet_info['code'] = packet[ICMP].code
                    
                    # Display packet info
                    self._display_packet_info(packet_info)
                    
                    # Add to packet queue for statistics
                    self.packet_queue.put(packet_info)
                    
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        
        try:
            # Start packet capture
            sniff(
                prn=packet_callback,
                count=packet_count,
                store=False,
                iface=interface
            )
            
            # Generate traffic report
            self._generate_traffic_report()
            
        except Exception as e:
            self.logger.error(f"Error capturing traffic: {e}")
    
    def _display_packet_info(self, packet_info: Dict):
        """Display formatted packet information"""
        protocol_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        proto = packet_info.get('protocol', 0)
        proto_name = protocol_names.get(proto, f'IP/{proto}')
        
        print(f"{packet_info['timestamp'][11:19]} | "
              f"{packet_info['source']:15} → {packet_info['destination']:15} | "
              f"{proto_name:6} | "
              f"{packet_info.get('src_port', ''):5} → {packet_info.get('dst_port', ''):5} | "
              f"{packet_info['size']:5} bytes")
    
    def _generate_traffic_report(self):
        """Generate traffic analysis report"""
        if self.packet_queue.empty():
            print("\nNo packets captured.")
            return
        
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        
        # Analyze packet statistics
        total_packets = len(packets)
        total_bytes = sum(p['size'] for p in packets)
        
        # Count by protocol
        protocol_counts = {}
        for packet in packets:
            proto = packet.get('protocol', 'Unknown')
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        # Count by source IP
        source_counts = {}
        for packet in packets:
            src = packet.get('source', 'Unknown')
            source_counts[src] = source_counts.get(src, 0) + 1
        
        # Generate report
        print(f"\n{'='*60}")
        print(f"TRAFFIC ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"Total Packets: {total_packets}")
        print(f"Total Bytes: {total_bytes:,}")
        print(f"Average Packet Size: {total_bytes/total_packets:.2f} bytes")
        print(f"\nProtocol Distribution:")
        
        for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets) * 100
            print(f"  {proto:10}: {count:5} packets ({percentage:.1f}%)")
        
        print(f"\nTop Sources:")
        for src, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / total_packets) * 100
            print(f"  {src:15}: {count:5} packets ({percentage:.1f}%)")
        
        print(f"{'='*60}")
        
        # Save report to file
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'protocol_distribution': protocol_counts,
            'top_sources': dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        }
        
        report_file = f"traffic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Traffic report saved to {report_file}")

class CommandLineInterface:
    """Enhanced command-line interface with better argument handling"""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Enhanced Network Monitoring Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s monitor google.com 8.8.8.8 --interval 10 --duration 300
  %(prog)s scan 192.168.1.1 --ports 1-1000,3389,8080-8090
  %(prog)s bandwidth --interface eth0 --interval 2 --duration 60
  %(prog)s traffic --count 500 --protocol tcp --src 192.168.1.100
            """
        )
        
        self.subparsers = self.parser.add_subparsers(dest='command', help='Command to execute')
        self._setup_parsers()
    
    def _setup_parsers(self):
        """Setup all command parsers"""
        # Monitor command
        monitor_parser = self.subparsers.add_parser('monitor', help='Monitor host availability')
        monitor_parser.add_argument('hosts', nargs='+', help='Hosts to monitor')
        monitor_parser.add_argument('--interval', '-i', type=int, default=5,
                                  help='Interval between checks (seconds)')
        monitor_parser.add_argument('--duration', '-d', type=int,
                                  help='Duration to monitor (seconds)')
        monitor_parser.add_argument('--timeout', '-t', type=int, default=2,
                                  help='Ping timeout (seconds)')
        
        # Scan command
        scan_parser = self.subparsers.add_parser('scan', help='Scan ports on a host')
        scan_parser.add_argument('host', help='Target host')
        scan_parser.add_argument('--ports', '-p', default='1-1024',
                               help='Ports to scan (e.g., 1-1000,80,443,8080-8090)')
        scan_parser.add_argument('--timeout', '-t', type=float, default=1.0,
                               help='Connection timeout per port (seconds)')
        scan_parser.add_argument('--workers', '-w', type=int, default=MAX_WORKERS,
                               help='Number of worker threads')
        
        # Bandwidth command
        bandwidth_parser = self.subparsers.add_parser('bandwidth', help='Monitor bandwidth usage')
        bandwidth_parser.add_argument('--interface', '-i',
                                    help='Network interface to monitor')
        bandwidth_parser.add_argument('--interval', type=float, default=1.0,
                                    help='Update interval (seconds)')
        bandwidth_parser.add_argument('--duration', '-d', type=int,
                                    help='Duration to monitor (seconds)')
        bandwidth_parser.add_argument('--graph', '-g', action='store_true',
                                    help='Display real-time graph')
        
        # Traffic command
        traffic_parser = self.subparsers.add_parser('traffic', help='Analyze network traffic')
        traffic_parser.add_argument('--count', '-c', type=int, default=100,
                                  help='Number of packets to capture')
        traffic_parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp', 'http', 'https'],
                                  help='Filter by protocol')
        traffic_parser.add_argument('--src', help='Filter by source IP')
        traffic_parser.add_argument('--dst', help='Filter by destination IP')
        traffic_parser.add_argument('--interface', '-i',
                                  help='Network interface to capture from')
        traffic_parser.add_argument('--output', '-o',
                                  help='Output file for captured packets')
        
        # Config command
        config_parser = self.subparsers.add_parser('config', help='Manage configuration')
        config_parser.add_argument('--show', action='store_true', help='Show current configuration')
        config_parser.add_argument('--reset', action='store_true', help='Reset to default configuration')
        
        # Info command
        self.subparsers.add_parser('info', help='Show system and network information')
    
    def parse_args(self):
        """Parse command line arguments"""
        return self.parser.parse_args()
    
    def display_info(self):
        """Display system and network information"""
        print(f"\n{'='*60}")
        print(f"SYSTEM INFORMATION")
        print(f"{'='*60}")
        print(f"Platform: {platform.platform()}")
        print(f"Python: {platform.python_version()}")
        print(f"Hostname: {socket.gethostname()}")
        
        # Network interfaces
        if PSUTIL_AVAILABLE:
            print(f"\nNetwork Interfaces:")
            try:
                interfaces = psutil.net_if_addrs()
                for interface, addresses in interfaces.items():
                    print(f"  {interface}:")
                    for addr in addresses:
                        if addr.family == socket.AF_INET:
                            print(f"    IPv4: {addr.address}")
                        elif addr.family == socket.AF_INET6:
                            print(f"    IPv6: {addr.address}")
            except Exception as e:
                print(f"  Error getting interface info: {e}")
        
        # Dependencies status
        print(f"\nDependencies:")
        print(f"  psutil: {'✓' if PSUTIL_AVAILABLE else '✗'}")
        print(f"  scapy: {'✓' if SCAPY_AVAILABLE else '✗'}")
        print(f"  matplotlib: {'✓' if MATPLOTLIB_AVAILABLE else '✗'}")
        print(f"{'='*60}")

def parse_port_ranges(port_spec: str) -> List[Tuple[int, int]]:
    """Parse port specification string into ranges"""
    ranges = []
    
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            try:
                start = int(start_str)
                end = int(end_str)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ranges.append((start, end))
                else:
                    print(f"Warning: Invalid port range {part}")
            except ValueError:
                print(f"Warning: Invalid port range format {part}")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ranges.append((port, port))
                else:
                    print(f"Warning: Invalid port {part}")
            except ValueError:
                print(f"Warning: Invalid port {part}")
    
    return ranges

def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║        ENHANCED NETWORK MONITORING TOOL v2.0.0           ║
║              Production-Ready Deployment                 ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Initialize components
        cli = CommandLineInterface()
        args = cli.parse_args()
        
        # Handle config command first
        if args.command == 'config':
            if args.reset:
                config = ConfigManager()
                print("Configuration reset to defaults")
            elif args.show:
                config = ConfigManager()
                for section in config.config.sections():
                    print(f"\n[{section}]")
                    for key, value in config.config.items(section):
                        print(f"{key} = {value}")
            return
        
        # Handle info command
        if args.command == 'info':
            cli.display_info()
            return
        
        # Check if command is provided
        if not args.command:
            cli.parser.print_help()
            return
        
        # Initialize configuration and monitor
        config = ConfigManager()
        monitor = NetworkMonitor(config)
        
        # Execute command
        if args.command == 'monitor':
            monitor.monitor_hosts(
                hosts=args.hosts,
                interval=args.interval,
                duration=args.duration
            )
            
        elif args.command == 'scan':
            port_ranges = parse_port_ranges(args.ports)
            if not port_ranges:
                print("Error: No valid ports specified")
                return
            
            # Set max workers
            os.environ['MAX_WORKERS'] = str(args.workers)
            
            print(f"\nStarting port scan on {args.host}")
            print(f"Port ranges: {args.ports}")
            print(f"Workers: {args.workers}")
            print(f"Timeout: {args.timeout}s")
            print("-" * 50)
            
            results = monitor.scan_ports(args.host, port_ranges, args.timeout)
            
            # Display results
            if results:
                print(f"\nOPEN PORTS on {args.host}:")
                print("-" * 50)
                for result in results:
                    print(f"  Port {result.port:5} - {result.service:15} "
                          f"({result.response_time:.2f}ms)")
                print(f"\nTotal: {len(results)} open ports found")
            else:
                print(f"\nNo open ports found on {args.host}")
            
            # Save results to file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            results_file = f"scan_{args.host}_{timestamp}.txt"
            with open(results_file, 'w') as f:
                f.write(f"Port Scan Results - {datetime.now()}\n")
                f.write(f"Target: {args.host}\n")
                f.write(f"Ports: {args.ports}\n")
                f.write(f"Scan duration: {datetime.now()}\n")
                f.write("-" * 50 + "\n")
                for result in results:
                    f.write(f"Port {result.port}: {result.service}\n")
            
            print(f"\nResults saved to: {results_file}")
            
        elif args.command == 'bandwidth':
            if not PSUTIL_AVAILABLE:
                print("Error: psutil is required for bandwidth monitoring")
                print("Install with: pip install psutil")
                return
            
            if args.graph and not MATPLOTLIB_AVAILABLE:
                print("Warning: matplotlib not available. Graph disabled.")
                args.graph = False
            
            # Initialize matplotlib if needed
            if args.graph:
                plt.ion()
                plt.figure(figsize=(12, 8))
            
            monitor.monitor_bandwidth(
                interface=args.interface,
                interval=args.interval,
                duration=args.duration
            )
            
        elif args.command == 'traffic':
            if not SCAPY_AVAILABLE:
                print("Error: scapy is required for traffic analysis")
                print("Install with: pip install scapy")
                return
            
            # Check for root/admin privileges
            if os.name == 'posix' and os.geteuid() != 0:
                print("Warning: Traffic capture may require root privileges")
                print("Consider running with: sudo python network_monitor.py traffic")
            
            monitor.analyze_traffic(
                packet_count=args.count,
                filter_protocol=args.protocol,
                src_ip=args.src,
                dst_ip=args.dst,
                interface=args.interface
            )
        
        else:
            cli.parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
    
    except Exception as e:
        print(f"\nError: {e}")
        logging.error(f"Main execution error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
