# Network_Monitor.py
# pip install platform subprocess time psutil scapy matplotlib

import os
import platform
import subprocess
import time
import socket # Above imports For system interactions and network communications.
import psutil # To monitor system and network resources.
from scapy.all import sniff # For packet manipulation and analysis.
import argparse # For command-line argument parsing.
import logging # To log events and errors.
import configparser # For reading configuration files.
import matplotlib.pyplot as plt # For visualizing bandwidth data.

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

def ping(host):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        return subprocess.call(command) == 0
    except Exception as e:
        logging.error(f"Error pinging {host}: {e}")
        return False

def monitor_hosts(hosts, interval=5):
    while True:
        for host in hosts:
            try:
                if ping(host):
                    print(f"{host} is reachable")
                    logging.info(f"{host} is reachable")
                else:
                    print(f"{host} is not reachable")
                    logging.warning(f"{host} is not reachable")
            except Exception as e:
                logging.error(f"Error monitoring {host}: {e}")
        time.sleep(interval)

def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            logging.error(f"Error scanning port {port} on {host}: {e}")
    return open_ports

def monitor_bandwidth(interval=1):
    sent_data = []
    recv_data = []
    timestamps = []

    plt.ion()  # Turn on interactive mode
    while True:
        try:
            net_io = psutil.net_io_counters()
            sent_data.append(net_io.bytes_sent)
            recv_data.append(net_io.bytes_recv)
            timestamps.append(time.time())

            print(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")
            logging.info(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")

            plt.plot(timestamps, sent_data, label='Bytes Sent', color='blue')
            plt.plot(timestamps, recv_data, label='Bytes Received', color='orange')
            plt.xlabel('Time')
            plt.ylabel('Bytes')
            plt.legend()
            plt.pause(0.1)

            time.sleep(interval)
        except Exception as e:
            logging.error(f"Error monitoring bandwidth: {e}")

def packet_callback(packet):
    try:
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            protocol = packet['IP'].proto
            print(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")
            logging.info(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def analyze_traffic(packet_count=10, filter_protocol=None, src_ip=None, dst_ip=None):
    def custom_packet_callback(packet):
        try:
            if filter_protocol and packet.haslayer('IP') and packet['IP'].proto != filter_protocol:
                return
            if src_ip and packet.haslayer('IP') and packet['IP'].src != src_ip:
                return
            if dst_ip and packet.haslayer('IP') and packet['IP'].dst != dst_ip:
                return
            packet_callback(packet)
        except Exception as e:
            logging.error(f"Error in custom packet callback: {e}")

    try:
        sniff(prn=custom_packet_callback, count=packet_count)
    except Exception as e:
        logging.error(f"Error analyzing traffic: {e}")

def main():
    parser = argparse.ArgumentParser(description="Network Monitoring Tool")
    subparsers = parser.add_subparsers(dest='command')

    ping_parser = subparsers.add_parser('ping', help='Monitor hosts via ping')
    ping_parser.add_argument('hosts', nargs='+', help='List of hosts to ping')
    ping_parser.add_argument('--interval', type=int, default=5, help='Time interval between pings')

    scan_parser = subparsers.add_parser('scan', help='Scan ports on a host')
    scan_parser.add_argument('host', help='Target host to scan')
    scan_parser.add_argument('--start', type=int, default=1, help='Start port')
    scan_parser.add_argument('--end', type=int, default=1024, help='End port')

    bandwidth_parser = subparsers.add_parser('bandwidth', help='Monitor network bandwidth')
    bandwidth_parser.add_argument('--interval', type=int, default=1, help='Time interval between reports')

    traffic_parser = subparsers.add_parser('traffic', help='Analyze network traffic')
    traffic_parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    traffic_parser.add_argument('--protocol', type=int, help='Filter by protocol (IP proto number)')
    traffic_parser.add_argument('--src', type=str, help='Source IP to filter')
    traffic_parser.add_argument('--dst', type=str, help='Destination IP to filter')

    args = parser.parse_args()

    if args.command == 'ping':
        monitor_hosts(args.hosts, args.interval)
    elif args.command == 'scan':
        print(f"Scanning ports on {args.host}...")
        open_ports = scan_ports(args.host, args.start, args.end)
        print("Open ports:", open_ports)
        logging.info(f"Open ports on {args.host}: {open_ports}")
    elif args.command == 'bandwidth':
        print("Monitoring bandwidth...")
        monitor_bandwidth(args.interval)
    elif args.command == 'traffic':
        analyze_traffic(args.count, args.protocol, args.src, args.dst)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
''' 
    Functions:
        ping(host): Pings a specified host to check its reachability.
        monitor_hosts(hosts, interval): Continuously pings a list of hosts at specified intervals and logs their status.
        scan_ports(host, start_port, end_port): Scans a range of ports on a specified host to identify open ports.
        monitor_bandwidth(interval): Monitors and logs the amount of data sent and received over the network, updating a live plot.
        packet_callback(packet): Processes captured packets, logging their source, destination, and protocol.
        analyze_traffic(packet_count, filter_protocol, src_ip, dst_ip): Captures and analyzes network traffic based on specified filters.

    Main Functionality:
        Uses argparse to allow users to run commands for pinging, port scanning, bandwidth monitoring, or traffic analysis from the command line.
        Logs all relevant actions and errors to a file (network_monitor.log).

Applications in Monitoring Protocols
    Host Monitoring: Regularly checks the availability of network devices, which is crucial for ensuring network reliability.
    Port Scanning: Identifies open ports that may be vulnerable or need to be secured, helping in network security assessments.
    Bandwidth Monitoring: Visualizes data usage over time, which can help in detecting unusual patterns that may indicate issues or breaches.
    Traffic Analysis: Captures and analyzes packets, allowing for detailed examination of network traffic for security and performance tuning.

Conclusion
This tool is valuable for network administrators and security professionals for maintaining the health and security of their networks. 
It automates common monitoring tasks and provides insights into network performance and security posture.

Step-by-Step Deployment

    Clone or Download the Code:
        Save the provided code into a file named network_monitor.py.

    Install Required Libraries:
    Open a terminal and run:
    bash
    
Create a Configuration File:

    Create a file named config.ini in the same directory as network_monitor.py. This can include any necessary configuration settings.

Set Up Logging:

    Ensure the log file path in the code (network_monitor.log) is writable by your user.

Run the Tool using the following commands:
    To ping hosts:
    bash

python network_monitor.py ping 192.168.1.1 192.168.1.2 --interval 10

To scan ports on a host:
bash

python network_monitor.py scan 192.168.1.1 --start 1 --end 1024

To monitor bandwidth:
bash

python network_monitor.py bandwidth --interval 5

To analyze traffic:
bash

    python network_monitor.py traffic --count 50 --src 192.168.1.1

Notes

    Make sure to run the script with appropriate permissions, especially for packet capturing (may require root/administrator access).
    Adjust the config.ini as needed for specific configurations.
    Monitor the network_monitor.log file for logs and errors during execution.
'''
# ===================================================================================================================================================

import os
import platform
import subprocess
import time
import socket
import psutil
from scapy.all import sniff
import argparse
import logging
import configparser
import matplotlib.pyplot as plt

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

def ping(host):
    """Ping a host to check its reachability."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    return subprocess.call(command) == 0

def monitor_hosts(hosts, interval=5):
    """Monitor hosts by pinging them at specified intervals."""
    while True:
        for host in hosts:
            reachable = ping(host)
            status = "reachable" if reachable else "not reachable"
            print(f"{host} is {status}")
            logging.info(f"{host} is {status}")
        time.sleep(interval)

def scan_ports(host, start_port, end_port):
    """Scan a range of ports on a host to identify open ports."""
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports

def monitor_bandwidth(interval=1):
    """Monitor and visualize network bandwidth usage."""
    sent_data, recv_data, timestamps = [], [], []
    plt.ion()  # Turn on interactive mode

    while True:
        net_io = psutil.net_io_counters()
        sent_data.append(net_io.bytes_sent)
        recv_data.append(net_io.bytes_recv)
        timestamps.append(time.time())

        print(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")
        logging.info(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")

        plt.clf()  # Clear the previous plot
        plt.plot(timestamps, sent_data, label='Bytes Sent', color='blue')
        plt.plot(timestamps, recv_data, label='Bytes Received', color='orange')
        plt.xlabel('Time')
        plt.ylabel('Bytes')
        plt.legend()
        plt.pause(0.1)

        time.sleep(interval)

def packet_callback(packet):
    """Process and log captured packets."""
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        protocol = packet['IP'].proto
        print(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")
        logging.info(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

def analyze_traffic(packet_count=10, filter_protocol=None, src_ip=None, dst_ip=None):
    """Capture and analyze network traffic with optional filtering."""
    def custom_packet_callback(packet):
        if filter_protocol and packet.haslayer('IP') and packet['IP'].proto != filter_protocol:
            return
        if src_ip and packet.haslayer('IP') and packet['IP'].src != src_ip:
            return
        if dst_ip and packet.haslayer('IP') and packet['IP'].dst != dst_ip:
            return
        packet_callback(packet)

    sniff(prn=custom_packet_callback, count=packet_count)

def main():
    """Main entry point for the network monitoring tool."""
    parser = argparse.ArgumentParser(description="Network Monitoring Tool")
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for pinging hosts
    ping_parser = subparsers.add_parser('ping', help='Monitor hosts via ping')
    ping_parser.add_argument('hosts', nargs='+', help='List of hosts to ping')
    ping_parser.add_argument('--interval', type=int, default=5, help='Time interval between pings')

    # Subparser for port scanning
    scan_parser = subparsers.add_parser('scan', help='Scan ports on a host')
    scan_parser.add_argument('host', help='Target host to scan')
    scan_parser.add_argument('--start', type=int, default=1, help='Start port')
    scan_parser.add_argument('--end', type=int, default=1024, help='End port')

    # Subparser for bandwidth monitoring
    bandwidth_parser = subparsers.add_parser('bandwidth', help='Monitor network bandwidth')
    bandwidth_parser.add_argument('--interval', type=int, default=1, help='Time interval between reports')

    # Subparser for traffic analysis
    traffic_parser = subparsers.add_parser('traffic', help='Analyze network traffic')
    traffic_parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    traffic_parser.add_argument('--protocol', type=int, help='Filter by protocol (IP proto number)')
    traffic_parser.add_argument('--src', type=str, help='Source IP to filter')
    traffic_parser.add_argument('--dst', type=str, help='Destination IP to filter')

    args = parser.parse_args()

    command_map = {
        'ping': lambda: monitor_hosts(args.hosts, args.interval),
        'scan': lambda: print("Open ports:", scan_ports(args.host, args.start, args.end)),
        'bandwidth': lambda: monitor_bandwidth(args.interval),
        'traffic': lambda: analyze_traffic(args.count, args.protocol, args.src, args.dst)
    }

    command_map.get(args.command, parser.print_help)()

if __name__ == "__main__":
    main()
""" 
Install Required Libraries:
Open a terminal and run:
bash

pip install psutil scapy matplotlib

Create a Configuration File:

    Create a file named config.ini in the same directory as network_monitor.py. This can include any necessary configuration settings.

Set Up Logging:

    Ensure the log file path in the code (network_monitor1.log) is writable by your user.

Run the Tool:
You can run the tool with different commands:

    To ping hosts:
    bash

python network_monitor.py ping 192.168.1.1 192.168.1.2 --interval 10

To scan ports on a host:
bash

python network_monitor.py scan 192.168.1.1 --start 1 --end 1024

To monitor bandwidth:
bash

python network_monitor.py bandwidth --interval 5

To analyze traffic:
bash

python network_monitor.py traffic --count 50 --src 192.168.1.1

If vulnerabilities such as open ports and poor network performance are noticed, take the following actions:
Addressing Open Ports

    Identify Purpose:
        Determine the necessity of each open port. Assess whether the services running are required.

    Implement Firewalls:
        Use firewalls to restrict access to open ports. Only allow connections from trusted IP addresses.

    Close Unused Ports:
        Disable or close any unnecessary open ports to reduce attack vectors.

    Change Default Settings:
        Change default port numbers for services if applicable to obscure them from automated scans.

    Regular Audits:
        Conduct regular network audits to identify and manage open ports and services.

Managing Poor Network Performance

    Bandwidth Monitoring:
        Continuously monitor bandwidth usage to identify spikes and patterns that may indicate issues.

    Optimize Network Configuration:
        Review and optimize router and switch configurations for better performance.

    Quality of Service (QoS):
        Implement QoS policies to prioritize critical traffic and manage bandwidth more effectively.

    Upgrade Infrastructure:
        If performance issues persist, consider upgrading network hardware (routers, switches) or increasing bandwidth.

    Analyze Traffic:
        Use traffic analysis tools to identify bottlenecks, unusual traffic patterns, or potential intrusions.

    Check for Malware:
        Scan the network for malware or unauthorized devices that may be consuming resources.

    User Education:
        Educate users about best practices for network usage to minimize unnecessary load.

Incident Response Plan

    Document Findings:
        Keep detailed records of vulnerabilities identified and actions taken.

    Inform Stakeholders:
        Notify relevant stakeholders about vulnerabilities and planned remediation steps.

    Develop a Remediation Plan:
        Create a structured plan for addressing identified vulnerabilities, including timelines and resources needed.

    Test Changes:
        After implementing changes, test to ensure that vulnerabilities are effectively mitigated without impacting normal operations.

    Review Policies:
        Update security policies and procedures based on lessons learned from vulnerabilities encountered.

By following these actions, you can effectively manage vulnerabilities and improve the overall security and performance of your network.
"""
# =======================================================================================================================================================

''' Inside CLI
mkdir NetworkManagementScript.py
cd NetworkManagementScript.py
code .
python -m venv myenv
source myenv/bin/activate  # On Windows use: myenv\Scripts\activate
pip install paramiko ping3


This following script will:

    Ping devices to check their availability.
    Connect to devices via SSH.
    Execute commands to gather information (e.g., uptime, interfaces).
'''

import paramiko
from ping3 import ping, verbose_ping

# List of devices to manage
devices = [
    {
        'hostname': '192.168.1.1',
        'username': 'admin',
        'password': 'password123'
    },
    {
        'hostname': '192.168.1.2',
        'username': 'admin',
        'password': 'password123'
    }
]

def check_device_availability(hostname):
    response = ping(hostname)
    if response is not None:
        print(f"{hostname} is reachable (Response time: {response} ms)")
        return True
    else:
        print(f"{hostname} is not reachable.")
        return False

def execute_command(hostname, username, password, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)

        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        errors = stderr.read().decode()

        if output:
            print(f"Output from {hostname}:\n{output}")
        if errors:
            print(f"Errors from {hostname}:\n{errors}")

        client.close()
    except Exception as e:
        print(f"Failed to connect to {hostname}: {e}")

def main():
    command_to_execute = 'uptime'  # Example command to check system uptime

    for device in devices:
        hostname = device['hostname']
        if check_device_availability(hostname):
            execute_command(hostname, device['username'], device['password'], command_to_execute)

if __name__ == '__main__':
    main()
""" 
CLI Executions on windows and linux
python NetworkManagementScript.py

Explanation of the Script

    Device List:
        Contains a list of devices with their IP addresses, usernames, and passwords.

    Check Device Availability:
        The check_device_availability function uses ping to check if the device is reachable.

    Execute Command:
        The execute_command function establishes an SSH connection to the device using paramiko, executes the specified command, and prints the output.

    Main Function:
        Iterates through the devices, checks their availability, and executes a predefined command (uptime).

Usage

    Replace the IP addresses, usernames, and passwords in the devices list with those of your actual network devices.
    Modify the command_to_execute variable to execute other commands as needed.
    Run the script, and it will check each device's availability and execute the specified command.

Important Note

    Ensure that the devices you are connecting to have SSH enabled and that the credentials used have the necessary permissions.
    Always use caution when executing commands on network devices, especially in production environments.
"""
# ---------------------------------------------------------------------------------------------------------------------------------------------
# Script2
# pip install psutil scapy matplotlib
import os
import platform
import subprocess
import time
import socket
import psutil
from scapy.all import sniff
import argparse
import logging
import configparser
import matplotlib.pyplot as plt

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

''' The application reads from config.ini for default settings, allowing users to change the configuration without modifying the code.
Create a config.ini file in the same directory as your script with the following script, substitute hosts with your own:

[DEFAULT]
ping_hosts = 192.168.1.1, 192.168.1.2
bandwidth_interval = 1
packet_count = 10
filter_protocol = None
src_ip = None
dst_ip = None
'''

# Function to ping hosts
def ping(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        return subprocess.call(command) == 0
    except Exception as e:
        logging.error(f"Error pinging {host}: {e}")
        return False

def monitor_hosts(hosts, interval=5):
    while True:
        for host in hosts:
            if ping(host):
                print(f"{host} is reachable")
                logging.info(f"{host} is reachable")
            else:
                print(f"{host} is not reachable")
                logging.warning(f"{host} is not reachable")
        time.sleep(interval)

# Function to scan ports
def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            logging.error(f"Error scanning port {port} on {host}: {e}")
    return open_ports

# Function to monitor bandwidth
def monitor_bandwidth(interval=1):
    sent_data = []
    recv_data = []
    timestamps = []

    while True:
        net_io = psutil.net_io_counters()
        sent_data.append(net_io.bytes_sent)
        recv_data.append(net_io.bytes_recv)
        timestamps.append(time.time())

        print(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")
        logging.info(f"Bytes sent: {net_io.bytes_sent}, Bytes received: {net_io.bytes_recv}")

        time.sleep(interval)

        # Plot the bandwidth data
        plt.plot(timestamps, sent_data, label='Bytes Sent', color='blue')
        plt.plot(timestamps, recv_data, label='Bytes Received', color='orange')
        plt.xlabel('Time')
        plt.ylabel('Bytes')
        plt.legend()
        plt.pause(0.1)

# Function for network traffic analysis
# def packet_callback(packet):
#     print(packet.summary())
#     logging.info(f"Packet captured: {packet.summary()}")

# def analyze_traffic(packet_count=10):
#     sniff(prn=packet_callback, count=packet_count)

def packet_callback(packet):
    # Filter by IP protocol and log details
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        protocol = packet['IP'].proto
        print(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")
        logging.info(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

def analyze_traffic(packet_count=10, filter_protocol=None, src_ip=None, dst_ip=None):
    def custom_packet_callback(packet):
        # Apply filters
        if filter_protocol and packet.haslayer('IP') and packet['IP'].proto != filter_protocol:
            return
        if src_ip and packet.haslayer('IP') and packet['IP'].src != src_ip:
            return
        if dst_ip and packet.haslayer('IP') and packet['IP'].dst != dst_ip:
            return
        packet_callback(packet)

    sniff(prn=custom_packet_callback, count=packet_count)

# Main function to handle CLI
def main():
    parser = argparse.ArgumentParser(description="Network Monitoring Tool")
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for ping monitoring
    ping_parser = subparsers.add_parser('ping', help='Monitor hosts via ping')
    ping_parser.add_argument('hosts', nargs='+', help='List of hosts to ping')
    ping_parser.add_argument('--interval', type=int, default=5, help='Time interval between pings')

    # Subparser for port scanning
    scan_parser = subparsers.add_parser('scan', help='Scan ports on a host')
    scan_parser.add_argument('host', help='Target host to scan')
    scan_parser.add_argument('--start', type=int, default=1, help='Start port')
    scan_parser.add_argument('--end', type=int, default=1024, help='End port')

    # Subparser for bandwidth monitoring
    bandwidth_parser = subparsers.add_parser('bandwidth', help='Monitor network bandwidth')
    bandwidth_parser.add_argument('--interval', type=int, default=1, help='Time interval between reports')

    # Subparser for traffic analysis
    # traffic_parser = subparsers.add_parser('traffic', help='Analyze network traffic')
    # traffic_parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')

    # args = parser.parse_args()
    traffic_parser = subparsers.add_parser('traffic', help='Analyze network traffic')
    traffic_parser.add_argument('--count', type=int, default=config.getint('DEFAULT', 'packet_count'), help='Number of packets to capture')
    traffic_parser.add_argument('--protocol', type=int, default=config.getint('DEFAULT', 'filter_protocol'), help='Filter by protocol (IP proto number)')
    traffic_parser.add_argument('--src', type=str, default=config.get('DEFAULT', 'src_ip'), help='Source IP to filter')
    traffic_parser.add_argument('--dst', type=str, default=config.get('DEFAULT', 'dst_ip'), help='Destination IP to filter')

    if args.command == 'ping':
        monitor_hosts(args.hosts, args.interval)
    elif args.command == 'scan':
        print(f"Scanning ports on {args.host}...")
        open_ports = scan_ports(args.host, args.start, args.end)
        print("Open ports:", open_ports)
        logging.info(f"Open ports on {args.host}: {open_ports}")
    elif args.command == 'bandwidth':
        print("Monitoring bandwidth...")
        plt.ion()  # Turn on interactive mode
        monitor_bandwidth(args.interval)
    elif args.command == 'traffic':
        analyze_traffic(args.count)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
''' 
How to Use the Application/script on a terminal

    Ping Monitoring:
    bash
python network_monitor.py ping 192.168.1.1 192.168.1.2 --interval 5

Port Scanning:
bash
python network_monitor.py scan 192.168.1.1 --start 1 --end 1024

Bandwidth Monitoring:
bash
python network_monitor.py bandwidth --interval 1

Network Traffic Analysis:
bash
python network_monitor.py traffic --count 10
'''
# Create a file called test_network_monitor.py with the following:
# pip install pytest

import unittest
from unittest.mock import patch
import network_monitor  # Assuming your main script is named network_monitor.py

class TestNetworkMonitor(unittest.TestCase):

    @patch('network_monitor.ping')
    def test_ping_success(self, mock_ping):
        mock_ping.return_value = True
        self.assertTrue(network_monitor.ping("192.168.1.1"))

    @patch('network_monitor.ping')
    def test_ping_failure(self, mock_ping):
        mock_ping.return_value = False
        self.assertFalse(network_monitor.ping("192.168.1.1"))

    @patch('network_monitor.scan_ports')
    def test_scan_ports(self, mock_scan_ports):
        mock_scan_ports.return_value = [80, 443]
        open_ports = network_monitor.scan_ports("192.168.1.1", 1, 1024)
        self.assertIn(80, open_ports)
        self.assertIn(443, open_ports)

    def test_load_configuration(self):
        config = network_monitor.config
        self.assertEqual(config.get('DEFAULT', 'bandwidth_interval'), '1')

if __name__ == '__main__':
    unittest.main()

''' 
Execute tests using:
bash
pytest test_network_monitor.py
'''
# ============================================================================================================

# 1. Interface Configuration
# Display all network interfaces
ip addr show
ip a

# Show specific interface
ip addr show eth0

# Display interface statistics
ip -s link show eth0

# Traditional ifconfig (deprecated but still used)
ifconfig
ifconfig eth0

# 2. IP Address Management
# Add IP address to interface
ip addr add 192.168.1.100/24 dev eth0

# Remove IP address
ip addr del 192.168.1.100/24 dev eth0

# Flush all IP addresses from interface
ip addr flush dev eth0

# 3. Routing Management
# Display routing table
ip route show
route -n

# Add default gateway
ip route add default via 192.168.1.1

# Add specific route
ip route add 10.0.0.0/8 via 192.168.1.1

# Delete route
ip route del 10.0.0.0/8

# Display routing cache
ip route show cache

# 4. Connectivity Testing
# Basic ping
ping google.com
ping 8.8.8.8

# Ping with specific count
ping -c 4 google.com

# Ping with interval
ping -i 2 google.com

# Ping with size
ping -s 1000 google.com

# 5. Network Path Analysis
# Trace route to destination
traceroute google.com
tracepath google.com

# Modern tracepath
mtr google.com

# Continuous route monitoring
mtr --report google.com

# 6. Port and Service Scanning
# Scan ports on remote host
nmap google.com

# Scan specific port range
nmap -p 1-1000 192.168.1.1

# TCP port scan
nc -zv google.com 80

# UDP port scan
nc -zvu google.com 53

# 7. Network Statistics
# Display network statistics
netstat -tuln          # Listening ports
netstat -tup           # Established connections
netstat -r             # Routing table
netstat -i             # Interface statistics
netstat -s             # Summary statistics

# Modern alternative to netstat
ss -tuln               # Listening ports
ss -tup                # Established connections
ss -s                  # Summary

# 8. Bandwidth Monitoring
# Real-time bandwidth monitoring
iftop
nethogs

# Interface statistics
sar -n DEV 1 5

# Continuous interface monitoring
watch -n 1 'ip -s link'

# Network traffic by process
nethogs eth0

# 9. DNS Diagnostics
# DNS lookup
nslookup google.com
dig google.com
host google.com

# Reverse DNS lookup
dig -x 8.8.8.8

# Query specific DNS server
dig @8.8.8.8 google.com

# DNS troubleshooting
dig google.com ANY

# 10. iptables Management
# Display firewall rules
iptables -L -n -v
iptables -t nat -L -n -v

# Save current rules
iptables-save > /etc/iptables/rules.v4

# Restore rules
iptables-restore < /etc/iptables/rules.v4

# Add rule to allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Block IP address
iptables -A INPUT -s 192.168.1.100 -j DROP

# 11. Firewalld (RHEL/CentOS/Fedora)
# Check firewalld status
systemctl status firewalld
firewall-cmd --state

# List all rules
firewall-cmd --list-all

# Open port
firewall-cmd --add-port=80/tcp --permanent
firewall-cmd --reload

# Add service
firewall-cmd --add-service=http --permanent

# 12. Service Control
# Restart network service (Systemd)
systemctl restart NetworkManager
systemctl restart networking      # Debian/Ubuntu
systemctl restart network         # RHEL/CentOS

# Check service status
systemctl status NetworkManager

# Enable service at boot
systemctl enable NetworkManager

# 13. DHCP Client Management
# Release and renew DHCP lease
dhclient -r eth0      # Release
dhclient eth0         # Renew

# For NetworkManager
nmcli con down eth0
nmcli con up eth0

# 14. Real-time Network Monitoring
# Comprehensive system monitoring
htop

# Network-specific monitoring
nload eth0
bmon

# Packet capture and analysis
tcpdump -i eth0
tcpdump -i eth0 port 80
tcpdump -i eth0 port 443
tcpdump -i eth0 host google.com

# Network quality testing
iperf3 -s                    # Server mode
iperf3 -c server_ip          # Client mode

# HTTP performance testing
curl -o /dev/null -s -w "%{time_total}\n" http://google.com

# Network delay measurement
ping -D google.com

# Scan for WiFi networks
iwlist scan
nmcli dev wifi list

# Connect to WiFi (NetworkManager)
nmcli dev wifi connect "SSID" password "password"

# Show WiFi interface info
iwconfig
iw dev

# Monitor mode
airmon-ng start wlan0

# Network Troubleshooting Scripts
#!/bin/bash
# Network diagnostic script
echo "=== Network Interface Status ==="
ip addr show

echo -e "\n=== Routing Table ==="
ip route show

echo -e "\n=== DNS Configuration ==="
cat /etc/resolv.conf

echo -e "\n=== Listening Ports ==="
ss -tuln

echo -e "\n=== Connectivity Test ==="
ping -c 3 8.8.8.8

# Monitor bandwidth usage
INTERFACE="eth0"

echo "Monitoring bandwidth on $INTERFACE"
echo "Press Ctrl+C to stop"

while true; do
    RX1=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
    TX1=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
    sleep 1
    RX2=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
    TX2=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
    
    RX_RATE=$((($RX2 - $RX1) / 1024))
    TX_RATE=$((($TX2 - $TX1) / 1024))
    
    echo "Download: ${RX_RATE} KB/s | Upload: ${TX_RATE} KB/s"
done

# 15. Important Network Configuration Files
# Network interfaces (Debian/Ubuntu)
cat /etc/network/interfaces

# NetworkManager connections
ls /etc/NetworkManager/system-connections/

# DNS resolvers
cat /etc/resolv.conf

# Hosts file
cat /etc/hosts

# Static routes
cat /etc/sysconfig/network-scripts/route-eth0  # RHEL/CentOS

# 16. Network Testing and Validation
# Test HTTP connectivity
curl -I http://google.com
wget --spider http://google.com

# Test SSL/TLS
openssl s_client -connect google.com:443

# Check MTU
ping -M do -s 1472 google.com  # 1500 - 28 = 1472

# Network latency test
ping -c 10 google.com | grep min/avg/max
