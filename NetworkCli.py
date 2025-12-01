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
