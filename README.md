# Enhanced Network Monitoring Tool

A comprehensive, production-ready network monitoring tool written in Python.

## Features

- **Host Monitoring**: Continuous ping monitoring with real-time statistics
- **Port Scanning**: Fast, concurrent port scanning with service detection
- **Bandwidth Monitoring**: Real-time network usage tracking with graphs
- **Traffic Analysis**: Packet capture and analysis with filtering
- **Scheduled Tasks**: Automated monitoring with configurable schedules
- **Multiple Outputs**: JSON, CSV, HTML reports and real-time console display
- **Alerting**: Configurable notifications via email, Slack, webhooks
- **Metrics Export**: Prometheus metrics endpoint for integration

# Architecture
┌─────────────────────────────────────────────────┐
│              Network Monitoring Tool            │
├─────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Monitor │  │  Scan   │  │Traffic  │        │
│  │ Manager │  │ Engine  │  │Analyzer │        │
│  └─────────┘  └─────────┘  └─────────┘        │
│         │            │            │            │
│  ┌─────────────────────────────────────┐      │
│  │         Data Collection Layer       │      │
│  └─────────────────────────────────────┘      │
│         │            │            │            │
│  ┌─────────────────────────────────────┐      │
│  │      Storage & Processing Layer     │      │
│  └─────────────────────────────────────┘      │
│         │            │            │            │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │ Reports │  │ Alerts  │  │ Metrics │        │
│  │ Generator│ │ Engine  │  │ Exporter│        │
│  └─────────┘  └─────────┘  └─────────┘        │
└─────────────────────────────────────────────────┘


### Monitor hosts
python network_monitor.py monitor google.com 8.8.8.8 --interval 10

### Scan ports
python network_monitor.py scan 192.168.1.1 --ports 1-1024,3389,8080

### Monitor bandwidth
python network_monitor.py bandwidth --interface eth0 --graph

### Analyze traffic
sudo python network_monitor.py traffic --count 1000 --protocol tcp

### Show system info
python network_monitor.py info

### Run with default schedule
python monitor_wrapper.py --schedule

### Configure custom schedule
python monitor_wrapper.py --custom

### Run as service
./start_monitor.sh service


# Quick Deployment
chmod +x deploy_network_monitor.sh
./deploy_network_monitor.sh

# Advanced deployment
## Docker deployment
docker-compose up -d

## Kubernetes deployment
kubectl apply -f kubernetes/

## Systemd service
sudo cp network-monitor.service /etc/systemd/system/
sudo systemctl enable network-monitor
sudo systemctl start network-monitor

# Clone and deploy
git clone <repository-url>
cd network-monitor
./deploy_network_monitor.sh

# ===================== Docker deployment =========================================
### Build and run
docker-compose up -d

### View logs
docker-compose logs -f network-monitor

### Stop services
docker-compose down
# ===================== Kubernettes deployment =======================================
### Apply configuration
kubectl apply -f kubernetes/

### View pods
kubectl get pods -l app=network-monitor

### View logs
kubectl logs deployment/network-monitor

# Edit config/network_monitor.yaml to customize

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
