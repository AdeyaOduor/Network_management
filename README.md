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

# ==================== Run in CLI ===============================================
# Clone and deploy
git clone <repository-url>
cd network-monitor
./deploy_network_monitor.sh


# ===================== Docker deployment =========================================
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f network-monitor

# Stop services
docker-compose down
# ===================== Kubernettes deployment =======================================
# Apply configuration
kubectl apply -f kubernetes/

# View pods
kubectl get pods -l app=network-monitor

# View logs
kubectl logs deployment/network-monitor

# Edit config/network_monitor.yaml to customize

