
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check Python version
check_python() {
    print_status "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 is not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    print_success "Python $PYTHON_VERSION detected"
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y \
                python3-pip \
                python3-dev \
                build-essential \
                libpcap-dev \
                tcpdump \
                wireshark-common
                
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS
            sudo yum install -y \
                python3-pip \
                python3-devel \
                gcc \
                libpcap-devel \
                tcpdump \
                wireshark
        fi
        
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if ! command -v brew &> /dev/null; then
            print_error "Homebrew not installed. Please install from https://brew.sh"
            exit 1
        fi
        
        brew update
        brew install python3 libpcap tcpdump wireshark
        
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows
        print_warning "Windows detected. Some features may be limited."
        print_warning "Please install Npcap from: https://npcap.com/"
    fi
}

# Create virtual environment
setup_venv() {
    print_status "Setting up Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi
    
    # Upgrade pip
    pip install --upgrade pip
    
    print_success "Virtual environment activated"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create requirements.txt
    cat > requirements.txt << 'EOF'
# Core dependencies
psutil>=5.9.0
scapy>=2.5.0
matplotlib>=3.5.0
argparse>=1.4.0
configparser>=5.3.0

# Optional dependencies for enhanced features
pandas>=1.5.0          # For data analysis
numpy>=1.23.0          # For numerical operations
requests>=2.28.0       # For HTTP monitoring
prometheus-client>=0.15.0  # For metrics export
click>=8.1.0           # For better CLI
rich>=12.6.0           # For beautiful console output
tabulate>=0.9.0        # For formatted tables
pyyaml>=6.0            # For YAML config support
EOF
    
    pip install -r requirements.txt
    
    # Install optional dependencies
    pip install pandas numpy requests prometheus-client click rich tabulate pyyaml
    
    print_success "Python dependencies installed"
}

# Setup directory structure
setup_directories() {
    print_status "Setting up directory structure..."
    
    mkdir -p logs
    mkdir -p reports
    mkdir -p config
    mkdir -p data
    
    print_success "Directory structure created"
}

# Create configuration files
create_configs() {
    print_status "Creating configuration files..."
    
    # Main configuration
    cat > config/network_monitor.yaml << 'EOF'
# Enhanced Network Monitor Configuration

monitor:
  log_level: INFO
  max_workers: 10
  default_ping_timeout: 2
  default_scan_timeout: 1
  bandwidth_interval: 1
  traffic_buffer_size: 1000
  
  # Alert thresholds
  alert_thresholds:
    ping_timeout_ms: 1000
    packet_loss_percent: 10
    bandwidth_threshold_mbps: 100
    port_scan_threshold: 100

networks:
  # Default hosts to monitor
  default_hosts:
    - google.com
    - 8.8.8.8
    - 1.1.1.1
    - localhost
  
  # Common port ranges
  port_ranges:
    common: "1-1024"
    web: "80,443,8080,8443"
    database: "3306,5432,27017,6379"
    windows: "135-139,445,3389"
    custom: "22,23,25,53,110,143,993,995"

notifications:
  email:
    enabled: false
    smtp_server: smtp.gmail.com
    smtp_port: 587
    sender: ""
    password: ""
    recipients: []
  
  slack:
    enabled: false
    webhook_url: ""
    channel: "#network-alerts"
  
  webhook:
    enabled: false
    url: ""
    secret: ""

output:
  # Report formats
  formats: [json, html, csv]
  
  # Retention policies
  retention:
    logs_days: 30
    reports_days: 90
    data_days: 365
  
  # Export options
  export_to:
    - prometheus
    - elasticsearch
    - splunk
  
  # File locations
  directories:
    logs: ./logs
    reports: ./reports
    data: ./data

security:
  # Security settings
  require_root: false
  allowed_interfaces: []
  blocked_ips: []
  rate_limits:
    scans_per_hour: 1000
    pings_per_minute: 60
    packets_per_second: 1000
EOF
    
    # Create systemd service file for Linux
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cat > network-monitor.service << EOF
[Unit]
Description=Enhanced Network Monitoring Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python network_monitor.py monitor --config config/network_monitor.yaml
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=network-monitor

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$(pwd)/logs $(pwd)/reports $(pwd)/data
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
        
        print_success "Systemd service file created"
    fi
    
    print_success "Configuration files created"
}

# Create startup scripts
create_startup_scripts() {
    print_status "Creating startup scripts..."
    
    # Linux/macOS startup script
    cat > start_monitor.sh << 'EOF'
#!/bin/bash
# Startup script for Enhanced Network Monitor

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
elif [[ -f "venv/Scripts/activate" ]]; then
    source venv/Scripts/activate
fi

# Check for configuration
if [[ ! -f "config/network_monitor.yaml" ]]; then
    echo "Configuration file not found. Creating default..."
    python network_monitor.py --create-config
fi

# Parse command line arguments
MODE=${1:-"interactive"}
INTERFACE=${2:-""}
DURATION=${3:-""}

case "$MODE" in
    "service")
        # Run as service (continuous monitoring)
        echo "Starting network monitor in service mode..."
        python network_monitor.py monitor \
            --config config/network_monitor.yaml \
            --daemon \
            --log-file logs/service.log
        ;;
    
    "scan")
        # Run port scan
        TARGET=${2:-"localhost"}
        echo "Starting port scan on $TARGET..."
        python network_monitor.py scan "$TARGET" \
            --config config/network_monitor.yaml \
            --output reports/scan_$(date +%Y%m%d_%H%M%S).json
        ;;
    
    "bandwidth")
        # Monitor bandwidth
        echo "Starting bandwidth monitoring..."
        python network_monitor.py bandwidth \
            --config config/network_monitor.yaml \
            --interface "$INTERFACE" \
            --duration "$DURATION" \
            --graph
        ;;
    
    "traffic")
        # Analyze traffic
        echo "Starting traffic analysis..."
        sudo python network_monitor.py traffic \
            --config config/network_monitor.yaml \
            --count 1000 \
            --interface "$INTERFACE" \
            --output reports/traffic_$(date +%Y%m%d_%H%M%S).pcap
        ;;
    
    "interactive"|*)
        # Interactive mode
        echo "Starting Enhanced Network Monitor in interactive mode..."
        python network_monitor.py
        ;;
esac
EOF
    
    chmod +x start_monitor.sh
    
    # Windows batch file
    cat > start_monitor.bat << 'EOF'
@echo off
REM Startup script for Enhanced Network Monitor (Windows)

cd /d %~dp0

REM Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Check for configuration
if not exist "config\network_monitor.yaml" (
    echo Configuration file not found. Creating default...
    python network_monitor.py --create-config
)

REM Start the monitor
echo Starting Enhanced Network Monitor...
python network_monitor.py

pause
EOF
    
    print_success "Startup scripts created"
}

# Create monitoring wrapper
create_monitoring_wrapper() {
    print_status "Creating monitoring wrapper..."
    
    cat > monitor_wrapper.py << 'EOF'
#!/usr/bin/env python3
"""
Monitoring Wrapper for Enhanced Network Monitor
Provides additional features and integrations
"""

import sys
import os
import time
import json
import yaml
import schedule
from datetime import datetime
from typing import Dict, List, Optional
import logging
from logging.handlers import RotatingFileHandler, SMTPHandler

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from network_monitor import NetworkMonitor, ConfigManager
except ImportError:
    print("Error: Could not import network_monitor module")
    sys.exit(1)

class MonitoringScheduler:
    """Schedule and manage monitoring tasks"""
    
    def __init__(self, config_path: str):
        self.config = ConfigManager(config_path)
        self.monitor = NetworkMonitor(self.config)
        self.tasks = []
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = self.config.get('output', 'directories.logs', './logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger('MonitoringScheduler')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'scheduler.log'),
            maxBytes=10*1024*1024,
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def add_daily_scan(self, time_str: str, target: str, ports: str):
        """Add daily port scan task"""
        def scan_job():
            self.logger.info(f"Running daily scan on {target}")
            print(f"\n{'='*60}")
            print(f"DAILY SCAN - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Target: {target}")
            print(f"Ports: {ports}")
            print(f"{'='*60}")
            
            # Parse port ranges
            from network_monitor import parse_port_ranges
            port_ranges = parse_port_ranges(ports)
            
            results = self.monitor.scan_ports(target, port_ranges)
            
            # Save results
            report_dir = self.config.get('output', 'directories.reports', './reports')
            os.makedirs(report_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(report_dir, f'scan_{target}_{timestamp}.json')
            
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'ports': ports,
                'open_ports': [
                    {
                        'port': r.port,
                        'service': r.service,
                        'response_time': r.response_time
                    }
                    for r in results
                ]
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Scan report saved to {report_file}")
            print(f"\nScan completed. Results saved to: {report_file}")
        
        schedule.every().day.at(time_str).do(scan_job)
        self.tasks.append(f"Daily scan at {time_str} on {target}")
        self.logger.info(f"Scheduled daily scan at {time_str} on {target}")
    
    def add_bandwidth_monitor(self, interval_minutes: int, duration_minutes: int):
        """Add periodic bandwidth monitoring"""
        def bandwidth_job():
            self.logger.info("Running bandwidth monitoring")
            print(f"\n{'='*60}")
            print(f"BANDWIDTH MONITOR - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")
            
            self.monitor.monitor_bandwidth(
                interval=1,
                duration=duration_minutes * 60
            )
        
        schedule.every(interval_minutes).minutes.do(bandwidth_job)
        self.tasks.append(f"Bandwidth monitor every {interval_minutes} minutes")
        self.logger.info(f"Scheduled bandwidth monitoring every {interval_minutes} minutes")
    
    def add_host_monitor(self, hosts: List[str], interval_minutes: int):
        """Add host availability monitoring"""
        def host_monitor_job():
            self.logger.info("Running host monitoring")
            print(f"\n{'='*60}")
            print(f"HOST MONITOR - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")
            
            self.monitor.monitor_hosts(
                hosts=hosts,
                interval=5,
                duration=60  # Run for 1 minute each check
            )
        
        schedule.every(interval_minutes).minutes.do(host_monitor_job)
        self.tasks.append(f"Host monitor every {interval_minutes} minutes")
        self.logger.info(f"Scheduled host monitoring every {interval_minutes} minutes")
    
    def run(self):
        """Run the scheduler"""
        print(f"\n{'='*60}")
        print(f"ENHANCED NETWORK MONITOR SCHEDULER")
        print(f"{'='*60}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scheduled tasks: {len(self.tasks)}")
        
        for i, task in enumerate(self.tasks, 1):
            print(f"  {i}. {task}")
        
        print(f"\nPress Ctrl+C to stop")
        print(f"{'='*60}\n")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nScheduler stopped by user")
            self.logger.info("Scheduler stopped by user")

def main():
    """Main entry point for monitoring wrapper"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitoring Scheduler')
    parser.add_argument('--config', '-c', default='config/network_monitor.yaml',
                       help='Configuration file path')
    parser.add_argument('--schedule', '-s', action='store_true',
                       help='Run with default schedule')
    parser.add_argument('--custom', action='store_true',
                       help='Configure custom schedule')
    
    args = parser.parse_args()
    
    # Create scheduler
    scheduler = MonitoringScheduler(args.config)
    
    if args.schedule:
        # Default schedule
        scheduler.add_daily_scan("02:00", "localhost", "1-1024,3389,8080,8443")
        scheduler.add_bandwidth_monitor(30, 5)  # Every 30 minutes, for 5 minutes
        scheduler.add_host_monitor(["google.com", "8.8.8.8", "localhost"], 15)
    
    elif args.custom:
        # Interactive custom schedule
        print("Custom Schedule Configuration")
        print("-" * 40)
        
        # Get daily scan settings
        scan_time = input("Daily scan time (HH:MM) [02:00]: ") or "02:00"
        scan_target = input("Scan target [localhost]: ") or "localhost"
        scan_ports = input("Ports to scan [1-1024,3389,8080,8443]: ") or "1-1024,3389,8080,8443"
        
        scheduler.add_daily_scan(scan_time, scan_target, scan_ports)
        
        # Get bandwidth monitor settings
        bw_interval = input("Bandwidth monitor interval (minutes) [30]: ") or "30"
        bw_duration = input("Bandwidth monitor duration (minutes) [5]: ") or "5"
        
        scheduler.add_bandwidth_monitor(int(bw_interval), int(bw_duration))
        
        # Get host monitor settings
        hosts_input = input("Hosts to monitor (comma-separated) [google.com,8.8.8.8,localhost]: ") \
                     or "google.com,8.8.8.8,localhost"
        hosts = [h.strip() for h in hosts_input.split(',')]
        host_interval = input("Host monitor interval (minutes) [15]: ") or "15"
        
        scheduler.add_host_monitor(hosts, int(host_interval))
    
    else:
        parser.print_help()
        return
    
    # Run scheduler
    scheduler.run()

if __name__ == "__main__":
    main()
EOF
    
    chmod +x monitor_wrapper.py
    print_success "Monitoring wrapper created"
}

# Create Docker deployment
create_docker_deployment() {
    print_status "Creating Docker deployment..."
    
    # Dockerfile
    cat > Dockerfile << 'EOF'
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 monitor

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p logs reports data config

# Set permissions
RUN chown -R monitor:monitor /app

# Switch to non-root user
USER monitor

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); s.connect(('google.com', 80)); s.close()" || exit 1

# Default command
CMD ["python", "network_monitor.py", "monitor", "--config", "config/network_monitor.yaml"]
EOF
    
    # Docker Compose
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  network-monitor:
    build: .
    container_name: network-monitor
    restart: unless-stopped
    privileged: true  # Required for packet capture
    network_mode: host  # Use host network for accurate monitoring
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./reports:/app/reports
      - ./data:/app/data
    environment:
      - TZ=UTC
      - LOG_LEVEL=INFO
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "5"
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; s = socket.socket(); s.settimeout(2); result = s.connect_ex(('google.com', 80)); s.close(); exit(0 if result == 0 else 1)"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

  # Optional: Add Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  # Optional: Add Grafana for dashboards
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false

volumes:
  prometheus_data:
  grafana_data:
EOF
    
    # Prometheus configuration
    mkdir -p prometheus
    cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'network-monitor'
    static_configs:
      - targets: ['network-monitor:8000']
    metrics_path: '/metrics'
    
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF
    
    print_success "Docker deployment files created"
}

# Create Kubernetes deployment
create_kubernetes_deployment() {
    print_status "Creating Kubernetes deployment..."
    
    mkdir -p kubernetes
    
    # Kubernetes deployment
    cat > kubernetes/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-monitor
  labels:
    app: network-monitor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: network-monitor
  template:
    metadata:
      labels:
        app: network-monitor
    spec:
      # Required for packet capture
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: network-monitor
        image: network-monitor:latest
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
          capabilities:
            add:
              - NET_ADMIN
              - NET_RAW
        ports:
        - containerPort: 8000
          name: metrics
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: logs
          mountPath: /app/logs
        - name: reports
          mountPath: /app/reports
        - name: data
          mountPath: /app/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - python
            - -c
            - |
              import socket
              s = socket.socket()
              s.settimeout(2)
              result = s.connect_ex(('google.com', 80))
              s.close()
              exit(0 if result == 0 else 1)
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - python
            - -c
            - "import sys; sys.exit(0)"
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: network-monitor-config
      - name: logs
        emptyDir: {}
      - name: reports
        emptyDir: {}
      - name: data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: network-monitor
spec:
  selector:
    app: network-monitor
  ports:
  - port: 8000
    targetPort: 8000
    name: metrics
  type: ClusterIP
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: network-monitor-config
data:
  network_monitor.yaml: |
    # Configuration as YAML string
    monitor:
      log_level: INFO
      max_workers: 10
EOF
    
    # ServiceMonitor for Prometheus Operator
    cat > kubernetes/servicemonitor.yaml << 'EOF'
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: network-monitor
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: network-monitor
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
EOF
    
    print_success "Kubernetes deployment files created"
}

# Create documentation
create_documentation() {
    print_status "Creating documentation..."
    
    cat > README.md << 'EOF'
