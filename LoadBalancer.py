import itertools
import random
import time

class LoadBalancer:
    def __init__(self, servers):
        self.servers = servers
        self.server_iterator = itertools.cycle(self.servers)

    def get_server(self):
        """Return the next server in a round-robin fashion."""
        return next(self.server_iterator)

    def distribute_load(self, requests):
        """Distribute requests to the servers."""
        for request in requests:
            server = self.get_server()
            print(f"Request {request} is being handled by {server}")
            time.sleep(random.uniform(0.5, 1.5))  # Simulate processing time

def main():
    # List of servers
    servers = ["Server 1", "Server 2", "Server 3"]

    # Create a LoadBalancer instance
    load_balancer = LoadBalancer(servers)

    # Simulate incoming requests
    requests = [f"Request {i+1}" for i in range(10)]
    load_balancer.distribute_load(requests)

if __name__ == "__main__":
    main()

""" 
Explanation of the Code

    LoadBalancer Class:
        Initializes with a list of servers and creates a circular iterator to cycle through them.
        get_server: Returns the next server in the list, cycling back to the start when reaching the end.
        distribute_load: Takes a list of requests and assigns each one to a server.

    Main Function:
        Initializes a list of servers and creates an instance of LoadBalancer.
        Simulates 10 incoming requests distributed across the servers.

Running the Script

To run the script, simply save it as load_balancer.py and execute it with Python:
bash

python load_balancer.py

Deploying a load balancer in a real-world application involves several steps, including selecting the appropriate technology stack, cloud infrastructure, and ensuring high availability. Here’s a structured approach to deploying a load balancer:
1. Choose Load Balancing Technology

    Software Load Balancers:
        Nginx: Popular for HTTP and TCP load balancing.
        HAProxy: High-performance TCP/HTTP load balancer.

    Cloud Load Balancers:
        AWS Elastic Load Balancing (ELB)
        Google Cloud Load Balancing
        Azure Load Balancer

2. Architecture Design

    Identify Components:
        Determine the application servers that will receive traffic.
        Identify databases, caches, and other services that may need load balancing.

    High Availability:
        Deploy load balancers in multiple availability zones.
        Use health checks to monitor the status of backend servers.

3. Set Up Your Environment

    Provision Infrastructure:
        Use cloud providers (AWS, GCP, Azure) or on-premises servers.
        Configure virtual machines or containers (e.g., Docker).

    Install Load Balancer Software:

        For Nginx:
        bash
        sudo apt update
        sudo apt install nginx
        
        For HAProxy:
        bash
        sudo apt update
        sudo apt install haproxy

4. Configure Load Balancer
Example: Nginx Configuration

    Edit the Nginx Configuration File:
    bash

sudo nano /etc/nginx/nginx.conf

Basic Configuration:
nginx

http {
    upstream backend {
        server backend1.example.com;
        server backend2.example.com;
        server backend3.example.com;
    }

    server {
        listen 80;

        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}

Test Configuration:
bash

sudo nginx -t

Reload Nginx:
bash

    sudo systemctl reload nginx

5. Implement Health Checks

    Nginx: Use the proxy_pass directive to handle responses from backend servers.
    HAProxy: Configure health checks in the HAProxy configuration file.

6. Set Up DNS

    Point your domain to the load balancer’s IP address or domain name.
    Use a DNS provider that supports TTL (Time to Live) settings to manage traffic efficiently.

7. Monitoring and Logging

    Monitoring Tools:
        Use tools like Prometheus, Grafana, or cloud-native monitoring solutions to track performance.

    Logging:
        Configure access and error logs for the load balancer to troubleshoot issues.

8. Security Considerations

    SSL/TLS: Implement HTTPS to encrypt traffic.
    Firewalls: Use security groups or firewall rules to restrict access.
    DDoS Protection: Consider services that provide DDoS mitigation.

9. Testing

    Load Testing: Use tools like Apache JMeter or Locust to simulate traffic.
    Failover Testing: Ensure that failover works correctly by simulating server failures.

10. Deploy and Maintain

    Deployment: Move from staging to production using CI/CD pipelines.
    Regular Maintenance: Keep the load balancer and servers updated.

"""
