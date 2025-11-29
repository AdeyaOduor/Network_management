# Automating Zone-Based Policy Firewall (ZPF) configuration on Cisco routers can enhance security management significantly. 

from netmiko import ConnectHandler
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

def connect_to_router(ip, username, password):
    """Connect to the router using SSH."""
    device = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': username,
        'password': password,
    }
    try:
        connection = ConnectHandler(**device)
        logging.info(f"Connected to {ip}")
        return connection
    except Exception as e:
        logging.error(f"Failed to connect to {ip}: {e}")
        return None

def define_policy(connection):
    """Define a service policy on the router."""
    try:
        commands = [
            "class-map match-any my_class",
            " match access-group name http_access",
            "policy-map my_policy",
            " class my_class",
            "  police 100000 2000 2000 conform-action transmit exceed-action drop"
        ]
        output = connection.send_config_set(commands)
        logging.info(f"Policy defined: {output}")
        return output
    except Exception as e:
        logging.error(f"Failed to define policy: {e}")
        return None

def configure_zpf(connection, zone_pairs):
    """Configure Zone-Based Policy Firewall on the router."""
    try:
        commands = []
        # Create zones
        for zone in set(pair['zone1'] for pair in zone_pairs).union(pair['zone2'] for pair in zone_pairs):
            commands.append(f"zone security {zone}")
        
        # Create zone pairs and attach policies
        for pair in zone_pairs:
            commands.append(f"zone pair security {pair['zone1']} {pair['zone2']} type {pair['type']}")
            commands.append(f"service-policy type {pair['type']} my_policy")

        output = connection.send_config_set(commands)
        logging.info(f"ZPF configuration applied: {output}")
        return output
    except Exception as e:
        logging.error(f"Failed to configure ZPF: {e}")
        return None

def show_zpf(connection):
    """Show the current ZPF configuration."""
    try:
        output = connection.send_command("show zone security")
        logging.info(f"Current ZPF configuration:\n{output}")
        return output
    except Exception as e:
        logging.error(f"Failed to show ZPF: {e}")
        return None

def disconnect_router(connection):
    """Disconnect from the router."""
    if connection:
        connection.disconnect()
        logging.info("Disconnected from the router.")

# Example usage
if __name__ == "__main__":
    routers = [
        {"ip": "192.168.1.1", "username": "admin", "password": "password1"},
        {"ip": "192.168.1.2", "username": "admin", "password": "password2"},
    ]

    zone_pairs = [
        {
            "zone1": "PRIVATE",
            "zone2": "PUBLIC",
            "type": "interzone",
        }
    ]

    for router in routers:
        conn = connect_to_router(router["ip"], router["username"], router["password"])
        if conn:
            define_policy(conn)  # Define the policy
            configure_zpf(conn, zone_pairs)  # Configure ZPF
            show_zpf(conn)  # Display current ZPF configuration
            disconnect_router(conn)  # Disconnect from the router
''' 
Step-by-Step Deployment Guide
1. Prepare Your Environment

    Install Python: Ensure Python is installed on your machine. You can download it from python.org.

    Install Required Libraries: Install the netmiko library for SSH connectivity.
    bash

    pip install netmiko

2. Gather Router Credentials

    Collect the IP addresses, usernames, and passwords for the routers you want to manage.

3. Modify the Script

    Update the Python script with the correct router IP addresses, usernames, and passwords. Customize the ZPF configurations as needed.

4. Save the Script

    Save the modified script as zpf_manager.py or any name you prefer.

5. Test Connectivity

    Before running the script, manually test SSH connectivity to your router:
    bash

    ssh admin@192.168.1.1

6. Run the Script

    Open a terminal and navigate to the directory where your script is saved. Run the script using Python:
    bash

    zpf_manager.py

7. Verify Configuration Changes

    After running the script, verify that the ZPF rules were applied correctly. Log into the router and use the following command:
    bash

show zone security
'''
