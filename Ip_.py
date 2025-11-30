# convert an IPv4 address from dotted decimal notation to binary representation. 
# This conversion is useful in networking for understanding how IP addresses are structured and processed at a lower level.
def dotted_decimal_to_binary(ip_address):
    octets = ip_address.split('.')
    binary_octets = []

    for octet in octets:
        binary_octet = bin(int(octet))[2:].zfill(8)  # Convert each octet to binary and pad with zeros
        binary_octets.append(binary_octet)

    binary_ip_address = '.'.join(binary_octets)
    return binary_ip_address

# Example usage
ip_address = '172.16.10.1'
binary_ip = dotted_decimal_to_binary(ip_address)
print("Dotted Decimal to Binary:", binary_ip)  # Output: Dotted Decimal to Binary: 10101100.00010000.00001010.00000001

""" 
Real-World Application Example: Network Configuration and Troubleshooting
Scenario: Understanding IP Addressing in Networking

Context: Network engineers and administrators often need to work with both decimal and binary representations of IP addresses for various tasks, 
including subnetting, configuring routers, and troubleshooting networks.

    Subnetting:
        When determining subnet masks and calculating subnets, administrators often convert IP addresses to binary. Understanding the binary 
        representation helps in recognizing which bits represent the network and which bits represent hosts.

    Routing:
        Routers and switches operate at the binary level. When configuring routing tables, engineers may need to convert IP addresses to binary to 
        understand how packets are routed within and between networks.

    Troubleshooting:
        When diagnosing connectivity issues, network professionals may analyze binary representations to identify misconfigurations. For example, 
        if two devices should be on the same subnet, their binary IP addresses can clarify whether they are indeed in the same range.

    Security:
        Understanding IP addresses in binary can help in configuring access control lists (ACLs) and firewall rules, allowing administrators to specify 
        rules based on specific bits in an IP address.
        e.g. access-list 100 permit ip host 192.168.1.10
             access-list 100 deny ip any any
             access-list 100 permit ip 192.168.1.0 0.0.0.255
"""
# -----------------------------------------------------------------------------------------------------------

# convert an IPv4 address from dotted decimal notation to hexadecimal format. This conversion can be useful in various networking contexts, such as 
# understanding packet structures, working with certain network protocols, and configuring devices that require hexadecimal IP representations.
def dotted_decimal_to_hex(ip_address):
    octets = ip_address.split('.')
    hex_octets = []

    for octet in octets:
        hex_octet = hex(int(octet))[2:].zfill(2)  # Convert each octet to hexadecimal and pad with zeros
        hex_octets.append(hex_octet)

    hex_ip_address = '.'.join(hex_octets)
    return hex_ip_address

# Example usage
ip_address = '192.168.10.1'
hex_ip = dotted_decimal_to_hex(ip_address)
print("Dotted Decimal to Hexadecimal:", hex_ip)
# Output: Dotted Decimal to Hexadecimal: c0.a8.0a.01

""" 
Real-World Applications of Hexadecimal IP Addresses
1. Network Protocols and Configuration

    Packet Analysis: Certain protocols may represent IP addresses in hexadecimal form. For example, in the context of low-level network protocols 
    like ARP (Address Resolution Protocol), hexadecimal representations may be used in packet headers.

    Device Configuration: Some network devices or software interfaces may require IP addresses to be entered in hexadecimal format, particularly in 
    specialized configurations or scripting environments.

2. Subnetting and IP Address Planning

    Visualizing Address Space: Hexadecimal representation can sometimes make it easier to visualize and manage IP address ranges, especially when 
    dealing with large blocks of addresses.

    Calculation of Network and Host Portions: When subnetting, converting to hexadecimal can provide a different perspective and may simplify 
    calculations in certain contexts, particularly when working with masks.

3. Debugging and Troubleshooting

    Packet Sniffing: Tools like Wireshark display packet data in hexadecimal. Understanding how to convert IP addresses to hex can aid in interpreting 
    this data better when troubleshooting network issues.

    Firewall Rules and ACLs: Some firewall configurations might use hexadecimal representations for IP addresses. Understanding how to convert and 
    represent these addresses correctly can ensure accurate rule creation.
"""
# -----------------------------------------------------------------------------------------------------

# convert an IPv4 address from dotted decimal notation to octal format. This conversion can be useful in specific networking contexts, such as legacy systems 
# or educational purposes, where octal representations might still be relevant.
def dotted_decimal_to_octal(ip_address):
    octets = ip_address.split('.')
    octal_octets = []

    for octet in octets:
        octal_octet = oct(int(octet))[2:].zfill(3)  # Convert each octet to octal and pad with zeros
        octal_octets.append(octal_octet)

    octal_ip_address = '.'.join(octal_octets)
    return octal_ip_address

# Example usage
ip_address = '172.168.1.0'
octal_ip = dotted_decimal_to_octal(ip_address)
print("Dotted Decimal to Octal:", octal_ip)
# Output: Dotted Decimal to Octal: 254.250.001.000
# ---------------------------------------------------------------------------------------------------------
""" Automate IPv4 addressing 
How to generate a specified number of usable IPv4 addresses from a given network in CIDR notation. 
This functionality can be useful for network configuration, testing, and allocation scenarios.

Example: When setting up new devices (like routers, switches, or servers) in a corporate network, administrators can quickly generate IP addresses 
to assign to these devices without manually calculating or tracking used addresses."""

import ipaddress

def generate_ipv4_addresses(network, num_addresses):
    network = ipaddress.ip_network(network)  # Convert the input string to an ip_network object
    addresses = []
    for ip in network.hosts():  # Iterate through all usable host IPs in the network
        addresses.append(str(ip))  # Append the IP address to the list
        if len(addresses) == num_addresses:  # Stop when the desired number of addresses is reached
            break
    return addresses

# Example network in CIDR notation and the desired number of addresses to generate.
network = '192.168.0.0/24'  # Define a network
num_addresses = 10  # Define how many addresses to generate

ipv4_addresses = generate_ipv4_addresses(network, num_addresses)  # Generate addresses
for address in ipv4_addresses:  # Print each generated address
    print(address)

""" 
Output:
192.168.0.1
192.168.0.2
192.168.0.3
192.168.0.4
192.168.0.5
192.168.0.6
192.168.0.7
192.168.0.8
192.168.0.9
192.168.0.10

Real-World Applications of Generating IPv4 Addresses
1. Network Planning and Design

    Address Allocation: When designing a network, administrators can use this function to quickly allocate IP addresses for devices in a specific 
    subnet. This helps ensure efficient use of available IP address space.

2. Testing and Development

    Simulated Environments: Developers can use generated IP addresses to set up test environments, ensuring that applications and services behave 
    correctly when interfacing with various IP addresses.

    Automated Testing: During automated testing of network applications, generating a range of IP addresses can help verify that the application can 
    handle different configurations and address scenarios.

3. Configuration Scripts

    Dynamic Configuration: Automated scripts that configure routers, switches, or servers can leverage this function to assign IP addresses dynamically 
    based on the specified network and requirements.

    DHCP Configuration: When configuring DHCP servers, administrators can generate a list of IP addresses to be assigned to clients dynamically.

4. Network Security

    Access Control Lists (ACLs): When configuring ACLs, administrators can use generated addresses to define which devices are permitted or denied 
    access to network resources.

    Monitoring and Logging: Security tools may need to monitor traffic for specific IP ranges. Generating these addresses programmatically can 
    streamline the setup of such monitoring tools.

"""

# ---------------------------------------------------------------------------------------------------------------------------------------------------------
# How to generate a list of usable IPv4 addresses from a given network address and subnet mask. This functionality is useful in various networking tasks,
# such as configuration, testing, and address allocation.

import ipaddress

def generate_ipv4_addresses(network_address, subnet_mask):
    network = ipaddress.IPv4Network(f"{network_address}/{subnet_mask}", strict=False)  # Create an IPv4Network object
    addresses = [str(ip) for ip in network.hosts()]  # Generate a list of usable host IP addresses
    return addresses

# Example usage
network_address = '192.168.1.0'  # Define the network address
subnet_mask = '24'  # Define the subnet mask
ipv4_addresses = generate_ipv4_addresses(network_address, subnet_mask)  # Generate IP addresses
for ip in ipv4_addresses:  # Print each generated IP address
    print(ip)
""" 
Real-World Applications of Generating IPv4 Addresses
1. Network Design and Planning

    Address Allocation: Administrators can quickly generate and allocate IP addresses for devices in a specific subnet, ensuring efficient use of 
    the available address space.

2. Testing and Development

    Simulated Environments: The function can be used to set up test environments with specific IP address ranges, enabling developers to test 
    applications under realistic conditions.

    Automated Testing: During automated testing of network applications, generating a range of IP addresses can be crucial for verifying that the 
    application handles different configurations correctly.

3. Configuration Management

    Dynamic Configuration: Network scripts can use this function to dynamically generate IP addresses for routers, switches, or servers, simplifying 
    configuration tasks.

    DHCP Configuration: When configuring DHCP servers, administrators can generate a list of IP addresses to be assigned to clients dynamically.

4. Network Security

    Access Control Lists (ACLs): When setting up ACLs, administrators can use generated addresses to specify which devices are permitted or denied 
    access to network resources.

    Monitoring and Logging: Security tools may need to monitor traffic for specific IP ranges. Generating these addresses programmatically can 
    streamline the setup of such monitoring tools.
"""


# -----------------------------------------------------------------------------------------------------------------------------------------------------
""" subnet an existing IPv4 network into smaller subnets based on a specified subnet mask. 
The code snippet below is designed to subnet an existing IPv4 network into smaller subnets based on a specified subnet mask. 
This functionality is particularly useful in network management and design, helping administrators efficiently allocate IP addresses and 
optimize network performance
    Scenario: Organizations often need to segment their networks for better management and security. Subnetting allows for creating smaller, 
    manageable networks within a larger network.
    Example: A company might subnet a larger network to separate departments (e.g., HR, IT, Sales) for performance and security reasons.
"""
import ipaddress

def subnet_network(network, subnet_mask):
    network = ipaddress.ip_network(network)  # Create an IPv4Network object from the input
    subnets = list(network.subnets(new_prefix=subnet_mask))  # Generate subnets with the new prefix
    return subnets

# Example usage
network = '192.168.0.0/24'  # Define the original network in CIDR notation
subnet_mask = 26  # Define the desired subnet mask (prefix length)
subnet_mask = 27  # Define the desired subnet mask (prefix length)

subnets = subnet_network(network, subnet_mask)  # Generate the subnets
for subnet in subnets:  # Print each generated subnet
    print(subnet)
""" 
Usable hosts
192.168.0.0/26
192.168.0.64/26
192.168.0.128/26
192.168.0.192/26

192.168.0.0/27
192.168.0.32/27
192.168.0.64/27
192.168.0.96/27
192.168.0.128/27
192.168.0.160/27
192.168.0.192/27
192.168.0.224/27

Real-World Applications of Subnetting
1. Network Design and Planning

    Segmenting Networks: Subnetting allows administrators to break down a large network into smaller, manageable segments. 
    This can improve performance and security by limiting broadcast domains and controlling traffic flows.

2. IP Address Management

    Efficient Use of IP Space: By subnetting, administrators can allocate IP addresses more efficiently, ensuring that each subnet 
    has enough addresses for its devices without wasting address space.

3. Security Enhancements

    Isolation of Network Segments: Subnetting can enhance security by isolating different parts of the network. For example, a guest network 
    can be subnetted separately from the internal network, preventing unauthorized access.

4. Improved Performance

    Reduced Broadcast Traffic: By dividing a network into subnets, broadcast traffic is contained within each subnet, reducing overall network 
    congestion and improving performance.

5. Simplified Troubleshooting and Maintenance

    Easier Diagnostics: When issues arise, subnetting can help isolate problems to specific segments of the network, making troubleshooting more 
    straightforward.

"""
# ------------------------------------------------------------------------------------------------------------------------------------------

""" 
How to retrieve the valid subnet mask and the default gateway from a given IPv4 network address specified in CIDR notation. 
This functionality is useful for network configuration and management, helping administrators to easily identify key networking parameters.

    Scenario: When setting up a network, administrators need to configure devices with the correct subnet mask and default gateway for proper 
    communication.
    Example: During the initial setup of routers and switches, this information is essential to ensure devices can communicate within their 
    subnet and with external networks.
    Scenario: Network issues often arise from incorrect subnet configurations. Administrators can quickly verify subnet masks and gateways to 
    diagnose problems.
    Example: If a device cannot access the internet, checking the default gateway and subnet mask can reveal misconfigurations.
"""
import ipaddress

network_address = '192.168.1.0/26'  # Define the network address in CIDR notation

# Get the valid subnet mask
subnet_mask = ipaddress.IPv4Network(network_address).netmask  # Retrieve the subnet mask

# Get the default gateway
default_gateway = ipaddress.IPv4Network(network_address)[1]  # Retrieve the first usable IP address as the gateway

print('Valid Subnet Mask:', subnet_mask)  # Output the subnet mask
print('Default Gateway:', default_gateway)  # Output the default gateway

""" using; '192.168.1.0/26'
Valid Subnet Mask: 255.255.255.192
Default Gateway: 192.168.1.1 for 60 LAN hosts

using; '192.168.1.0/27'
Valid Subnet Mask: 255.255.255.224
Default Gateway: 192.168.1.1 for 20 LAN hosts

Real-World Applications
1. Network Configuration

    Setting Up Routers and Switches: Knowing the valid subnet mask and default gateway is essential when configuring network devices. 
    This information helps ensure devices can communicate properly within the network.

2. IP Address Management

    Dynamic Host Configuration Protocol (DHCP): When setting up a DHCP server, the subnet mask and default gateway are critical parameters 
    that must be configured to ensure that clients can obtain valid IP addresses and communicate with other networks.

3. Troubleshooting

    Network Diagnostics: Understanding the subnet mask and default gateway can help network administrators diagnose connectivity issues. For 
    example, if devices cannot reach the gateway, it may indicate a misconfiguration in the subnetting.

4. Security Settings

    Access Control Lists (ACLs): Properly configuring ACLs often requires knowledge of the subnet mask and gateway to correctly define which 
    devices can access certain resources.
"""
# ---------------------------------------------------------------------------------------------------------------------------------

""" 
How to determine the network address from a given IP address and subnet mask. This functionality is 
useful for network configuration and management tasks.
Apython program that determine the network address of a destination IP using the AND operation by:
    Converting the IP address and subnet mask into binary format.
    Performing the AND operation on the binary representations of the IP address and subnet mask.
    Convert the resulting binary back to decimal format to get the destination network address.
"""

import ipaddress

def get_network_address(ip, subnet_mask):
    # Create IPv4Network object from the IP and subnet mask
    network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
    
    # Get the network address
    network_address = network.network_address
    
    return network_address

# Example usage
ip = '192.168.1.10'  # Destination IP address
subnet_mask = '255.255.255.0'  # Subnet mask

network_address = get_network_address(ip, subnet_mask)
print(f"The network address for IP {ip} with subnet mask {subnet_mask} is: {network_address}")

""" 
Output: 
The network address for IP 192.168.1.10 with subnet mask 255.255.255.0 is: 192.168.1.0

Real-World Applications
1. Network Configuration

    Setting Up Devices: Knowing the network address is essential when configuring networking devices, such as routers and switches, to ensure that 
    they are correctly assigned to the appropriate subnetwork.

2. IP Address Management

    Dynamic Host Configuration Protocol (DHCP): When configuring DHCP servers, the network address is crucial for defining the scope of available IP 
    addresses for clients within a subnet.

3. Subnetting and Planning

    Network Design: Understanding how to derive network addresses is essential for effective subnetting, allowing network administrators to design 
    networks that optimize performance and security.

4. Troubleshooting

    Connectivity Issues: In troubleshooting scenarios, knowing the network address helps determine if devices are correctly assigned within the same 
    network segment.
"""
# ---------------------------------------------------------------------------------------------------------------------------

""" Automate ipv6 addressing
The following code snippet demonstrates how to generate a specified number of usable IPv6 addresses from a given network in CIDR notation. 
This functionality is useful for various networking tasks, such as testing, configuration, and address allocation.
    Scenario: Network administrators need to allocate IPv6 addresses for devices within a subnet. This function allows them to generate a list of 
    available addresses quickly.
    Example: When setting up new devices in an IPv6-enabled network, administrators can generate addresses for those devices without manually 
    calculating them.
"""

import ipaddress

def generate_ipv6_addresses(network, num_addresses):
    network = ipaddress.ip_network(network)  # Create an IPv6Network object from the input
    addresses = []
    for ip in network.hosts():  # Iterate through all usable host IPs in the network
        addresses.append(str(ip))  # Append the IP address to the list
        if len(addresses) == num_addresses:  # Stop when the desired number of addresses is reached
            break
    return addresses

# Example usage
network = '2001:db8::/64'  # Define a network in CIDR notation
num_addresses = 10  # Define how many addresses to generate

ipv6_addresses = generate_ipv6_addresses(network, num_addresses)  # Generate addresses
for address in ipv6_addresses:  # Print each generated address
    print(address)
"""
Output:
2001:db8::1
2001:db8::2
2001:db8::3
2001:db8::4
2001:db8::5
2001:db8::6
2001:db8::7
2001:db8::8
2001:db8::9
2001:db8::a

Real-World Applications of Generating IPv6 Addresses
1. Network Planning and Design

    Address Allocation: When designing a network, administrators can use this function to quickly allocate IPv6 addresses for devices in a specific 
    subnet, ensuring efficient use of available address space.

2. Testing and Development

    Simulated Environments: Developers can use generated IPv6 addresses to set up test environments, ensuring that applications and services behave 
    correctly when interfacing with various IP addresses.

    Automated Testing: During automated testing of network applications, generating a range of IPv6 addresses can help verify that the application can 
    handle different configurations and address scenarios.

3. Configuration Scripts

    Dynamic Configuration: In custom scripts or tools, IPv6 addresses may be required for certain calculations or configurations. Knowing how to 
    generate these addresses programmatically can facilitate such tasks.

4. Network Security

    Access Control Lists (ACLs): When configuring ACLs, administrators can use generated addresses to define which devices are permitted or denied 
    access to network resources.

    Monitoring and Logging: Security tools may need to monitor traffic for specific IPv6 ranges. Generating these addresses programmatically can 
    streamline the setup of such monitoring tools.

"""
# -----------------------------------------------------------------------------------------------------------------

""" 
How to subnet an IPv6 network using a specified subnet mask. This functionality is valuable for network design and management, allowing administrators to 
divide a larger network into smaller sub-networks (subnets).
    Scenario: Organizations often need to manage and allocate IPv6 addresses efficiently. Subnetting allows for creating smaller address blocks from a larger network.
    Example: An enterprise might subnet a larger IPv6 network for different departments, ensuring that each has a sufficient range of addresses.

    Scenario: Subnetting helps to segment a network for better security and performance.
    Example: By creating separate subnets for different services (e.g., servers, user devices, and IoT devices), organizations can isolate traffic and enhance security.
"""

import ipaddress

def subnet_network(network, subnet_mask):
    network = ipaddress.ip_network(network)  # Create an IPv6Network object from the input
    subnets = list(network.subnets(new_prefix=subnet_mask))  # Generate subnets with the new prefix
    return subnets

# Example usage
network = '2001:db8::/32'  # Define the original IPv6 network in CIDR notation
subnet_mask = 64  # Define the desired subnet mask (prefix length)

subnets = subnet_network(network, subnet_mask)  # Generate the subnets
for subnet in subnets:  # Print each generated subnet
    print(subnet)
""" 
2001:db8:0:0::/64
2001:db8:0:1::/64
2001:db8:0:2::/64
2001:db8:0:3::/64
...
2001:db8:0:ffff::/64

Real-World Applications of Subnetting IPv6
1. Network Design and Planning

    Segmenting Networks: Subnetting allows network administrators to break a large network into smaller, manageable segments. 
    This improves performance and security by limiting broadcast domains and controlling traffic flows.

2. Efficient Use of IP Address Space

    Address Allocation: By subnetting, administrators can efficiently allocate IPv6 addresses to different departments or services, 
    ensuring optimal utilization of the available address space.

3. Security Enhancements

    Isolation of Network Segments: Subnetting can enhance security by isolating different parts of the network. For example, a guest network 
    can be subnetted separately from the internal network to prevent unauthorized access.

4. Improved Performance

    Reduced Broadcast Traffic: By dividing a network into subnets, broadcast traffic is contained within each subnet, reducing overall network 
    congestion and improving performance.

5. Simplified Troubleshooting and Maintenance

    Easier Diagnostics: When issues arise, subnetting helps isolate problems to specific segments of the network, making troubleshooting more 
    straightforward.
"""

# --------------------------------------------------------------------------------------------------------------------------------------------------
""" 
The following code snippet demonstrates how to create multiple subnets from a given IPv6 network based on a list of desired prefix lengths. 
This functionality is useful for network planning and allocation, allowing administrators to derive subnets of varying sizes from a larger 
address block."""

import ipaddress

def subnet_ipv6(network, prefix_lengths):
    network = ipaddress.ip_network(network)  # Create an IPv6Network object from the input
    subnets = []
    for prefix_length in prefix_lengths:  # Iterate through the list of desired prefix lengths
        subnet = list(network.subnets(new_prefix=prefix_length))  # Generate subnets with the new prefix
        subnets.extend(subnet)  # Add generated subnets to the list
    return subnets

# Example usage
network = '2001:db8:abcd::/48'  # Define the original IPv6 network in CIDR notation
prefix_lengths = [64, 80, 96]  # Define the desired prefix lengths

subnets = subnet_ipv6(network, prefix_lengths)  # Generate the subnets
for subnet in subnets:  # Print each generated subnet
    print(subnet)

""" Output
2001:db8:abcd::/64
2001:db8:abcd:1::/64
2001:db8:abcd:2::/64
...
2001:db8:abcd:ff::/64
2001:db8:abcd:0:0:0:0:0/80
2001:db8:abcd:0:0:0:0:1/80
...
2001:db8:abcd:0:0:0:0:ffff/96"""
# -----------------------------------------------------------------------------------------------------------------------------
""" How to use the ipinfo library to retrieve and display information about an IP address using the IPinfo API. 
This can be particularly useful in various real-world applications, especially in networking, cybersecurity, and marketing analytics.


Fisrt install ipinfo package by running the following in the terminal

$ pip install ipinfo

Then run the following code:
"""
import ipinfo
import sys

# Get the IP address from the command line
try:
    ip_address = sys.argv[1]
except IndexError:
    ip_address = None
# placeholder for the API access token required to authenticate requests to the IPinfo API
access_token = '<put_your_access_token_here>'

# Create a client object with the access token
handler = ipinfo.getHandler(access_token)

# Get the IP info
details = handler.getDetails(ip_address)

# Print the IP info
for key, value in details.all.items():
    print(f"{key}: {value}")

    """ To run the code, open a terminal or command prompt, navigate to the directory 
    where the script is located, and execute the following command:"""
    
    # Run the following in the terminal
    $ python get_ip_info.py 142.93.95.0 
  # output  
    
""" Replace get_ip_info.py with the name of the Python script file, and 142.93.95.0 
with the IP address for which you want to retrieve information.

Scenario: Targeted Market Analytics Advertising Campaigns

Company Context: A digital marketing agency wants to optimize its advertising campaigns based on the geographic 
locations of users interacting with their ads. By understanding where users are coming from, they can tailor their 
marketing strategies more effectively.

    Data Collection:
        When users click on ads, the agency captures their IP addresses. Using the above code, the agency can look up 
        information about each IP address to determine its geographic location and other relevant details.

    IP Address Lookup:
        By running the script with the captured IP addresses, the agency retrieves information such as:
            Country
            Region
            City
            ISP (Internet Service Provider)
            Organization

    Analysis:
        The agency analyzes the collected data to identify trends in user engagement:
            Which regions have higher conversion rates?
            Are there specific cities where ads perform exceptionally well or poorly?

    Campaign Optimization:
        Based on the insights gained, the agency can:
            Adjust ad spend by region, increasing investment in high-performing areas.
            Create localized content that resonates better with users in specific locations.
            Identify potential new markets for expansion based on geographic engagement.

    Reporting:
        The agency generates reports for clients, detailing the performance of campaigns by region, helping to inform future marketing strategies.

"""
# ------------------------------------------------------------------------------------------------------------------------------
"""
The follwing code snippet demonstrates how to plan and allocate subnets from a given IPv4 network based on specific requirements. 
This functionality is essential for network administrators who need to efficiently allocate address space based on organizational needs."""

import ipaddress
def plan_networks(network, requirements):
    network = ipaddress.ip_network(network)  # Create an IPv4Network object from the input
    subnet_objects = []  # List to store allocated subnet objects
    for req in requirements:  # Iterate through each requirement
        subnet_mask = req['subnet_mask']  # Extract the subnet mask
        subnet_count = req['subnet_count']  # Extract the required number of subnets
        subnets = list(network.subnets(new_prefix=subnet_mask))  # Generate subnets with the specified mask
        if len(subnets) < subnet_count:  # Check if enough subnets are available
            raise ValueError(f"Not enough subnets available for requirement: {req}")
        if subnet_count > 0:  # If there are subnets needed
            subnet_objects.extend(subnets[:subnet_count])  # Allocate the required subnets
            network = subnets[subnet_count - 1].supernet()  # Update the network to the supernet of the last allocated subnet
    return subnet_objects  # Return the list of allocated subnets

# Example usage
network = '192.168.0.0/24'  # Define the original network in CIDR notation
requirements = [
    {'subnet_mask': 26, 'subnet_count': 4},  # Request for 4 subnets of /26 each
    {'subnet_mask': 27, 'subnet_count': 8},  # Request for 8 subnets of /27 each
    {'subnet_mask': 28, 'subnet_count': 16}  # Request for 16 subnets of /28 each
]

subnet_objects = plan_networks(network, requirements)  # Plan the networks based on requirements
for subnet in subnet_objects:  # Print each allocated subnet
    print(subnet)

""" Output
192.168.0.0/26
192.168.0.64/26
192.168.0.128/26
192.168.0.192/26

192.168.0.0/27
192.168.0.32/27
192.168.0.64/27
192.168.0.96/27
192.168.0.128/27
192.168.0.160/27
192.168.0.192/27
192.168.0.224/27

192.168.0.0/28
192.168.0.16/28
192.168.0.32/28
192.168.0.48/28
192.168.0.64/28
192.168.0.80/28
192.168.0.96/28
192.168.0.112/28
192.168.0.128/28
192.168.0.144/28
192.168.0.160/28
192.168.0.176/28
192.168.0.192/28
192.168.0.208/28
192.168.0.224/28
192.168.0.240/28
"""
# -----------------------------------------------------------------------------------------------------------------------
""" 
The following code snippet demonstrates how to subnet a given IPv4 network into smaller subnets based on a specified number of host bits. 
This functionality is useful for network planning and management, allowing administrators to create subnets that can accommodate a certain number of 
hosts."""
import ipaddress
def subnet_network(network, host_bits):
    network = ipaddress.ip_network(network)
    subnets = list(network.subnets(new_prefix=network.prefixlen + host_bits))
    return subnets

network = '172.16.0.0/22'  # Define the original network
host_bits = 10  # Define the number of host bits

subnets = subnet_network(network, host_bits)  # Generate the subnets
for subnet in subnets:  # Print each generated subnet
    print(subnet)

"""  Output
172.16.0.0/32
172.16.0.1/32
172.16.0.2/32
...
172.16.3.255/32

Scenario: Splitting a Network for Different Departments

Context: A medium-sized organization has a network 172.16.0.0/22 that needs to be divided into smaller subnets for different departments, 
such as IT, HR, and Sales. Each department has a specific requirement for the number of devices (hosts).

    Initial Network Setup:
        The organization starts with a single network block (172.16.0.0/22), allowing for 1024 IP addresses.

    Departmental Needs:
        The IT department requires 100 devices.
        The HR department requires 50 devices.
        The Sales department requires 30 devices.

    Subnetting:
        The organization decides to allocate subnets based on the number of host bits required for each department. By using the function:
            For IT (100 devices), they might choose to allocate a subnet with a prefix that allows for at least 128 addresses (e.g., /25).
            For HR (50 devices), they might allocate a /26.
            For Sales (30 devices), they might allocate a /27.

    Implementation:
        Using the provided code, the IT department could call the function with a suitable prefix length to generate their subnet, and similarly 
        for HR and Sales.
        This ensures efficient IP address usage and simplifies network management.

    Network Security and Segmentation:
        By splitting the network into subnets, the organization improves security by isolating departments from each other, allowing for better 
        traffic management and enhanced security policies.

"""
# ------------------------------------------------------------------------------------------------------------------------

""" 
The following code snippet demonstrates how to implement Variable Length Subnet Masking (VLSM) using Python's ipaddress module. VLSM allows network 
administrators to create subnets of different sizes within a single network, optimizing the use of IP addresses based on specific requirements."""
import ipaddress
def vlsm(network, subnets):
    network = ipaddress.ip_network(network)
    subnets.sort(reverse=True)
    subnet_objects = []
    for subnet in subnets:
        subnet_objects.append(network.subnets(new_prefix=subnet))
        network = next(network.subnets(new_prefix=subnet))
    return subnet_objects

# Take a network in CIDR notation and a list of subnet masks (prefix lengths)
network = '192.168.0.0/24'
subnets = [28,] # 27, 26

subnet_objects = vlsm(network, subnets)
for subnet in subnet_objects:
    for sub in subnet:
        print(sub)
    print('---')
""" Output
192.168.0.0/28
192.168.0.16/28
192.168.0.32/28
192.168.0.48/28
192.168.0.64/28
192.168.0.80/28
192.168.0.96/28
192.168.0.112/28
192.168.0.128/28
192.168.0.144/28
192.168.0.160/28
192.168.0.176/28
192.168.0.192/28
192.168.0.208/28
192.168.0.224/28
192.168.0.240/28
---
Context: Designing a Network for a Company

Scenario: A company has been allocated a network block of 192.168.0.0/24 and needs to divide it into smaller subnets for different departments: 
IT, HR, and Sales. Each department has different requirements for the number of devices (hosts).

    Departmental Needs:
        IT Department: Requires 50 devices.
        HR Department: Requires 20 devices.
        Sales Department: Requires 10 devices.

    Subnetting with VLSM:
        The company decides to allocate subnets based on the number of hosts required:
            IT: Needs a subnet that supports at least 50 devices, which could be a /26 (64 addresses).
            HR: Needs a subnet that supports at least 20 devices, which could be a /27 (32 addresses).
            Sales: Needs a subnet that supports at least 10 devices, which could be a /28 (16 addresses).

    Implementing VLSM:
        Using the provided code, the network administrator can call the vlsm function with the appropriate subnet masks for each department, ensuring 
        efficient use of the available IP address space.

    Benefits:
        Efficient Address Utilization: By allocating subnets based on actual requirements, the organization minimizes wasted IP addresses.
        Enhanced Security: Each department can be isolated in its own subnet, allowing for tailored security policies and traffic management.
        Future Scalability: The design can accommodate growth; for example, if the IT department needs more addresses, a larger subnet can be allocated 
        from the remaining address space.
"""
# ------------------------------------------------------------------------------------------------------------------------
""" 
How to generate link-local addresses (LLA) for IPv6 using a specified prefix and unique interface identifiers. 
Link-local addresses are used in local network segments and are crucial for network communication on the same local link.
"""
import ipaddress
import random

def generate_dynamic_lla(interface_ids):
    lla_prefix = ipaddress.IPv6Network("fe80::/10")
    lla_addresses = []
    for interface_id in interface_ids:
        lla_address = str(lla_prefix.network_address + int(interface_id))
        lla_addresses.append(lla_address)
    
    return lla_addresses

# Example usage
interface_ids = ['1', '2', '3', '4', '5']

dynamic_lla_addresses = generate_dynamic_lla(interface_ids)
for address in dynamic_lla_addresses:
    print(address)
""" 
Scenario: Automatic Configuration of Devices in a Local Network

Context: In a local area network (LAN) where multiple devices (such as computers, printers, and IoT devices) need to communicate 
without requiring a centralized configuration server, link-local addresses are essential.

    Device Setup:
        Each device in the network is assigned a unique interface identifier, which could be based on hardware characteristics (like MAC addresses) 
        or simply incremented numbers.

    Dynamic Address Generation:
        Using the generate_dynamic_lla function, network administrators can automatically generate link-local addresses for each interface as devices 
        boot up or connect to the network.

    Local Communication:
        Once configured with link-local addresses, devices can communicate directly with each other without needing global addresses or additional 
        routing configurations. This is particularly useful for:
            Device Discovery: Devices can discover each other on the network, which is essential for services like printing or file sharing.
            IoT Applications: Many IoT devices use link-local addresses for direct communication, allowing them to form a local mesh network without 
            complex setups.

    Network Resilience:
        Link-local addresses provide a level of resilience; even if a global address is not available (e.g., during DHCP failures), devices can still 
        communicate over the local network.
"""
