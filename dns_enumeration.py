""" 
The following code snippet performs DNS lookups for various record types (A, AAAA, CNAME, MX, NS, SOA, TXT) 
for a specified domain using the dnspython library. It then prints the results for each record type.

run $ pip install dnspython first on the terminal
"""
import dns.resolver

# Set the target domain and record types
target_domain = "thepythoncode.com"
record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

# Create a DNS resolver
resolver = dns.resolver.Resolver()

for record_type in record_types:
    # Perform DNS lookup for the specified domain and record type
    try:
        answers = resolver.resolve(target_domain, record_type)
        # Print the answers
        print(f"{record_type} records for {target_domain}:")
        for rdata in answers:
            print(f" - {rdata}")
    except dns.resolver.NoAnswer:
        print(f"No {record_type} records found for {target_domain}.")
    except dns.resolver.LifetimeTimeout:
        print(f"Timeout while resolving {record_type} records for {target_domain}.")
    except Exception as e:
        print(f"Error resolving {record_type} records for {target_domain}: {e}")

""""
to execute above code run the following in terminal
$ python dns_enumeration.py

Output:

DNS records for thepythoncode.com (A):
99.81.207.218
52.19.6.38    
34.247.123.251

DNS records for thepythoncode.com (MX):
0 thepythoncode-com.mail.protection.outlook.com.

DNS records for thepythoncode.com (NS):
sparrow.ezoicns.com.
siamese.ezoicns.com.
giraffe.ezoicns.com.
manatee.ezoicns.com.

DNS records for thepythoncode.com (SOA):
giraffe.ezoicns.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

DNS records for thepythoncode.com (TXT):
"v=spf1 include:spf.protection.outlook.com -all"
"NETORGFT5410317.onmicrosoft.com"
"google-site-verification=yJTOgIk39vl3779N3QhPF-mAR36QE00J6LdXHeID4fM"
""""
# --------------------------------------------------------------------------------------------------------------------------------
# example 1
#  In this example, the resolve_dns() function takes a hostname as input and attempts to resolve its IP address using socket.
# gethostbyname(). If the resolution is successful, it returns the IP address. Otherwise, it returns None.
# You can replace www.example.com in the example with the hostname you want to resolve, and the code will output the IP address 
# if it is resolved successfully. Otherwise, it will indicate that the resolution failed.
import socket

def resolve_dns(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

# Example usage
hostname = "www.example.com"
ip_address = resolve_dns(hostname)
if ip_address:
    print(f"The IP address of {hostname} is {ip_address}")
else:
    print(f"Failed to resolve the IP address for {hostname}")
