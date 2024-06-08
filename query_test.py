from scapy.all import *


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
    

def main():
    while True:
        send_dns_query("10.0.0.150", "www.instagram.com")
        

if __name__ == "__main__":
    main()
