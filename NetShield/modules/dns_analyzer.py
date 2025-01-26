from scapy.all import sniff, DNS, DNSQR

def analyze_dns():
    print("[*] Monitoring DNS queries...")
    
    def dns_callback(packet):
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            print(f"[DNS Query] {packet[DNSQR].qname.decode()} from {packet[IP].src}")

    sniff(filter="udp port 53", prn=dns_callback, store=False)
