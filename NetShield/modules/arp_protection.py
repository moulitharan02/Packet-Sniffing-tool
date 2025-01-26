from scapy.all import ARP, sniff, send
from collections import defaultdict

def restore_arp(ip, mac, gateway_ip, gateway_mac):
    packet = ARP(op=2, pdst=ip, hwdst=mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, verbose=False)

def detect_arp_spoofing():
    print("[*] Monitoring ARP table for spoofing attacks...")
    known_mappings = defaultdict(str)
    
    def arp_monitor(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            sender_ip = packet[ARP].psrc
            sender_mac = packet[ARP].hwsrc
            
            if known_mappings[sender_ip] and known_mappings[sender_ip] != sender_mac:
                print(f"[ALERT] ARP Spoofing detected! IP: {sender_ip} is being spoofed.")
            else:
                known_mappings[sender_ip] = sender_mac

    sniff(filter="arp", prn=arp_monitor, store=False)
