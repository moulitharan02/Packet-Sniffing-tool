from scapy.all import sniff, TCP, IP

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        print(f"[ALERT] SYN Flood detected from {packet[IP].src}:{packet[TCP].sport}")

def start_ids():
    print("[*] Starting Intrusion Detection System...")
    sniff(prn=detect_syn_flood, store=False)
