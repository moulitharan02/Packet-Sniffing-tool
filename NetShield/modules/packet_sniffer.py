from scapy.all import sniff, wrpcap
import datetime

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(interface):
    print(f"[*] Starting packet capture on {interface}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"logs/capture_{timestamp}.pcap"
    
    packets = sniff(iface=interface, prn=packet_callback, store=True)
    wrpcap(pcap_file, packets)
    print(f"[*] Packets saved to {pcap_file}")
