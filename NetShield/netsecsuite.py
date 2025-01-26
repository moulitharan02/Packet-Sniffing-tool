import argparse
from modules import packet_sniffer, ids, arp_protection, port_scanner, dns_analyzer, visualizer

def main_menu():
    print("""
██╗  ██╗██████╗ ██╗███████╗██╗  ██╗
██║ ██╔╝██╔══██╗██║██╔════╝██║  ██║
█████╔╝ ██████╔╝██║███████╗███████║
██╔═██╗ ██╔══██╗██║╚════██║██╔══██║
██║  ██╗██║  ██║██║███████║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
    """)
    print("Welcome to NetShield - Comprehensive Network Security Toolkit")
    print("-----------------------------------------------------------")

def main():

    main_menu()

    parser = argparse.ArgumentParser(
        description="NetShield - Comprehensive Network Security Toolkit",
        epilog="For detailed usage, use --help."
    )
    

    parser.add_argument("-s", "--sniff", action="store_true", help="Start packet sniffer")
    parser.add_argument("-i", "--interface", type=str, help="Specify the network interface (e.g., eth0, wlan0)")
    
    parser.add_argument("-a", "--detect-arp", action="store_true", help="Detect and mitigate ARP spoofing attacks")
    
    parser.add_argument("-p", "--scan", action="store_true", help="Perform a port scan")
    parser.add_argument("-t", "--target", type=str, help="Specify the target IP for port scanning")
    
    parser.add_argument("-d", "--ids", action="store_true", help="Start intrusion detection system")
    
    parser.add_argument("-n", "--analyze-dns", action="store_true", help="Analyze DNS traffic")
    
    parser.add_argument("-v", "--visualize", action="store_true", help="Visualize traffic data")
    

    args = parser.parse_args()
    
    # Option execution
    if args.sniff and args.interface:
        packet_sniffer.start_sniffing(args.interface)
    elif args.detect_arp:
        arp_protection.detect_arp_spoofing()
    elif args.scan and args.target:
        port_scanner.scan_ports(args.target)
    elif args.ids:
        ids.start_ids()
    elif args.analyze_dns:
        dns_analyzer.analyze_dns()
    elif args.visualize:
        visualizer.visualize_traffic()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

