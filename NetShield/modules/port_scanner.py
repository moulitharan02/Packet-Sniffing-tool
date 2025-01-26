import socket

def scan_ports(target):
    print(f"[*] Scanning ports on {target}...")
    open_ports = []
    
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        if sock.connect_ex((target, port)) == 0:
            print(f"[+] Port {port} is open")
            open_ports.append(port)
        sock.close()
    
    print(f"[*] Scan complete. Open ports: {open_ports}")
