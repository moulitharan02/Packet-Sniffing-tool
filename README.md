
---

```markdown
# NetShield

NetShield is a versatile **network security toolkit** for **Kali Linux**. It combines packet sniffing, ARP protection, DNS analysis, intrusion detection, port scanning, and traffic visualization, offering network administrators and security researchers a comprehensive way to monitor and secure networks.

---

## Features

- **Packet Sniffer**: Captures and logs live network packets.
- **ARP Protection**: Detects and prevents ARP spoofing attacks.
- **DNS Analyzer**: Monitors DNS queries for potential spoofing.
- **Intrusion Detection**: Identifies suspicious traffic patterns.
- **Port Scanner**: Scans open ports on target systems.
- **Traffic Visualizer**: Graphical representation of network activity.
- **Logs and Alerts**: Saves traffic and attack alerts for analysis.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/moulitharan02/NetShield.git
   cd NetShield
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   sudo python3 netsecsuite.py
   ```

---

## Usage

Start NetShield and select an option from the menu:

```bash
sudo python3 netsecsuite.py
```

Command-line options:
- `--sniff` - Start packet sniffer.
- `--scan <target>` - Perform a port scan.
- `--arp` - Enable ARP protection.
- `--dns` - Analyze DNS traffic.
- `--visualize` - Visualize network traffic.

Example:
```bash
sudo python3 netsecsuite.py --scan 192.168.1.1
```

---

## Logs

- **Traffic Logs**: `logs/traffic.log` - Network traffic details.
- **Alerts Logs**: `logs/alerts.log` - Security alerts.

---

## License

NetShield is open-source and licensed under the **MIT License**.

---

## Disclaimer

NetShield is for educational and authorized security testing only. The authors are not liable for misuse of the tool.

---

## Contact

- GitHub: [moulitharan02](https://github.com/moulitharan02)
```

---
