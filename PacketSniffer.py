#!/usr/bin/env python3
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

# Color codes for terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

# Logger
LOG_FILE = "packet_log.txt"

def log_packet(packet_info):
    """Save packet information to a log file."""
    with open(LOG_FILE, "a") as file:
        file.write(packet_info + "\n")

def analyze_packet(packet):
    """Analyze captured packet and return formatted information."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        proto_name = "Unknown"
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"

        payload = bytes(packet[IP].payload)[:50]  # Show first 50 bytes

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        info = (
            f"{Colors.BOLD}{Colors.CYAN}=== Packet Captured ==={Colors.RESET}\n"
            f"{Colors.YELLOW}Time:{Colors.RESET} {timestamp}\n"
            f"{Colors.GREEN}Source IP:{Colors.RESET} {ip_src}\n"
            f"{Colors.GREEN}Destination IP:{Colors.RESET} {ip_dst}\n"
            f"{Colors.BLUE}Protocol:{Colors.RESET} {proto_name} ({proto})\n"
            f"{Colors.RED}Payload:{Colors.RESET} {payload}\n"
        )

        print(info)
        log_packet(info)

def start_sniffer(interface=None):
    """Start sniffing packets."""
    print(f"{Colors.HEADER}[+] Starting packet sniffer... Press Ctrl+C to stop{Colors.RESET}")
    sniff(prn=analyze_packet, store=False, iface=interface)

if __name__ == "__main__":
    try:
        interface = None  # You can set interface like "eth0" if needed
        start_sniffer(interface)
    except PermissionError:
        print(f"{Colors.RED}[!] Permission denied. Run with sudo.{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}\n[!] Sniffing stopped by user.{Colors.RESET}")
