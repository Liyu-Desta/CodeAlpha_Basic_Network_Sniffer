from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import argparse
import sys

def list_interfaces():
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for iface in interfaces:
        print(f"- {iface}")

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[*] Protocol: TCP")
            print(f"[*] Source Port: {tcp_layer.sport}")
            print(f"[*] Destination Port: {tcp_layer.dport}")
            print(f"[*] Flags: {tcp_layer.flags}")

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[*] Protocol: UDP")
            print(f"[*] Source Port: {udp_layer.sport}")
            print(f"[*] Destination Port: {udp_layer.dport}")

        # Check for ICMP packets
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"[*] Protocol: ICMP")
            print(f"[*] Type: {icmp_layer.type}")
            print(f"[*] Code: {icmp_layer.code}")
        
        # Display Raw Data (Payload)
        if packet.haslayer(IP):
            payload = packet[IP].payload
            if payload:
                print(f"[*] Payload: {payload}")

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer in Python using Scapy")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on", required=False)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture", default=0)
    parser.add_argument("-f", "--filter", type=str, help="BPF filter to apply", default="")
    parser.add_argument("-l", "--list", action='store_true', help="List all available network interfaces")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    if not args.interface:
        print("[-] No interface specified. Use -l to list available interfaces.")
        sys.exit(1)

    print(f"[*] Starting packet capture on interface: {args.interface}")
    print(f"[*] Packet count: {args.count if args.count > 0 else 'Infinite'}")
    print(f"[*] BPF Filter: {args.filter if args.filter else 'None'}")

    try:
        sniff(
            iface=args.interface,
            prn=packet_callback,
            count=args.count,
            filter=args.filter,
            store=False
        )
    except PermissionError:
        print("[-] Permission denied: You need to run this script with elevated privileges.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
