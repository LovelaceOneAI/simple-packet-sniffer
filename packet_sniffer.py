from scapy.all import sniff, IP, TCP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] Packet: {ip_layer.src} → {ip_layer.dst}")
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    Protocol: TCP | Src Port: {tcp_layer.sport} → Dst Port: {tcp_layer.dport}")
        print("-" * 50)

# Start sniffing (may need sudo/admin)
print("[*] Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)

Add basic packet sniffer script using Scapy
