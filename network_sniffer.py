from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process captured packets
def packet_handler(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check for TCP packets
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")

        # Check for UDP packets
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")

        # Check for raw payload
        if packet.haslayer(Raw):
            raw_data = packet.getlayer(Raw).load
            print(f"Raw Data: {raw_data}")

# Start sniffing on the network interface (e.g., 'eth0' or 'wlan0')
print("Starting network sniffer...")
sniff(prn=packet_handler, count=0)  # count=0 means it will run indefinitely
