from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

LOG_FILE = "captured_packets.txt"

tcp_count = 0
UDP_count = 0
icmp_count = 0
other_count = 0

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"
        
        src_port = "-"
        dst_port = "-"
        if packet.haslayer(TCP):
         src_port = packet[TCP].sport
         dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
         src_port = packet[UDP].sport
         dst_port = packet[UDP].dport
        
        packet_length = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        global tcp_count, UDP_count, icmp_count, other_count
        if protocol == "TCP":
            tcp_count += 1
        elif protocol == "UDP":
            UDP_count += 1
        elif protocol == "ICMP":
            icmp_count += 1
        else:
            other_count += 1
        output = (
            f"\n{'='*60}\n"
            f"Time           : {timestamp}\n"
            f"Source IP      : {src_ip}\n"
            f"Destination IP : {dst_ip}\n"
            f"Protocol       : {protocol}\n"
            f"Packet Length  : {packet_length} bytes\n"
            f"Source Port    : {src_port}\n"
            f"Destination Port: {dst_port}\n"
            f"{'='*60}"
            )
        print(output)

        with open(LOG_FILE, "a") as file:
            file.write(output + "\n")

        
print("Starting Network Sniffer...")
print("Press Ctrl + C to stop the sniffer.\n")

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffer stopped.")
    print(f"Total TCP packets captured: {tcp_count}")
    print(f"Total UDP packets captured: {UDP_count}")
    print(f"Total ICMP packets captured: {icmp_count}")
    print(f"Total Other packets captured: {other_count}")
    print("="*40)



