from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Unknown"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        print(f"{datetime.now()} - {protocol} Packet")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Payload: {bytes(packet[IP].payload)}\n")


def start_sniffing(interface):
    print(f"Starting packet sniffer on {interface}...\n")
    sniff(iface=interface, prn=packet_callback, store=False)


if __name__ == "__main__":
    interface = input("Enter the interface to sniff on: ")
    start_sniffing(interface)
