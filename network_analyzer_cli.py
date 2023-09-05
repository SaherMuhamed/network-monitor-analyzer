import sys
import socket
import threading
from colorama import Fore
import scapy.all as scapy

packets_counter = 0

def packet_sniffer(interface):
    try:
        print("\n(+) Starting packet sniffer on interface " + interface)
        print("================================================================================\n")
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except KeyboardInterrupt:
        print("(+) Stopping packet sniffer")
        sys.exit(0)
    except Exception as e:
        print("(-) An error occurred: " + str(e))

def resolve_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except socket.herror:
        return ip_address
    
def process_packet(packet):
    global packets_counter
    try:
        if packet.haslayer(scapy.TCP):
            tcp_packet = packet[scapy.TCP]
            tcp_length = len(tcp_packet)
            tcp_src_port = tcp_packet.sport
            tcp_dst_port = tcp_packet.dport
            tcp_src_host = packet[scapy.IP].src
            tcp_dst_host = packet[scapy.IP].dst
            packets_counter += 1
            # src_host = resolve_hostname(packet[scapy.IP].src)
            # dst_host = resolve_hostname(packet[scapy.IP].dst)
            print(Fore.LIGHTGREEN_EX + f"{packets_counter}:: TCP - Source: {tcp_src_host}:{tcp_src_port} - Destination: {tcp_dst_host}:{tcp_dst_port} - Length: {tcp_length} Bytes")

            if tcp_dst_port == 80 or tcp_src_port == 80:
                print(Fore.LIGHTGREEN_EX + f"{packets_counter}:: HTTP - Source: {tcp_src_host}:{tcp_src_port} - Destination: {tcp_dst_host}:{tcp_dst_port} - Length: {tcp_length} Bytes")

        if packet.haslayer(scapy.UDP):
            udp_packet = packet[scapy.UDP]
            udp_length = len(udp_packet)
            udp_src_host = packet[scapy.IP].src
            udp_dst_host = packet[scapy.IP].dst
            udp_src_port = udp_packet.sport
            udp_dst_port = udp_packet.dport
            packets_counter += 1
            print(Fore.LIGHTBLUE_EX + f"{packets_counter}:: UDP - Source: {udp_src_host}:{udp_src_port} - Destination: {udp_dst_host}:{udp_dst_port} - Length: {udp_length} Bytes")

        if packet.haslayer(scapy.ARP):
            arp_packet = packet[scapy.ARP]
            arp_length = len(arp_packet)
            arp_src_ip = arp_packet.psrc
            arp_dst_ip = arp_packet.pdst
            packets_counter += 1
            print(Fore.LIGHTRED_EX + f"{packets_counter}:: ARP - Source: {arp_src_ip} - Destination: {arp_dst_ip} - Length: {arp_length} Bytes")

        if packet.haslayer(scapy.ICMP):
            icmp_packet = packet[scapy.ICMP]
            icmp_length = len(icmp_packet)
            icmp_type = icmp_packet.type
            icmp_code = icmp_packet.code
            packets_counter += 1
            print(Fore.LIGHTMAGENTA_EX + f"{packets_counter}:: ICMP - Type: {icmp_type} - Code: {icmp_code}:{udp_dst_port} - Length: {icmp_length} Bytes")
        
    except Exception as e:
        pass
        # print("(-) An error occurred while processing a packet: " + str(e))
if __name__ == "__main__":
    # interface = input("Enter the interface (e.g., eth0): ")
    packet_sniffer(interface="Realtek RTL8822BE 802.11ac PCIe Adapter")  # specifiy your network adapter here
