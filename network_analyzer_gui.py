import time
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import *
import scapy.all as scapy

class NetworkAnalyzer:
    def __init__(self, interface):
        self.interface = interface
        self.packets_counter = 0   # adding a packet counter to count how many packets got captured
        self.root = tk.Tk()
        self.root.title("Network Monitor & Analyzer")   # adding program title
        self.root.iconbitmap("./assets/circle.ico")   # adding a window icon to the program
        self.root.state('zoomed')   # maximize the window when the program runs

        self.setup_gui()

    def setup_gui(self):
        self.tree = ttk.Treeview(self.root, columns=("Packet No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        self.tree.heading("#1", text="Packet No.", anchor="w")
        self.tree.heading("#2", text="Time", anchor="w")
        self.tree.heading("#3", text="Source", anchor="w")
        self.tree.heading("#4", text="Destination", anchor="w")
        self.tree.heading("#5", text="Protocol", anchor="center")
        self.tree.heading("#6", text="Length", anchor="w")
        self.tree.heading("#7", text="Info", anchor="w")

        for col in self.tree['columns']:
            self.tree.column(col, anchor="center")  # center the text inside columns

        # here I adjusted a specific columns as needed
        self.tree.column("#1", width=110)
        self.tree.column("#2", width=110)
        self.tree.column("#5", width=105)
        self.tree.column("#6", width=150)

        self.tree.tag_configure("TCP", background="#C8E4B2")
        self.tree.tag_configure("UDP", background="lightblue")
        self.tree.tag_configure("ARP", background="#FF6969")
        self.tree.tag_configure("ICMP", background="#A084E8")
        self.tree.tag_configure("HTTP", background="#5D9C59")
        self.tree.tag_configure("CORRUPTED_TCP", background="#001C30", foreground="#E966A0")

        # adding a vertical scrollbar
        self.vertical_scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.vertical_scrollbar.pack(side="right", fill="y")

        # adding a horizontal scrollbar if needed
        self.horizontal_scrollbar = ttk.Scrollbar(self.root, orient="horizontal", command=self.tree.xview)
        self.horizontal_scrollbar.pack(side="bottom", fill="x")

        # configure the Treeview to use the scrollbars
        self.tree.configure(yscrollcommand=self.vertical_scrollbar.set, xscrollcommand=self.horizontal_scrollbar.set)

        style = ttk.Style()
        style.configure("Treeview", font=("Cascadia Code", 11), rowheight=21)
        style.configure("Treeview.Heading", font=("Consolas", 16), foreground="#9400FF")

        self.tree.pack(expand=tk.YES, fill=tk.BOTH)   # pack all gui
        self.start_sniffer_thread()

    def start_sniffer_thread(self):
        sniffer_thread = threading.Thread(target=self.packet_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()

    def packet_sniffer(self):
        try:
            # print("(+) Starting packet sniffer on interface " + self.interface + "\n")
            scapy.sniff(iface=self.interface, store=False, prn=lambda pkt: self.process_packet(pkt))
        except Exception as e:
            pass
            # print("(-) An error occurred: " + str(e))

    def process_packet(self, packet):
        capture_time = time.strftime("%I:%M:%S %p")
        try:
            if packet.haslayer(scapy.TCP):
                tcp_packet = packet[scapy.TCP]
                tcp_length = len(tcp_packet)
                tcp_src_port = tcp_packet.sport
                tcp_dst_port = tcp_packet.dport
                self.packets_counter += 1
                tcp_src_host = packet[scapy.IP].src
                tcp_dst_host = packet[scapy.IP].dst
                data = (f"{self.packets_counter}", capture_time, f"{tcp_src_host}:{tcp_src_port}", f"{tcp_dst_host}:{tcp_dst_port}", "TCP", f"{tcp_length} bytes", tcp_packet.summary())
                self.tree.insert("", "end", values=data, tags=("TCP",))

                if tcp_dst_port == 80 or tcp_src_port == 80:
                    self.packets_counter += 1
                    http_data = (f"{self.packets_counter}", capture_time, f"{tcp_src_host}:{tcp_src_port}", f"{tcp_dst_host}:{tcp_dst_port}", "HTTP", f"{tcp_length} bytes", str(tcp_packet[scapy.Raw].load))
                    self.tree.insert("", "end", values=http_data, tags=("HTTP",))

            if packet.haslayer(scapy.UDP):
                udp_packet = packet[scapy.UDP]
                udp_length = len(udp_packet)
                udp_src_host = packet[scapy.IP].src
                udp_dst_host = packet[scapy.IP].dst
                udp_src_port = udp_packet.sport
                udp_dst_port = udp_packet.dport
                self.packets_counter += 1
                data = (f"{self.packets_counter}", capture_time, f"{udp_src_host}:{udp_src_port}", f"{udp_dst_host}:{udp_dst_port}", "UDP", f"{udp_length} bytes", udp_packet.summary())
                self.tree.insert("", "end", values=data, tags=("UDP",))

            if packet.haslayer(scapy.ARP):
                arp_packet = packet[scapy.ARP]
                arp_length = len(arp_packet)
                arp_src_ip = arp_packet.psrc
                arp_dst_ip = arp_packet.pdst
                self.packets_counter += 1
                data = (f"{self.packets_counter}", capture_time, f"{arp_src_ip}", f"{arp_dst_ip}", "ARP", f"{arp_length} bytes", arp_packet.summary())
                self.tree.insert("", "end", values=data, tags=("ARP",))

            if packet.haslayer(scapy.ICMP):
                icmp_packet = packet[scapy.ICMP]
                icmp_length = len(icmp_packet)
                icmp_type = icmp_packet.type
                icmp_code = icmp_packet.code
                self.packets_counter += 1
                data = (f"{self.packets_counter}", capture_time, f"{icmp_type}", f"{icmp_code}", "ICMP", f"{icmp_length} bytes", icmp_packet.summary())
                self.tree.insert("", "end", values=data, tags=("ICMP",))

        except Exception as e:
            # print("(-) An error occurred while processing a packet: " + str(e))
            pass

    def run(self):
        self.root.mainloop()
