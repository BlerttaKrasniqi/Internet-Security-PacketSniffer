import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import PacketSniffer
import netifaces


class PacketDetails:
    def __init__(self, master, packet_info, raw_data):
        self.details_window = tk.Toplevel(master)
        self.details_window.title("Packet Details")

        columns = ("Field", "Value")
        self.details_tree = ttk.Treeview(self.details_window, columns=columns, show="headings")

        for col in columns:
            self.details_tree.heading(col, text=col)
            self.details_tree.column(col, width=200)

        self.details_tree.pack(fill=tk.BOTH, expand=True)

        # Parsing packet_info into a more detailed format
        packet_details = self.parse_packet_details(packet_info, raw_data)

        for detail in packet_details:
            self.details_tree.insert("", tk.END, values=detail)

    def parse_packet_details(self, packet_info, raw_data):
        details = []
        ip_header = [
            ("Version", packet_info[0]),
            ("Header Length", packet_info[1]),
            ("TTL", packet_info[2]),
            ("Protocol", packet_info[3]),
            ("Source IP", packet_info[4]),
            ("Destination IP", packet_info[5])
        ]

        tcp_header = [
            ("ACK", packet_info[6]),
            ("SEQ", packet_info[7]),
            ("Flags", packet_info[8]),
            ("Port Protocol", packet_info[9]),
            ("Source Port", packet_info[10]),
            ("Destination Port", packet_info[11])
        ]

        details.append(("IP Header", ""))
        details.extend(ip_header)

        details.append(("TCP Header", ""))
        details.extend(tcp_header)

        details.append(("Raw Data", raw_data))

        self.raw_data_text = scrolledtext.ScrolledText(self.details_window, wrap=tk.WORD, height=10)
        self.raw_data_text.insert(tk.END, raw_data)
        self.raw_data_text.config(state=tk.DISABLED)
        self.raw_data_text.pack(fill=tk.BOTH, expand=True)

        return details


if __name__ == "__main__":
    root = tk.Tk()
    gui = PacketDetails(root)
    root.mainloop()
