import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import PacketSniffer
import netifaces

class FilterPacketsGUI:
    def __init__(self, main_app):
        self.main_app = main_app
        self.filter_window = tk.Toplevel(main_app.master)
        self.filter_window.title("Filtered Packet Sniffer")

        # Frame for Filter Criteria
        frame_filters = ttk.Frame(self.filter_window)
        frame_filters.pack(pady=10)

        # Protocol Filter
        ttk.Label(frame_filters, text="Filter Protocol:").grid(row=0, column=0, sticky=tk.W)
        self.protocol_entry = ttk.Entry(frame_filters, width=15)
        self.protocol_entry.grid(row=0, column=1, padx=5)

        # Source IP Filter
        ttk.Label(frame_filters, text="Filter Source IP:").grid(row=1, column=0, sticky=tk.W)
        self.src_ip_entry = ttk.Entry(frame_filters, width=15)
        self.src_ip_entry.grid(row=1, column=1, padx=5)

        # Destination IP Filter
        ttk.Label(frame_filters, text="Filter Destination IP:").grid(row=2, column=0, sticky=tk.W)
        self.dest_ip_entry = ttk.Entry(frame_filters, width=15)
        self.dest_ip_entry.grid(row=2, column=1, padx=5)

        # Version Filter
        ttk.Label(frame_filters, text="Filter Version:").grid(row=3, column=0, sticky=tk.W)
        self.version_entry = ttk.Entry(frame_filters, width=15)
        self.version_entry.grid(row=3, column=1, padx=5)

        # Header Length Filter
        ttk.Label(frame_filters, text="Filter Header Length:").grid(row=4, column=0, sticky=tk.W)
        self.header_length_entry = ttk.Entry(frame_filters, width=15)
        self.header_length_entry.grid(row=4, column=1, padx=5)

        # TTL Filter
        ttk.Label(frame_filters, text="Filter TTL:").grid(row=5, column=0, sticky=tk.W)
        self.ttl_entry = ttk.Entry(frame_filters, width=15)
        self.ttl_entry.grid(row=5, column=1, padx=5)

         # ACK Filter
        ttk.Label(frame_filters, text="Filter ACK:").grid(row=5, column=0, sticky=tk.W)
        self.ack_entry = ttk.Entry(frame_filters, width=15)
        self.ack_entry.grid(row=5, column=1, padx=5)


        # SYN Filter
        ttk.Label(frame_filters, text="Filter SYN:").grid(row=5, column=0, sticky=tk.W)
        self.syn_entry = ttk.Entry(frame_filters, width=15)
        self.syn_entry.grid(row=5, column=1, padx=5)
        

        # Offset Filter
        ttk.Label(frame_filters, text="Filter Offset:").grid(row=8, column=0, sticky=tk.W)
        self.offset_entry = ttk.Entry(frame_filters, width=15)
        self.offset_entry.grid(row=8, column=1, padx=5)

        # Port Protocol Filter
        ttk.Label(frame_filters, text="Filter Port Protocol:").grid(row=9, column=0, sticky=tk.W)
        self.port_protocol_entry = ttk.Entry(frame_filters, width=15)
        self.port_protocol_entry.grid(row=9, column=1, padx=5)

        # Src Port Filter
        ttk.Label(frame_filters, text="Filter Src Port:").grid(row=10, column=0, sticky=tk.W)
        self.src_port_entry = ttk.Entry(frame_filters, width=15)
        self.src_port_entry.grid(row=10, column=1, padx=5)

        # Dest Port Filter
        ttk.Label(frame_filters, text="Filter Dest Port:").grid(row=11, column=0, sticky=tk.W)
        self.dest_port_entry = ttk.Entry(frame_filters, width=15)
        self.dest_port_entry.grid(row=11, column=1, padx=5)

        # Button to apply filter
        self.apply_filter_button = ttk.Button(frame_filters, text="Apply Filter", command=self.apply_filter)
        self.apply_filter_button.grid(row=12, columnspan=2, pady=10)

    def apply_filter(self):
        protocol_filter = self.protocol_entry.get().lower()
        src_ip_filter = self.src_ip_entry.get().lower()
        dest_ip_filter = self.dest_ip_entry.get().lower()
        version_filter = self.version_entry.get().lower()
        header_length_filter = self.header_length_entry.get().lower()
        ttl_filter = self.ttl_entry.get().lower()
        ack_filter = self.ack_entry.get().lower()
        syn_filter = self.syn_entry.get().lower()
        offset_filter = self.offset_entry.get().lower()
        port_protocol_filter = self.port_protocol_entry.get().lower()
        src_port_filter = self.src_port_entry.get().lower()
        dest_port_filter = self.dest_port_entry.get().lower()

        self.main_app.set_filters(protocol_filter, src_ip_filter, dest_ip_filter, 
                                  version_filter, header_length_filter, ttl_filter, offset_filter,
                                  ack_filter, syn_filter, 
                                  port_protocol_filter, src_port_filter, dest_port_filter)

def main():
    global main_app
    root = tk.Tk()
    main_app = FilterPacketsGUI(root)
    root.mainloop()

if __name__ == "__main__":
        main()
