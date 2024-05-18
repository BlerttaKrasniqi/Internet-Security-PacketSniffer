import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import PacketSniffer
import netifaces
import FilterPacketsGUI
import PacketDetails

class PacketSnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")
        
        
        # Frame for Network Interfaces
        frame_interfaces = ttk.Frame(master)
        frame_interfaces.pack(pady=10)
        

        ttk.Label(frame_interfaces, text="Select Network Interface:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(frame_interfaces, values=netifaces.interfaces(), width=50)
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        # Frame for Control Buttons
        frame_controls = ttk.Frame(master)
        frame_controls.pack(pady=10)

        self.start_button = ttk.Button(frame_controls, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(frame_controls, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        self.filter_button = ttk.Button(frame_controls, text="Filter", command=self.open_filter_window)
        self.filter_button.pack(side=tk.LEFT, padx=5)

        # Adding an Unfilter button
        self.unfilter_button = ttk.Button(frame_controls, text="Unfilter", command=self.unfilter_packets)
        self.unfilter_button.pack(side=tk.LEFT, padx=5)

        # Adding a Clear button
        self.clear_button = ttk.Button(frame_controls, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        

        # ScrolledText widget for displaying packets
        columns = ("Version", "Header Length", "TTL", "Protocol", "Src IP", "Dest IP", "ACK", "SEQ", "Flags", "Port Protocol", "Src Port", "Dest Port","Data")
        self.packet_tree = ttk.Treeview(master, columns=columns, show="headings", selectmode="extended")
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=80)
        self.packet_tree.heading("Version", text="Version")
        self.packet_tree.heading("Header Length", text="Header Length")
        self.packet_tree.heading("TTL", text="TTL")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Src IP", text="Src IP")
        self.packet_tree.heading("Dest IP", text="Dest IP")
        self.packet_tree.heading("ACK", text="ACK")
        self.packet_tree.heading("SEQ", text="SEQ")
        self.packet_tree.heading("Flags", text="Flags")
        self.packet_tree.heading("Port Protocol", text="Port Protocol")
        self.packet_tree.heading("Src Port", text="Src Port")
        self.packet_tree.heading("Dest Port", text="Dest Port")
        self.packet_tree.heading("Data", text="Data")
        self.packet_tree.pack(pady=10)

        # Adding a vertical scrollbar
        self.scrollbar = ttk.Scrollbar(master, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=self.scrollbar.set)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.LEFT, fill=tk.Y)
  

        self.stop_event = threading.Event()

        # Thread control
        self.sniffer_thread = None

        # Initialize storage for all packets
        self.all_packets = []

        self.protocol_filter = ""
        self.src_ip_filter = ""
        self.dest_ip_filter = ""
        self.version_filter = ""
        self.header_length_filter = ""
        self.ttl_filter = ""
        self.ack_filter = ""
        self.seq_filter = ""
        self.flags_filter = ""
        self.port_protocol_filter = ""
        self.src_port_filter = ""
        self.dest_port_filter = ""
        self.data_filter = None

        self.packet_tree.bind("<Double-1>", self.show_packet_details)

    

    def start_sniffing(self):
        interface = self.interface_combo.get()
        if interface:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.sniffer_thread = threading.Thread(target=self.run_sniffer, args=(interface,))
            self.sniffer_thread.start()

    def run_sniffer(self, interface):
        try:
            PacketSniffer.main(interface, self.update_display, stop_event=self.stop_event)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.stop_event.set()  # Set the event to signal the sniffing thread to stop
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def open_filter_window(self):
        FilterPacketsGUI.FilterPacketsGUI(self)
    
    def set_filters(self, protocol_filter, src_ip_filter, dest_ip_filter, 
                    version_filter, header_length_filter,ttl_filter,
                    ack_filter,seq_filter,flags_filter,
                    port_protocol_filter,src_port_filter,dest_port_filter):
        self.protocol_filter = protocol_filter.lower()
        self.src_ip_filter = src_ip_filter.lower()
        self.dest_ip_filter = dest_ip_filter.lower()
        self.version_filter = version_filter.lower()
        self.header_length_filter = header_length_filter.lower()
        self.ttl_filter = ttl_filter.lower()
        self.ack_filter = ack_filter.lower()
        self.seq_filter = seq_filter.lower()
        self.flags_filter = flags_filter.lower()
        self.port_protocol_filter = port_protocol_filter.lower()
        self.src_port_filter = src_port_filter.lower()
        self.dest_port_filter = dest_port_filter.lower()
        


        # Clear the current display
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # Re-apply the filters to all stored packets
        for packet in self.all_packets:
            packet_info = packet.split(", ")
            if self.apply_filters(packet_info):
                self.packet_tree.insert("", tk.END, values=packet_info)

    def apply_filters(self, packet_info, failed):
    # Extract packet information
     version = packet_info[0].lower()
     header_length = packet_info[1].lower()
     ttl = packet_info[2].lower()
     protocol = packet_info[3].lower()
     src_ip = packet_info[4].lower()
     dest_ip = packet_info[5].lower()
     ack = packet_info[6].lower()
     seq = packet_info[7].lower()
     flags = packet_info[8].lower()
     port_protocol = packet_info[9].lower()
     src_port = packet_info[10].lower()
     dest_port = packet_info[11].lower()
 
     # Check if any filter criteria match
     if (not self.version_filter or self.version_filter in version) and \
        (not self.header_length_filter or self.header_length_filter in header_length) and \
        (not self.ttl_filter or self.ttl_filter in ttl) and \
        (not self.protocol_filter or self.protocol_filter in protocol) and \
        (not self.src_ip_filter or self.src_ip_filter in src_ip) and \
        (not self.dest_ip_filter or self.dest_ip_filter in dest_ip) and \
        (not self.ack_filter or self.ack_filter in ack) and \
        (not self.seq_filter or self.seq_filter in seq) and \
        (not self.flags_filter or self.flags_filter in flags) and \
        (not self.port_protocol_filter or self.port_protocol_filter in port_protocol) and \
        (not self.src_port_filter or self.src_port_filter in src_port) and \
        (not self.dest_port_filter or self.dest_port_filter in dest_port):
         # Check if the packet failed and should be displayed
         if failed:
             return True
         else:
             return True  # Always display packets that pass other filters
     return False  # Filter out packets that don't match filter criteria or didn't fail

    
    def unfilter_packets(self):
        # Clear the filters
        self.protocol_filter = ""
        self.src_ip_filter = ""
        self.dest_ip_filter = ""
        self.version_filter = ""
        self.header_length_filter = ""
        self.ttl_filter = ""
        self.ack_filter = ""
        self.seq_filter = ""
        self.flags_filter = ""
        self.port_protocol_filter = ""
        self.src_port_filter = ""
        self.dest_port_filter = ""

        # Clear the current display
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # Display all stored packets
        for packet in self.all_packets:
            packet_info = packet.split(", ")
            self.packet_tree.insert("", tk.END, values=packet_info)
    
    def clear_packets(self):
        # Clear the displayed packets
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Clear the stored packets
        self.all_packets = []



    def update_display(self, packet_details, protocol_info):
      if packet_details and protocol_info:
            packet_data = f"{packet_details}, {protocol_info}"
            # Store all packets
            self.all_packets.append(packet_data)
            

            # Apply filters directly within update_display
            packet_info = packet_data.split(", ")
            if self.apply_filters(packet_info):
                # Update the GUI in the main thread
                self.master.after(0, self._insert_packet, packet_info)
    


    def show_packet_details(self, event):
        selected_item = self.packet_tree.selection()
        if selected_item:
            packet_info = self.packet_tree.item(selected_item, "values")
        # Extract the raw data based on the selected packet details
            raw_data = ""
            for packet in self.all_packets:
                packet_split = packet.split(", ", 12)
                if len(packet_split) > 12 and all(info in packet for info in packet_info):
                    raw_data = packet_split[12]
                    break
            PacketDetails.PacketDetails(self.master, packet_info, raw_data)

 
def main():
    root = tk.Tk()
    gui = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
  main()
