# Packet Sniffer in Python
##### Course: _Internet Security_
##### Professor: _Mërgim Hoti_
##### _University of Prishtina "Hasan Prishtina"_
##### _Faculty of Electrical and Computer Engineering_
## Basic Overview
This project is a comprehensive packet sniffer implemented in Python for Windows systems. It captures and analyzes network packets, displaying detailed information about them. The packet sniffer features a GUI for ease of use, allowing users to start and stop packet sniffing, apply filters, and view packet details.

## Features
- **Capture Packets**: Sniffs network packets on the selected network interface.
- **Protocol Support**: Identifies and processes ICMP, TCP, and UDP packets.
- **Filtering**: Users can apply various filters to view specific packets based on criteria such as protocol, IP address, TTL, ports, and more.
- **GUI**: An intuitive graphical interface to control packet sniffing, view captured packets, and display detailed packet information.
- **Packet Details**: Displays comprehensive details of the captured packets, including IP headers and protocol-specific data.
#### Capturing packets:
![image](https://github.com/BlerttaKrasniqi/Internet-Security-PacketSniffer/assets/121398589/3b58ebc0-14dd-4624-bce2-be3062d008f4)
#### Filtering packets:
![image](https://github.com/BlerttaKrasniqi/Internet-Security-PacketSniffer/assets/121398589/cd5f6171-e612-489f-8a1f-ff01d7c9917f)
#### Packet details:
![image](https://github.com/BlerttaKrasniqi/Internet-Security-PacketSniffer/assets/121398589/45502fb1-15f3-401e-a92f-3d082d5427bb)

## Files
- `PacketSniffer.py`: Core module for capturing and processing packets.
- `PacketSnifferGUI.py`: GUI for the packet sniffer application.
- `PacketDetails.py`: Module for displaying detailed packet information in the GUI.
- `FilterPacketsGUI.py`: Module for setting filters for captured packets in the GUI.

## Installation and Usage

### Requirements
- Python 3.x (version 3 or higher)
- Windows operating system
- Any suitable code editor that supports Python (PyCharm, IntellIJ, Visual Studio Code...)
    ##### Dependencies
    - Python 3.x
    - socket
    - struct
    - netifaces
    - textwrap
    - tkinter
    
Install dependencies using pip:
```sh
pip install netifaces
```
### Steps
1. Clone this repository
2. Make sure you install the dependencies listed above

### Usage 

>On some systems, capturing network packets may require elevated privileges. Ensure you run the application with administrator rights to avoid permission errors.

1. **Run the Application**: Execute PacketSnifferGUI.py to start the GUI application.
    ```sh
    python PacketSnifferGUI.py
    ```

2. **Select Network Interface**: In the GUI, select the network interface you wish to monitor.

3. **Start Sniffing**: Click on the "Start Sniffing" button to begin capturing packets.

4. **Stop Sniffing**: Click on the "Stop Sniffing" button to stop capturing packets.

5. **Filter Packets**: Click on the "Filter" button to open the filter window, where you can set various criteria to filter captured packets.

6. **Unfilter Packets**: Click on the "Unfilter" button to remove all filters and display all captured packets.

7. **Clear Packets**: Click on the "Clear" button to remove all displayed packets from the list.

8. **View Packet Details**: Double-click on any captured packet in the list to view detailed information about it.

#### Notes
- The packet sniffer currently supports IPv4. Additional protocol and IPv6 support can be added as needed.
- Make sure you have the required permissions to sniff network traffic on the selected interface.

| Contributors |
|------------------|
| [Blerta Krasniqi](https://github.com/BlerttaKrasniqi) |
| [Dëshira Randobrava](https://github.com/d3shira) | 
| [Diart Maraj](https://github.com/diartmaraj) |
