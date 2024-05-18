import socket
import struct
import netifaces
import psutil
import textwrap

#for multi-line formatting:
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    connection.bind(('0.0.0.0', 0))
    connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)                             #////////////
        print('\nEthernet frame(firstt):')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {},'. format(dest_mac, src_mac, eth_protocol))
#Displaying packet data:
        #8 for IPv4
        if eth_protocol == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data, = process_icmp(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            # Inside the condition where IPv4 protocol is identified
            if proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                    data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            #Other
            else:
                print(TAB_1 +'Data')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, data))

#depaketimi i IPv4 paketave
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#formatimi i IPv4 adreses
def ipv4(addr):
    return '.'.join(map(str, addr))


def get_protocol_name(proto):
    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        # Add other protocol mappings as needed
    }
    return protocol_map.get(proto, "Unknown")


#Unpack ICMP packet
#data[:4] grab first 4 bytes(header)
#data[4:] grab everything after 4th byte (payload)
def process_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    print("ICMP Packet:")
    print(f"Type: {icmp_type}, Code: {code}")
    print(f"Checksum: {checksum}")
    if icmp_type == 8 and code == 0:
        print("Protocol: ICMP Echo Request (Ping)")
    elif icmp_type == 0 and code == 0:
        print("Protocol: ICMP Echo Reply (Ping Response)")
    else:
        print("Protocol: Other ICMP Protocol")


#Unpack TCP segment

def process_tcp(data):
    # Process TCP packet
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        "URG": (offset_reserved_flags & 32) >> 5,
        "ACK": (offset_reserved_flags & 16) >> 4,
        "PSH": (offset_reserved_flags & 8) >> 3,
        "RST": (offset_reserved_flags & 4) >> 2,
        "SYN": (offset_reserved_flags & 2) >> 1,
        "FIN": offset_reserved_flags & 1
    }
    protocol = "Unknown"
    if (dest_port >= 1 and dest_port <= 1023) or (src_port >= 1 and src_port <=1023):
        protocol = process_well_known_port(dest_port)
    
    return acknowledgment, sequence, flags, protocol, src_port, dest_port, data[offset:]   

#Unpack UDP segment
def process_udp(data):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    protocol = "Unknown"
    if (dest_port >= 1 and dest_port <= 1023) or (src_port >= 1 and src_port <=1023):
        protocol = process_well_known_port(dest_port)

    return src_port, dest_port, length,protocol, checksum, data[8:]

def process_well_known_port(port):
    # Map well-known ports to their associated protocols
    port_protocol_mapping = {
        1: "TCPMUX",
        5: "Remote Job Entry",
        7: "Echo",
        9: "Discard",
        11: "SYSTAT",
        13: "Daytime",
        15: "Unassigned",
        17: "Quote of the Day",
        19: "Character Generator",
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        37: "Time",
        42: "Name Server",
        43: "Whois",
        49: "Login Host Protocol",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        70: "Gopher",
        79: "Finger",
        80: "HTTP",
        88: "Kerberos",
        101: "NIC Host Name Server",
        102: "ISO-TSAP",
        107: "Remote Telnet Service",
        109: "POP2",
        110: "POP3",
        111: "Sun Remote Procedure Call",
        113: "Ident",
        115: "SFTP",
        117: "UUCP Path Service",
        119: "NNTP",
        123: "NTP",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        179: "BGP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        512: "Remote Process Execution",
        513: "Rlogin",
        514: "Syslog",
        515: "Line Printer Daemon",
        517: "Talk",
        518: "NTalk",
        519: "UUDMP",
        520: "Routing Information Protocol",
        525: "Timed",
        530: "RPC",
        554: "RTSP",
        546: "DHCPv6 Client",
        547: "DHCPv6 Server",
        548: "AFP",
        554: "Real Time Streaming Protocol",
        556: "Remotefs",
        563: "NNTP over TLS/SSL",
        587: "SMTP Submission",
        591: "FileMaker",
        631: "Internet Printing Protocol",
        636: "LDAPS",
        873: "rsync",
        990: "FTPS",
        993: "IMAPS",
        995: "POP3S",
        # Add more port-protocol mappings as needed
    }

    return port_protocol_mapping.get(port, "Unknown")


#Format multi-line data (not sniffing related)
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def handle_unknown_protocol(protocol,data):
    if hasattr(data,'__len__'):
        print(f'Unknown protocol: {protocol}')
        print(f'Data: {data[:min(40, len(data))]}')
    else:
        print(f'Unknown protocol: {protocol}')
        print(f'Data: Data is not a sequence and cannot be displayed')

if __name__ == "__main__":
    main()






