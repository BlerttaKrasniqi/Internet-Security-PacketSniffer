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
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg,flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

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






