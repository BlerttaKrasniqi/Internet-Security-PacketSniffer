import socket
import struct
import textwrap

def main():
    conncetion = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conncetion.recvfrom(65536)
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Destination: {}, Source: {}, Protocol: {},'. format(dest_mac, src_mac, eth_protocol))
#depaketimi i ethernet frame

def ethernet_frame(data):
    dest_mac_address, src_mac_address, protocol = struct.unpack('! 6s 6s H', data[:14])   #6 karaktere per destination, 6 per source, H small unsigned integer per protokol - 2 bajt
     #te dhenat qe vijn i merr prej fillimit deri te karakteri i 14 (dmth 14 bajta)
    return get_mac_addr(dest_mac_address), get_mac_addr(src_mac_address), socket.htons(protocol), data[14:]


# kthimi i mac adreses ne format qe mundet me u lexu prej njeriut

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()








