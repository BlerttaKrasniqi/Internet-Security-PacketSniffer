import socket
import struct
import textwrap

#depaketimi i ethernet frame

def ethernet_frame(data):
    dest_mac_address, src_mac_address, protocol = struct.unpack('! 6s 6s H', data[:14])   #6 karaktere per destination, 6 per source, H small unsigned integer per protokol - 2 bajt
     #te dhenat qe vijn i merr prej fillimit deri te karakteri i 14 (dmth 14 bajta)
    return get_mac_addr(dest_mac_address), get_mac_addr(src_mac_address), socket.htons(protocol), data[14:]











