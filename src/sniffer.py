import socket
import threading
import time
import os
import sys
import mutex
from struct import unpack
#create an INET, raw socket
s4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
s4.settimeout(1)
s6.settimeout(1)
shutdown_event = threading.Event()

dump_lock = threading.Lock()
t1_mutex = threading.Lock()
t2_mutex = threading.Lock()

t1_term = False
t2_term = False


def dump_ipv4_packet(pack):
    
    dump_lock.acquire() 
    
    packet_string = pack[0]
    ip_addr = pack[1]
    ip_header = packet_string[0:20]
    unpacked_header = unpack('!BBBBBBBBBBBBBBBBBBBB' , ip_header)
    
    version = unpacked_header[0] >> 4
    header_length = unpacked_header[0] & 0xF
    
    dscp = unpacked_header[1] >> 2
    ecn = unpacked_header[1] & 0x3
   
    length_one = unpacked_header[2]
    length_two = unpacked_header[3]
    total_length = (length_one << 8) + length_two
    identification = (unpacked_header[4] << 8) + unpacked_header[5]
    ttl = unpacked_header[8]
    protocol = unpacked_header[9]
    checksum = (unpacked_header[10] << 8) + int(unpacked_header[11])
    source_ip = str(unpacked_header[12]) + "." + str(unpacked_header[13]) + '.' + str(unpacked_header[14]) + '.' + str(unpacked_header[15])
    dest_ip = str(unpacked_header[16]) + "." + str(unpacked_header[17]) + '.' + str(unpacked_header[18]) + '.' + str(unpacked_header[19])

    print("START PACKET DUMP")
    print("IP_ADDR", ip_addr)
    print("unpacked", unpacked_header)
    print("VERSION", version)
    print("HEADER LENGTH", header_length)
    print("IDEN", identification)
    print("DSCP", dscp)
    print("ECN", ecn)
    print("TOTAL LENGTH", total_length)
    print("TTL", ttl)
    print("PROTOCOL", protocol)
    print("SOURCE_IP", source_ip)
    print("DEST_IP", dest_ip)

    tcp_start = header_length * 4
    tcp_header = packet_string[tcp_start:tcp_start + 20]
    unpacked_tcp = unpack('!HHLLBBHHH', tcp_header)

    dump = unpack("!HHBBBBBBBBBBHHH", tcp_header)
    print(dump)
    print(unpacked_tcp, "UNPACKED")
    source_port = unpacked_tcp[0]
    dest_port = unpacked_tcp[1]
    seq = unpacked_tcp[2] 
    print("SOURCE PORT", source_port)
    print("DEST PORT", dest_port)
    print("SEQ", seq >> 11)
     

    print("END PACKET DUMP\n\n")

    dump_lock.release()

def monitor_ipv4():
    # receive a packet
    one = True
    while True:
        try:
            packet = s4.recvfrom(65566)
        except Exception as err:
            packet = None
        if packet is not None:
            dump_ipv4_packet(packet)
            one = False

        # Check to see if program should terminate
        t1_mutex.acquire()
        if t1_term:
            t1_mutex.release()
            sys.exit(1)
        t1_mutex.release() 

def monitor_ipv6():
    # receive a packet
    while True:
        try:
            packet = s6.recvfrom(65566)
        except Exception as err:
            packet = None
        print(packet)

        # Check to see if program should terminate
        t2_mutex.acquire()
        if t2_term:
            t2_mutex.release()
            sys.exit(1)
        t2_mutex.release()
    
if __name__ == '__main__':

    t1 = threading.Thread(target=monitor_ipv4)
    t2 = threading.Thread(target=monitor_ipv6)
    t1.start()
    t2.start()

    while True:
        try:
            while(1):
                pass
        except(KeyboardInterrupt, SystemExit):
            print("Caught term signal. Exiting")
            t1_mutex.acquire()
            t1_term = True
            t1_mutex.release()
            t2_mutex.acquire()
            t2_term = True
            t2_mutex.release()
            sys.exit(1)
