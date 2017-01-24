import socket
import threading
import time
import os
import sys
import mutex

#create an INET, raw socket
s4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
s4.settimeout(1)
s6.settimeout(1)
shutdown_event = threading.Event()

t1_mutex = threading.Lock()
t2_mutex = threading.Lock()

t1_term = False
t2_term = False

def monitor_ipv4():
    # receive a packet
    while True:
        try:
            packet = s4.recvfrom(65566)
        except Exception as err:
            packet = None
        print(packet)

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
