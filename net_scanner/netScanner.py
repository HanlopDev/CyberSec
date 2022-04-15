#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answer_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan("10.0.2.1/24")
print_result(scan_result)
