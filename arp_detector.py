#!/usr/bin/env python

from scapy.all import *


def get_mac(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    ans_list = scapy.all.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return ans_list[0][1].hwsrc


def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(pkt):
    if pkt.haslayer(scapy.all.ARP) and pkt[scapy.all.ARP].op == 2:
        try:
            real_mac = get_mac(pkt[scapy.all.ARP].psrc)
            response_mac = pkt[scapy.all.ARP].hwsrc
            if real_mac != response_mac:
                print("[+] You are under attack!")
        except IndexError:
            pass

sniff("eth0")