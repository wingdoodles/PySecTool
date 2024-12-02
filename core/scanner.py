import scapy.all as scapy
import socket

class NetworkScanner:
    def __init__(self):
        self.target = "192.168.1.0/24"
    
    def start_scan(self):
        arp_request = scapy.ARP(pdst=self.target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return [(element[1].psrc, element[1].hwsrc) for element in answered_list]