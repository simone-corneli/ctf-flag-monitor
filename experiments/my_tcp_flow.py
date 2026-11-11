"""
program: my_tcp_flow
Author: corneli-simone

this program is a experiment to make confident with scapy layers,
in particular i want try to sniff some packets, and find all
tcp flows.
"""

from os.path import *
from time import *

import requests
from scapy.all import *

pck_number = 0
"""
data structure
tcp_flows = {(ips, ipd, sport, dport):{client_to_server:[packs], server_to_client:[packs]}}
tcp_ordinated_flows = {(ips, ipd, sport, dport): [pacchetti ordinati]}
"""


def main():

    capture = AsyncSniffer(iface="wlp2s0", filter="tcp port 80", prn=my_summary_print)

    capture.start()
    sleep(2)

    richiesta_http()
    sleep(2)

    packets = capture.stop()
    print(len(packets), end="\n\n\n")

    tcp_streams = tcp_flows(packets)
    print_tcp_streams(tcp_streams)


def richiesta_http():
    url = "http://web-14.challs.olicyber.it/"
    requests.get(url)


def print_tcp_streams(tcp_streams):
    global pck_number
    for tupla in tcp_streams:
        print(f"TUPLA = {tupla}")

        for direction in tcp_streams[tupla]:
            print(f"\npackets {direction!s} are:\n")
            pck_number = 0
            for packet in tcp_streams[tupla][direction]:
                my_summary_print(packet)


def my_summary_print(packet):
    global pck_number

    if packet.haslayer("TCP"):
        pck_number += 1
        print(f"\n-packet N°{pck_number}\n")

        print(f"{packet["IP"].src} ->" f" {packet["IP"].dst}")
        print(
            f"seq = {packet["TCP"].seq}\n"
            f"ack = {packet["TCP"].ack}\n"
            f"sport = {packet["TCP"].sport}\n"
            f"dport = {packet["TCP"].dport}\n"
        )
        print(f"flags = {packet["TCP"].flags} ")

        if packet.haslayer(Raw):
            packet["Raw"].show()
            print(len(packet[Raw].load))


def tcp_flows(packets):
    tcp_flows = {}

    for packet in packets:
        if packet.haslayer("TCP"):

            tupla_tcp_CtoS = (
                str(packet["IP"].src),
                str(packet["IP"].dst),
                str(packet["TCP"].sport),
                str(packet["TCP"].dport),
            )
            tupla_tcp_StoC = (
                str(packet["IP"].dst),
                str(packet["IP"].src),
                str(packet["TCP"].dport),
                str(packet["TCP"].sport),
            )
            find = 0
            for tupla in tcp_flows:

                if tupla == tupla_tcp_CtoS:
                    (tcp_flows[tupla]["client_to_server"]).append(packet)
                    find = 1
                    break

                elif tupla == tupla_tcp_StoC:
                    (tcp_flows[tupla]["server_to_client"]).append(packet)
                    find = 1
                    break

            if find == 0:
                tcp_flows[tupla_tcp_CtoS] = {
                    "client_to_server": [packet],
                    "server_to_client": [],
                }

    print_tcp_streams(tcp_flows)
    for tupla in tcp_flows:
        for direction in tcp_flows[tupla]:
            tcp_flows[tupla][direction] = pcks_riordination(tcp_flows[tupla][direction])

    return tcp_flows


def pcks_riordination(packets):

    packets_ordinated = []
    counter = 0

    while len(packets) > 2:
        counter = 0
        next_packet = packets[counter]

        for counter in range(len(packets) - 1):
            if next_packet["TCP"].seq > packets[counter + 1]["TCP"].seq:
                next_packet = packets[counter + 1]

        packets_ordinated.append(next_packet)
        packets.pop(packets.index(next_packet))

    if packets[0]["TCP"].seq < packets[1]["TCP"].seq:
        packets_ordinated.extend(packets)

    else:
        packets_ordinated.append(packets[1])
        packets_ordinated.append(packets[0])

    return packets_ordinated


if __name__ == "__main__":
    main()
