"""
Program: my_tcp_flow
Author: corneli-simone

This program is an experiment to become familiar with Scapy layers.
In particular, I want to try sniffing packets and finding all
TCP flows.
"""

import time
from os.path import *

import requests
from scapy.all import *

pck_number = 0


def main():
    global pck_number

    capture = sniff(iface="wlp2s0", filter="tcp port 80")

    capture.start()
    time.sleep(2)

    url = "http://web-14.challs.olicyber.it/"
    response = requests.get(url)
    time.sleep(2)
    packets = capture.stop()

    tcp_flows = tcp_flows_constructor(packets)
    print_tcp_streams(tcp_flows)

    ordered_tcp_flows = reassemble_tcp_flow(tcp_flows)
    flow_number = 0

    for connection_tuple in ordered_tcp_flows:
        flow_number += 1
        pck_number = 0

        print(
            f"\n\n\n\t\t\t### FLOW No. {flow_number} ###" + f"\tnumber of packets = "
            f"{len(ordered_tcp_flows[connection_tuple])}"
        )

        for segment in ordered_tcp_flows[connection_tuple]:
            my_summary_print(segment)


def print_tcp_streams(tcp_streams):
    global pck_number

    for connection_tuple in tcp_streams:
        print(f"CONNECTION TUPLE = {connection_tuple}")

        for direction in tcp_streams[connection_tuple]:
            print(f"\npackets {direction!s} are:\n")
            pck_number = 0

            for packet in tcp_streams[connection_tuple][direction]:
                my_summary_print(packet)


def my_summary_print(packet):
    global pck_number

    if packet.haslayer("TCP"):
        pck_number += 1
        print(f"\n-Packet No. {pck_number}\n")

        print(f"{packet['IP'].src} ->" f" {packet['IP'].dst}")

        print(
            f"seq = {packet['TCP'].seq}\n"
            f"ack = {packet['TCP'].ack}\n"
            f"sport = {packet['TCP'].sport}\n"
            f"dport = {packet['TCP'].dport}\n"
        )

        print(f"flags = {packet['TCP'].flags} ")

        if packet.haslayer(Raw):
            packet["Raw"].show()
            print(len(packet[Raw].load))


def tcp_flows_constructor(packets):
    tcp_flows = {}

    for packet in packets:
        if packet.haslayer("TCP"):

            client_to_server_tuple = (
                str(packet["IP"].src),
                str(packet["IP"].dst),
                str(packet["TCP"].sport),
                str(packet["TCP"].dport),
            )

            server_to_client_tuple = (
                str(packet["IP"].dst),
                str(packet["IP"].src),
                str(packet["TCP"].dport),
                str(packet["TCP"].sport),
            )

            found = 0

            for connection_tuple in tcp_flows:

                if connection_tuple == client_to_server_tuple:
                    (tcp_flows[connection_tuple]["client_to_server"]).append(packet)
                    found = 1
                    break

                elif connection_tuple == server_to_client_tuple:
                    (tcp_flows[connection_tuple]["server_to_client"]).append(packet)
                    found = 1
                    break

            if found == 0:
                tcp_flows[client_to_server_tuple] = {
                    "client_to_server": [packet],
                    "server_to_client": [],
                }

    for connection_tuple in tcp_flows:
        for direction in tcp_flows[connection_tuple]:
            tcp_flows[connection_tuple][direction] = reorder_packets(
                tcp_flows[connection_tuple][direction]
            )

    return tcp_flows


def reorder_packets(packets):
    ordered_packets = []
    counter = 0

    if len(packets) > 1:
        while len(packets) > 2:
            counter = 0
            next_packet = packets[counter]

            for counter in range(len(packets) - 1):
                if next_packet["TCP"].seq > packets[counter + 1]["TCP"].seq:
                    next_packet = packets[counter + 1]

            ordered_packets.append(next_packet)
            packets.pop(packets.index(next_packet))

        if packets[0]["TCP"].seq < packets[1]["TCP"].seq:
            ordered_packets.extend(packets)

        else:
            ordered_packets.append(packets[1])
            ordered_packets.append(packets[0])

    else:
        ordered_packets = packets

    return ordered_packets


def reassemble_tcp_flow(tcp_flows):

    for connection_tuple in tcp_flows:
        tcp_flow = []
        client_to_server = tcp_flows[connection_tuple]["client_to_server"]
        server_to_client = tcp_flows[connection_tuple]["server_to_client"]
        first = True

        while len(client_to_server) > 0 and len(server_to_client) > 0:
            if first:
                seq = compute_seq(client_to_server[0])
                tcp_flow.append(client_to_server.pop(0))
                client = False
                server = True
                first = False

            if server:
                if server_to_client[0]["TCP"].ack == seq:
                    seq = compute_seq(server_to_client[0])
                    tcp_flow.append(server_to_client.pop(0))
                    client = True
                    server = False
                else:
                    seq = compute_seq(client_to_server[0])
                    tcp_flow.append(client_to_server.pop(0))

            if client:
                if client_to_server[0]["TCP"].ack == seq:
                    seq = compute_seq(client_to_server[0])
                    tcp_flow.append(client_to_server.pop(0))
                    client = False
                    server = True
                else:
                    seq = compute_seq(server_to_client[0])
                    tcp_flow.append(server_to_client.pop(0))

        if len(client_to_server) > 0:
            tcp_flow.extend(client_to_server)

        elif len(server_to_client) > 0:
            if server_to_client[0]["TCP"].ack == compute_seq(tcp_flow[0]):
                tcp_flow.insert(server_to_client.pop(0), 0)
            tcp_flow.extend(server_to_client)

        tcp_flows[connection_tuple] = tcp_flow

    return tcp_flows


def compute_seq(packet):
    seq = packet["TCP"].seq

    if "S" in packet["TCP"].flags:
        seq += 1

    if "F" in packet["TCP"].flags:
        seq += 1

    if packet.haslayer("Raw"):
        seq += len(packet["Raw"].load)

    return seq


if __name__ == "__main__":
    main()
