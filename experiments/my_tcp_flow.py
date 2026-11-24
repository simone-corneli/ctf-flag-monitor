"""
program: my_tcp_flow
Author: corneli-simone

this program is a experiment to make confident with scapy layers,
in particular i want try to sniff some packets, and find all
tcp flows.
"""

from scapy.all import *
from os.path import *
import time
import requests

pck_number = 0
def main():
    global pck_number

    capture = sniff(
                    iface = "wlp2s0",
                    filter = "tcp port 80"
                    )

    capture.start()
    time.sleep(2)

    url = "http://web-14.challs.olicyber.it/"
    testo = requests.get(url)
    time.sleep(2)
    packets = capture.stop()

    tcp_flows = tcp_flows_constructor(packets)
    print_tcp_streams(tcp_flows)

    tcp_flows_ordinated = riassembly_tcp_flow(tcp_flows)
    flow_number = 0
    for tupla in tcp_flows_ordinated:
        flow_number += 1
        pck_number = 0
        print(f"\n\n\n\t\t\t###FLOW N°{flow_number}###"
              + f"\tnumber of packets = {len(tcp_flows_ordinated[tupla])}")
        for segment in tcp_flows_ordinated[tupla]:
            my_summary_print(segment)

def print_tcp_streams(tcp_streams):
    global pck_number
    for tupla in tcp_streams:
        print(f"TUPLA = {tupla}")

        for direction in tcp_streams[tupla]:
            print(f"\npackets {str(direction)} are:\n")
            pck_number = 0
            for packet in tcp_streams[tupla][direction]:
                my_summary_print(packet)
                
def my_summary_print(packet):
    global pck_number

    if packet.haslayer("TCP"):
        pck_number += 1
        print(f"\n-packet N°{pck_number}\n")    

        print(
                f"{packet["IP"].src} ->" 
                f" {packet["IP"].dst}"
                )
        print(
                f"seq = {packet["TCP"].seq}\n"
                f"ack = {packet["TCP"].ack}\n"
                f"sport = {packet["TCP"].sport}\n"
                f"dport = {packet["TCP"].dport}\n"
                )
        print(f"flags = {packet["TCP"].flags} ")

        if(packet.haslayer(Raw)):
            packet["Raw"].show()
            print(len(packet[Raw].load))

def tcp_flows_constructor(packets):
    tcp_flows = {}
    
    for packet in packets:
        if(packet.haslayer("TCP")):

            tupla_tcp_CtoS =(
                        str(packet["IP"].src), str(packet["IP"].dst),
                        str(packet["TCP"].sport), str(packet["TCP"].dport)
                        )
            tupla_tcp_StoC =(
                        str(packet["IP"].dst), str(packet["IP"].src),
                        str(packet["TCP"].dport), str(packet["TCP"].sport)
                        )
            find = 0
            for tupla in tcp_flows:

                if (tupla == tupla_tcp_CtoS):
                    (tcp_flows[tupla]["client_to_server"]).append(packet)
                    find = 1
                    break

                elif (tupla == tupla_tcp_StoC):
                    (tcp_flows[tupla]["server_to_client"]).append(packet)
                    find = 1
                    break

            if find == 0:
                tcp_flows[tupla_tcp_CtoS] = {"client_to_server":[packet],
                                              "server_to_client":[]}

    for tupla in tcp_flows:
        for direction in tcp_flows[tupla]:
            tcp_flows[tupla][direction] = pcks_riordination(tcp_flows[tupla][direction])

    return tcp_flows

def pcks_riordination(packets):
    packets_ordinated=[]
    counter = 0

    if (len(packets) > 1):
        while len(packets) > 2:
            counter = 0
            next_packet = packets[counter]

            for counter in range(len(packets)-1):
                if (next_packet["TCP"].seq > packets[counter+1]["TCP"].seq):
                    next_packet = packets[counter+1]

            packets_ordinated.append(next_packet)
            packets.pop(packets.index(next_packet))


        if packets[0]["TCP"].seq < packets[1]["TCP"].seq:
            packets_ordinated.extend(packets)

        else:
            packets_ordinated.append(packets[1])
            packets_ordinated.append(packets[0])
    else:
        packets_ordinated = packets

    return packets_ordinated

def riassembly_tcp_flow(tcp_flows):

    for tupla in tcp_flows:
        tcp_flow = []
        client_to_server = tcp_flows[tupla]["client_to_server"]
        server_to_client = tcp_flows[tupla]["server_to_client"]
        first = True
        
        while(len(client_to_server) > 0 and len(server_to_client) > 0):
            if (first):
                seq = compute_seq(client_to_server[0])
                tcp_flow.append(client_to_server.pop(0))
                client = False
                server = True
                first = False
            if (server):
                if(server_to_client[0]["TCP"].ack == seq):
                    seq = compute_seq(server_to_client[0])
                    tcp_flow.append(server_to_client.pop(0))
                    client = True
                    server = False
                else:
                    seq = compute_seq(client_to_server[0])
                    tcp_flow.append(client_to_server.pop(0))

            if (client):
                if(client_to_server[0]["TCP"].ack == seq):
                    seq = compute_seq(client_to_server[0])
                    tcp_flow.append(client_to_server.pop(0))
                    client = False
                    server = True
                else:
                    seq = compute_seq(server_to_client[0])
                    tcp_flow.append(server_to_client.pop(0))

        if (len(client_to_server) > 0):
            tcp_flow.extend(client_to_server)

        elif(len(server_to_client) > 0):
            if(server_to_client[0]["TCP"].ack == compute_seq(tcp_flow[0])):
                tcp_flow.insert(server_to_client.pop(0),0)
            tcp_flow.extend(server_to_client)

        tcp_flows[tupla] = tcp_flow

    return tcp_flows

def compute_seq(packet):
    seq = packet["TCP"].seq

    if ("S" in packet["TCP"].flags):
        seq += 1
    if ("F" in packet["TCP"].flags):
        seq += 1
    if packet.haslayer("Raw"):
        seq += len(packet["Raw"].load)

    return seq

if __name__ == "__main__":
    main()