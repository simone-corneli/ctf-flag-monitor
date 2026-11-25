from scapy.all import sniff, TCPSession, IP
from scapy.utils import in4_isincluded
import re
import sys

FLAG_PATTERN = re.compile(rb"[A-Z0-9]{31}=")

TEAM_NETWORK = "10.254.0.0"
TEAM_MASK = 16


def flag_destination(packet):
    if not (packet.haslayer("IP")):
        return "UNKNOWN"

    src = packet["IP"].src
    dst = packet["IP"].dst

    src_inside = in4_isincluded(src, TEAM_NETWORK, TEAM_MASK)
    dst_inside = in4_isincluded(dst, TEAM_NETWORK, TEAM_MASK)

    if src_inside and not (dst_inside):
        return "FLAG-IN"

    elif dst_inside and not (src_inside):
        return "FLAG-OUT"

    elif src_inside and dst_inside:
        return "AMBIGUOUS?!"

    else:
        return "UNKNOWN"


def packet_processor(packet):

    if packet.haslayer("Raw"):

        payload = packet["Raw"].load

        match = FLAG_PATTERN.search(payload)

        if match:
            print("\n!!! POSSIBLE FLAG DETECTED !!!")
            print(f"Flag: {match.group().decode()}")
            print(f"Pacchetto: {packet.summary()}")

            if packet.haslayer("IP"):
                print(f"IP sorgente: {packet["IP"].src}")
                print(f"IP destinazione: {packet["IP"].dst}")

            if packet.haslayer("TCP"):
                print(f"Porta sorgente: {packet["TCP"].sport}")
                print(f"Porta destinazione: {packet["TCP"].dport}")
                print(f"TCP Sequence: {packet["TCP"].seq}")
                print(f"TCP Acknowledgment: {packet["TCP"].ack}")

            print(flag_destination(packet))


def main():

    try:
        pcap_path = sys.argv[1]
        print(f"\nAnalyzing: {pcap_path}")
        sniff(offline=pcap_path, session=TCPSession, prn=packet_processor)

    except Exception as e:
        print(f"File ignored: {pcap_path} ({e})")


if __name__ == "__main__":
    main()
