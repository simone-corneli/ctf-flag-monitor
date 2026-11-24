from scapy.all import sniff, TCPSession
import re

FLAG_PATTERN = re.compile(rb"[A-Z0-9]{31}=")

PCAP_FILE = "../../captures/pcap3"

def packet_processor(packet):

    if packet.haslayer("Raw"):

        payload = packet["Raw"].load

        match = FLAG_PATTERN.search(payload)

        if match:
            print("\n!!! POSSIBILE FLAG TROVATA !!!")
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

            if (identify_http(payload)) == "HTTP REQUEST":
                print("PROBABLY FLAG-IN")

            if (identify_http(payload)) == "HTTP RESPONSE":
                print("PROBABLY FLAG-OUT")


def identify_http(payload):

    if payload.startswith((
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS "
    )):
        return "HTTP REQUEST"

    elif payload.startswith(b"HTTP/"):
        return "HTTP RESPONSE"

    return "UNKNOWN"

def main():

        try:
            print(f"\nAnalizzo: {PCAP_FILE}")
            sniff(
                offline=PCAP_FILE,
                session=TCPSession,
                prn=packet_processor
            )

        except Exception as e:
            print(f"File ignorato: {PCAP_FILE} ({e})")


if __name__ == "__main__":
    main()