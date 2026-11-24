from scapy.all import *
counter = 0

def packet_processor(packet):
    global counter

    counter += 1

    print(f"\nCALLBACK N°{counter}")
    print(packet.summary())

capture = sniff(
    offline="../../../Tirocinio/leopardo.pcapng",
    session=TCPSession,
    count=6000,
    prn=packet_processor
)

print(f"\nPacchetti restituiti da sniff(): {len(capture)}")
print(f"Chiamate alla callback: {counter}")