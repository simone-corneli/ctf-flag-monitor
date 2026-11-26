from scapy.all import *

counter = 0


def packet_processor(packet):
    global counter

    counter += 1

    print(f"\nCALLBACK No. {counter}")
    print(packet.summary())


capture = sniff(
    offline="../../../Tirocinio/leopardo.pcapng",
    session=TCPSession,
    count=6000,
    prn=packet_processor,
)

print(f"\nPackets returned by sniff(): {len(capture)}")
print(f"Callback calls: {counter}")
