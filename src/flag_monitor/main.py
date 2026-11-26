import argparse
import re

from scapy.all import TCPSession, sniff
from scapy.utils import in4_isincluded

parser = argparse.ArgumentParser(description="Find flags from pcap/pcapng files")
parser.add_argument(
    "pcap_paths",
    nargs="+",
    help="Paths to PCAP files to analyze,"
    + "separated by spaces (e.g., path1 path2 path3).",
)

FLAG_PATTERN = re.compile(rb"[A-Z0-9]{31}=")

TEAM_NETWORK = "10.254.0.0"
TEAM_MASK = 16


def flag_parsing(flag):
    flag_info = {
        "round": int(flag[0:2], 36),
        "team": int(flag[2:4], 36),
        "service": int(flag[4:6], 36),
    }
    return flag_info


def flag_destination(packet):

    if in4_isincluded(packet["IP"].src, TEAM_NETWORK, TEAM_MASK):
        direction = "FLAG-IN"

    elif in4_isincluded(packet["IP"].dst, TEAM_NETWORK, TEAM_MASK):
        direction = "FLAG-OUT"

    else:
        direction = "UNKNOWN"

    return direction


def packet_processor(packet):

    if packet.haslayer("TCP") and packet.haslayer("Raw"):

        match = FLAG_PATTERN.search(packet["Raw"].load)

        if match:
            flag = match.group().decode()
            flag_info = flag_parsing(flag)
            message = (
                "\n---------------------------------\n"
                + "!!! POSSIBLE FLAG DETECTED !!!\n"
                + f"Flag: {flag} | Direction: {flag_destination(packet)}\n"
                + f"Round: {flag_info['round']}\n"
                + f"Team_id: {flag_info['team']}\n"
                + f"Service_id: {flag_info['service']}\n"
                + f"{packet["IP"].src}:{packet["TCP"].sport} ->\n"
                + f"{packet["IP"].dst}:{packet["TCP"].dport}\n"
                + f"sequence_number = {packet["TCP"].seq}\n"
                + "---------------------------------"
            )
            print(message)


def main():

    args = parser.parse_args()
    for path in args.pcap_paths:
        try:
            print(
                "\n\n"
                + ("#") * 40
                + "\n"
                + f"\nAnalyzing: {path!s}\n\n"
                + ("#") * 40
                + "\n"
            )

            sniff(offline=str(path), session=TCPSession, prn=packet_processor)

        except Exception as e:
            print(f"\nFile ignored: {path} ({e})\n")


if __name__ == "__main__":
    main()
