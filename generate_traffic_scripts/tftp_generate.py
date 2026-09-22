#!/usr/bin/env python3

import argparse
import struct
from scapy.all import Ether, IP, UDP, Raw, wrpcap


def tftp_rrq(filename: str, mode: str = "octet") -> bytes:
    # Opcode 1 = RRQ
    return struct.pack("!H", 1) + filename.encode() + b"\x00" + mode.encode() + b"\x00"


def tftp_data(block: int, data: bytes) -> bytes:
    # Opcode 3 = DATA
    return struct.pack("!HH", 3, block) + data


def tftp_ack(block: int) -> bytes:
    # Opcode 4 = ACK
    return struct.pack("!HH", 4, block)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a TFTP PCAP using a custom UDP server port."
    )
    parser.add_argument(
        "-o", "--output",
        default="generated_pcaps/70_tftp.pcap",
        help="Output PCAP filename"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=70,
        help="Custom TFTP listening port (default: 1069)"
    )
    parser.add_argument(
        "--server-transfer-port",
        type=int,
        default=50000,
        help="Server TFTP transfer-ID UDP port (default: 50000)"
    )
    parser.add_argument(
        "--filename",
        default="example.txt",
        help="Filename requested by the TFTP client"
    )

    args = parser.parse_args()

    client_ip = "192.168.1.10"
    server_ip = "192.168.1.20"

    client_mac = "02:00:00:00:00:10"
    server_mac = "02:00:00:00:00:20"

    client_port = 40000

    file_data = (
        b"Hello from a TFTP transfer on a custom UDP port!\n"
        b"This packet capture was generated with Scapy.\n"
    )

    packets = []

    # 1. Client -> Server: TFTP RRQ
    #
    # The client contacts the server's custom listening port.
    rrq = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / UDP(sport=client_port, dport=args.port)
        / Raw(tftp_rrq(args.filename))
    )
    packets.append(rrq)

    # 2. Server -> Client: DATA block 1
    #
    # Normal TFTP behavior is for the server to reply from a new UDP
    # Transfer Identifier (TID), rather than continuing from its listening
    # port.
    data = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / UDP(sport=args.server_transfer_port, dport=client_port)
        / Raw(tftp_data(1, file_data))
    )
    packets.append(data)

    # 3. Client -> Server: ACK block 1
    ack = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / UDP(sport=client_port, dport=args.server_transfer_port)
        / Raw(tftp_ack(1))
    )
    packets.append(ack)

    # Make packet timing a little more natural.
    base_time = 1700000000.0
    for i, pkt in enumerate(packets):
        pkt.time = base_time + (i * 0.050)

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print(f"TFTP request port: UDP/{args.port}")
    print(f"Server transfer port: UDP/{args.server_transfer_port}")


if __name__ == "__main__":
    main()
