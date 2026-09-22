#!/usr/bin/env python3

import argparse
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def roc_crc16(data: bytes) -> int:
    """
    ROC Plus CRC-16.

    Polynomial: x^16 + x^15 + x^2 + 1
    Reflected polynomial: 0xA001
    Initial value: 0x0000

    CRC is transmitted LSB first.
    """
    crc = 0x0000

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    return crc & 0xFFFF


def roc_plus_frame(
    dest_unit: int,
    dest_group: int,
    src_unit: int,
    src_group: int,
    opcode: int,
    data: bytes = b"",
) -> bytes:
    """
    Build a ROC Plus frame.

        Offset  Size    Field
        ------  ----    ----------------
        0       1       Destination Unit
        1       1       Destination Group
        2       1       Source Unit
        3       1       Source Group
        4       1       Opcode
        5       1       Data Length
        6       N       Data
        6+N     2       CRC, LSB first
    """

    if len(data) > 255:
        raise ValueError("ROC Plus data field cannot exceed 255 bytes")

    header = bytes([
        dest_unit & 0xFF,
        dest_group & 0xFF,
        src_unit & 0xFF,
        src_group & 0xFF,
        opcode & 0xFF,
        len(data) & 0xFF,
    ])

    message = header + data
    crc = roc_crc16(message)

    # ROC CRC is transmitted LSB then MSB
    return message + struct.pack("<H", crc)


def tcp_packet(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    seq,
    ack,
    flags,
    payload=b"",
):
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=sport,
            dport=dport,
            seq=seq,
            ack=ack,
            flags=flags,
            window=64240,
        )
    )

    if payload:
        pkt /= Raw(payload)

    return pkt


def main():
    parser = argparse.ArgumentParser(
        description="Generate a ROC Plus TCP PCAP on a custom port."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=4001,
        help="Custom ROC Plus server TCP port (default: 4001)",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/4001_roc_plus.pcap",
        help="Output PCAP filename",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.100",
        help="Host/client IPv4 address",
    )

    parser.add_argument(
        "--roc-ip",
        default="192.168.10.50",
        help="ROC controller IPv4 address",
    )

    parser.add_argument(
        "--roc-unit",
        type=int,
        default=13,
        help="ROC destination unit address",
    )

    parser.add_argument(
        "--roc-group",
        type=int,
        default=5,
        help="ROC destination group address",
    )

    args = parser.parse_args()

    client_mac = "02:00:00:00:00:01"
    roc_mac = "02:00:00:00:00:02"

    client_port = 49152
    roc_port = args.port

    #
    # ROC Plus Opcode 7:
    # request current time/date
    #
    # Request has zero data bytes.
    #
    request = roc_plus_frame(
        dest_unit=args.roc_unit,
        dest_group=args.roc_group,
        src_unit=1,
        src_group=0,
        opcode=7,
        data=b"",
    )

    #
    # Example Opcode 7 response data:
    #
    #   seconds
    #   minutes
    #   hours
    #   day
    #   month
    #   year
    #   leap-year indicator
    #   day of week
    #
    clock_data = bytes([
        30,  # seconds
        41,  # minutes
        12,  # hour
        22,  # day
        9,   # month
        26,  # year
        0,   # leap year
        2,   # day of week
    ])

    response = roc_plus_frame(
        dest_unit=1,
        dest_group=0,
        src_unit=args.roc_unit,
        src_group=args.roc_group,
        opcode=7,
        data=clock_data,
    )

    print("ROC Plus request :", request.hex(" "))
    print("ROC Plus response:", response.hex(" "))

    #
    # Create a plausible TCP session.
    #
    client_isn = 1000
    server_isn = 5000

    cseq = client_isn
    sseq = server_isn

    packets = []

    # ------------------------------------------------------------
    # TCP three-way handshake
    # ------------------------------------------------------------

    syn = tcp_packet(
        client_mac,
        roc_mac,
        args.client_ip,
        args.roc_ip,
        client_port,
        roc_port,
        seq=cseq,
        ack=0,
        flags="S",
    )
    packets.append(syn)

    cseq += 1

    syn_ack = tcp_packet(
        roc_mac,
        client_mac,
        args.roc_ip,
        args.client_ip,
        roc_port,
        client_port,
        seq=sseq,
        ack=cseq,
        flags="SA",
    )
    packets.append(syn_ack)

    sseq += 1

    ack = tcp_packet(
        client_mac,
        roc_mac,
        args.client_ip,
        args.roc_ip,
        client_port,
        roc_port,
        seq=cseq,
        ack=sseq,
        flags="A",
    )
    packets.append(ack)

    # ------------------------------------------------------------
    # Host -> ROC: Opcode 7 request
    # ------------------------------------------------------------

    request_pkt = tcp_packet(
        client_mac,
        roc_mac,
        args.client_ip,
        args.roc_ip,
        client_port,
        roc_port,
        seq=cseq,
        ack=sseq,
        flags="PA",
        payload=request,
    )
    packets.append(request_pkt)

    cseq += len(request)

    # Server acknowledges request
    request_ack = tcp_packet(
        roc_mac,
        client_mac,
        args.roc_ip,
        args.client_ip,
        roc_port,
        client_port,
        seq=sseq,
        ack=cseq,
        flags="A",
    )
    packets.append(request_ack)

    # ------------------------------------------------------------
    # ROC -> Host: Opcode 7 response
    # ------------------------------------------------------------

    response_pkt = tcp_packet(
        roc_mac,
        client_mac,
        args.roc_ip,
        args.client_ip,
        roc_port,
        client_port,
        seq=sseq,
        ack=cseq,
        flags="PA",
        payload=response,
    )
    packets.append(response_pkt)

    sseq += len(response)

    # Client acknowledges response
    response_ack = tcp_packet(
        client_mac,
        roc_mac,
        args.client_ip,
        args.roc_ip,
        client_port,
        roc_port,
        seq=cseq,
        ack=sseq,
        flags="A",
    )
    packets.append(response_ack)

    # ------------------------------------------------------------
    # Give packets sensible timestamps
    # ------------------------------------------------------------

    base_time = 1.0

    for i, pkt in enumerate(packets):
        pkt.time = base_time + (i * 0.010)

    wrpcap(args.output, packets)

    print()
    print(f"Wrote {len(packets)} packets to {args.output}")
    print(f"ROC Plus server port: TCP/{roc_port}")
    print(f"Request length:        {len(request)} bytes")
    print(f"Response length:       {len(response)} bytes")


if __name__ == "__main__":
    main()
