#!/usr/bin/env python3

import argparse
import struct
from scapy.all import Ether, IP, UDP, Raw, wrpcap


def fins_header(
    icf,
    dest_node,
    src_node,
    sid,
    dest_network=0,
    dest_unit=0,
    src_network=0,
    src_unit=0,
    gateway_count=2,
):
    """
    FINS/UDP header: 10 bytes

      0  ICF   Information Control Field
      1  RSV   Reserved
      2  GCT   Gateway Count
      3  DNA   Destination Network Address
      4  DA1   Destination Node Address
      5  DA2   Destination Unit Address
      6  SNA   Source Network Address
      7  SA1   Source Node Address
      8  SA2   Source Unit Address
      9  SID   Service ID
    """

    return bytes([
        icf,
        0x00,                   # RSV
        gateway_count,
        dest_network,
        dest_node,
        dest_unit,
        src_network,
        src_node,
        src_unit,
        sid,
    ])


def fins_memory_read_request(
    plc_node,
    client_node,
    sid,
    word_address,
    count,
):
    """
    Create a FINS Memory Area Read (0101) request.

    Reads DM words using memory area code 0x82.
    """

    header = fins_header(
        icf=0x80,       # Command, response required
        dest_node=plc_node,
        src_node=client_node,
        sid=sid,
    )

    command = bytes([
        0x01, 0x01,     # Memory Area Read
        0x82,           # DM Area, word access
    ])

    # Beginning address:
    #   2 bytes word number, big endian
    #   1 byte bit offset
    address = struct.pack(">H", word_address) + b"\x00"

    # Number of words, big endian
    item_count = struct.pack(">H", count)

    return header + command + address + item_count


def fins_memory_read_response(
    plc_node,
    client_node,
    sid,
    values,
):
    """
    Create a successful FINS Memory Area Read response.
    """

    header = fins_header(
        icf=0xC0,       # Response
        dest_node=client_node,
        src_node=plc_node,
        sid=sid,
    )

    command = bytes([
        0x01, 0x01,     # Memory Area Read
    ])

    end_code = bytes([
        0x00, 0x00,     # Normal completion
    ])

    data = b"".join(
        struct.pack(">H", value & 0xFFFF)
        for value in values
    )

    return header + command + end_code + data


def make_udp_packet(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    payload,
):
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )


def main():
    parser = argparse.ArgumentParser(
        description="Generate an Omron FINS/UDP PCAP using a custom port."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9601,
        help="Custom PLC FINS/UDP port (default: 9601)",
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=40000,
        help="Client UDP source port (default: 40000)",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/9601_omron_fins.pcap",
        help="Output PCAP filename",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.40",
        help="Client IP address",
    )

    parser.add_argument(
        "--plc-ip",
        default="192.168.10.42",
        help="PLC IP address",
    )

    parser.add_argument(
        "--client-node",
        type=int,
        default=40,
        help="FINS client node address",
    )

    parser.add_argument(
        "--plc-node",
        type=int,
        default=42,
        help="FINS PLC node address",
    )

    parser.add_argument(
        "--word",
        type=int,
        default=100,
        help="Starting DM word (default: D100)",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=2,
        help="Number of DM words to read",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    if not 1 <= args.client_port <= 65535:
        raise ValueError("Client port must be between 1 and 65535")

    if not 0 <= args.plc_node <= 255:
        raise ValueError("PLC node must be 0-255")

    if not 0 <= args.client_node <= 255:
        raise ValueError("Client node must be 0-255")

    if not 0 <= args.word <= 65535:
        raise ValueError("DM word must be 0-65535")

    if not 1 <= args.count <= 100:
        raise ValueError("Count must be 1-100")

    client_mac = "02:00:00:00:00:01"
    plc_mac = "02:00:00:00:00:02"

    sid = 0x01

    # ------------------------------------------------------------
    # FINS Memory Area Read request
    #
    # Example:
    #     Read 2 words starting at D100
    # ------------------------------------------------------------

    request_payload = fins_memory_read_request(
        plc_node=args.plc_node,
        client_node=args.client_node,
        sid=sid,
        word_address=args.word,
        count=args.count,
    )

    # ------------------------------------------------------------
    # Generate arbitrary example PLC values.
    #
    # D100 = 0x1234
    # D101 = 0x5678
    # etc.
    # ------------------------------------------------------------

    example_values = [
        (0x1234 + (i * 0x1111)) & 0xFFFF
        for i in range(args.count)
    ]

    response_payload = fins_memory_read_response(
        plc_node=args.plc_node,
        client_node=args.client_node,
        sid=sid,
        values=example_values,
    )

    # ------------------------------------------------------------
    # Client -> PLC
    # ------------------------------------------------------------

    request_packet = make_udp_packet(
        src_mac=client_mac,
        dst_mac=plc_mac,
        src_ip=args.client_ip,
        dst_ip=args.plc_ip,
        sport=args.client_port,
        dport=args.port,
        payload=request_payload,
    )

    # ------------------------------------------------------------
    # PLC -> Client
    # ------------------------------------------------------------

    response_packet = make_udp_packet(
        src_mac=plc_mac,
        dst_mac=client_mac,
        src_ip=args.plc_ip,
        dst_ip=args.client_ip,
        sport=args.port,
        dport=args.client_port,
        payload=response_payload,
    )

    # Give the packets realistic timestamps
    request_packet.time = 1.000
    response_packet.time = 1.025

    packets = [
        request_packet,
        response_packet,
    ]

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print(f"FINS/UDP PLC port : {args.port}")
    print(f"Client port       : {args.client_port}")
    print(f"PLC               : {args.plc_ip} / node {args.plc_node}")
    print(f"Client            : {args.client_ip} / node {args.client_node}")
    print(f"Read              : D{args.word} - D{args.word + args.count - 1}")
    print()
    print("Request :", request_payload.hex(" "))
    print("Response:", response_payload.hex(" "))


if __name__ == "__main__":
    main()
