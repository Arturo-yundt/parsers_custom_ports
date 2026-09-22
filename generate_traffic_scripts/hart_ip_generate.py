#!/usr/bin/env python3

import argparse
import struct
from scapy.all import Ether, IP, UDP, Raw, wrpcap


# HART-IP message types
REQUEST  = 0
RESPONSE = 1
PUBLISH  = 2

# HART-IP message IDs
SESSION_INITIATE = 0
SESSION_CLOSE    = 1
KEEP_ALIVE       = 2
PASS_THROUGH     = 3


def hart_ip_header(
    message_type,
    message_id,
    transaction_id,
    payload_len,
    status=0,
    version=1,
):
    """
    HART-IP header (8 bytes):

        Byte 0     Version
        Byte 1     Message Type
        Byte 2     Message ID
        Byte 3     Status
        Bytes 4-5  Transaction ID / Sequence Number
        Bytes 6-7  Payload length

    Multi-byte integers are network byte order (big endian).
    """
    return struct.pack(
        "!BBBBHH",
        version,
        message_type,
        message_id,
        status,
        transaction_id,
        payload_len,
    )


def make_hart_ip(
    message_type,
    message_id,
    transaction_id,
    payload=b"",
    status=0,
):
    header = hart_ip_header(
        message_type=message_type,
        message_id=message_id,
        transaction_id=transaction_id,
        payload_len=len(payload),
        status=status,
    )

    return header + payload


def main():
    parser = argparse.ArgumentParser(
        description="Generate a HART-IP PCAP using a custom UDP port."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5095,
        help="Custom HART-IP UDP port (default: 15094)",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/5095_hart_ip.pcap",
        help="Output PCAP filename",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.100",
    )

    parser.add_argument(
        "--server-ip",
        default="192.168.10.50",
    )

    args = parser.parse_args()

    client_port = 40000
    hart_port = args.port

    #
    # Example HART command 0 request.
    #
    # This is the Pass Through payload from the FieldComm Group
    # HART-IP client example.
    #
    request_hart = bytes.fromhex(
        "82 A6 4E 0B 15 38 00 00 4C"
    )

    #
    # Corresponding example response.
    #
    response_hart = bytes.fromhex(
        "86 A6 4E 0B 15 38 00 18 "
        "00 D0 FE 26 4E 05 07 04 "
        "01 0E 0C 0B 15 38 05 02 "
        "00 0F D0 00 26 00 26 84 69"
    )

    transaction_id = 13

    request = make_hart_ip(
        message_type=REQUEST,
        message_id=PASS_THROUGH,
        transaction_id=transaction_id,
        payload=request_hart,
    )

    response = make_hart_ip(
        message_type=RESPONSE,
        message_id=PASS_THROUGH,
        transaction_id=transaction_id,
        payload=response_hart,
    )

    packets = []

    # Client -> HART-IP server
    packets.append(
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(
            src=args.client_ip,
            dst=args.server_ip,
        )
        / UDP(
            sport=client_port,
            dport=hart_port,
        )
        / Raw(request)
    )

    # HART-IP server -> client
    packets.append(
        Ether(
            src="02:00:00:00:00:02",
            dst="02:00:00:00:00:01",
        )
        / IP(
            src=args.server_ip,
            dst=args.client_ip,
        )
        / UDP(
            sport=hart_port,
            dport=client_port,
        )
        / Raw(response)
    )

    # Give the packets slightly different timestamps
    packets[0].time = 1.000
    packets[1].time = 1.050

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print(f"HART-IP custom port: UDP/{hart_port}")


if __name__ == "__main__":
    main()
