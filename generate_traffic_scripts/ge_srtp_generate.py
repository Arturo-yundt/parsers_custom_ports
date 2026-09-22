#!/usr/bin/env python3

import argparse
import datetime
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap


SRTP_FRAME_LEN = 56

# Packet types used by the public GE-SRTP dissector
PKT_INIT     = 0x0000
PKT_INIT_ACK = 0x0001
PKT_REQUEST  = 0x0002
PKT_RESPONSE = 0x0003

# Message types
MSG_SHORT     = 0xC0
MSG_SHORT_ACK = 0xD4

# Service request codes
READ_SYS_MEM = 0x04

# Memory selector for %R registers
WORD_R = 0x08


def set_u16le(buf, offset, value):
    buf[offset:offset + 2] = struct.pack("<H", value & 0xFFFF)


def build_init_request():
    """
    GE SRTP initialization request.

    Public reverse-engineered clients send 56 zero bytes before
    sending normal service requests.
    """
    return bytes(SRTP_FRAME_LEN)


def build_init_response():
    """
    Synthetic SRTP INIT_ACK.

    Public captures/examples show the first byte as 0x01 and
    commonly 0x0f at offset 8.
    """
    msg = bytearray(SRTP_FRAME_LEN)

    set_u16le(msg, 0, PKT_INIT_ACK)
    msg[8] = 0x0F

    return bytes(msg)


def build_read_r_request(register=1, count=1, sequence=6):
    """
    Create a 56-byte GE SRTP READ_SYS_MEM request.

    register=1 means %R1. SRTP uses a zero-based address in
    offsets 44-45, so %R1 is encoded as index 0.
    """

    if not 1 <= register <= 65536:
        raise ValueError("register must be between 1 and 65536")

    if not 1 <= count <= 65535:
        raise ValueError("count must be between 1 and 65535")

    msg = bytearray(SRTP_FRAME_LEN)

    # ---------------------------------------------------------
    # Generic SRTP header
    # ---------------------------------------------------------

    set_u16le(msg, 0, PKT_REQUEST)

    # Sequence/index field
    set_u16le(msg, 2, sequence)

    # Text length. Public implementations frequently leave this
    # zero for short service requests.
    set_u16le(msg, 4, 0)

    # Known constant fields used by public SRTP implementations.
    msg[9] = 0x01
    msg[17] = 0x01

    # Timestamp fields: second, minute, hour
    now = datetime.datetime.now()
    msg[26] = now.second
    msg[27] = now.minute
    msg[28] = now.hour

    # Repeated sequence number
    msg[30] = sequence & 0xFF

    # Short SRTP service request
    msg[31] = MSG_SHORT

    # Mailbox source
    msg[32:36] = b"\x00\x00\x00\x00"

    # Mailbox destination commonly used in public implementations
    msg[36:40] = b"\x10\x0e\x00\x00"

    msg[40] = 1       # Packet number
    msg[41] = 1       # Total packet count

    # ---------------------------------------------------------
    # Service request
    # ---------------------------------------------------------

    msg[42] = READ_SYS_MEM
    msg[43] = WORD_R

    # Register index is zero based.
    register_index = register - 1
    set_u16le(msg, 44, register_index)

    # Number of requested registers/items
    set_u16le(msg, 46, count)

    # 48-55 remain zero for this short request.

    return bytes(msg)


def build_read_r_response(
    value=0x1234,
    sequence=6,
):
    """
    Create a synthetic successful short SRTP response.

    For the public 56-byte response layout:
        42-43 = status
        44... = returned payload
    """

    if not 0 <= value <= 0xFFFF:
        raise ValueError("value must fit in a 16-bit register")

    msg = bytearray(SRTP_FRAME_LEN)

    set_u16le(msg, 0, PKT_RESPONSE)
    set_u16le(msg, 2, sequence)
    set_u16le(msg, 4, 0)

    msg[9] = 0x01
    msg[17] = 0x01

    now = datetime.datetime.now()
    msg[26] = now.second
    msg[27] = now.minute
    msg[28] = now.hour

    msg[30] = sequence & 0xFF
    msg[31] = MSG_SHORT_ACK

    # Reverse the mailbox direction for the response.
    msg[32:36] = b"\x10\x0e\x00\x00"
    msg[36:40] = b"\x00\x00\x00\x00"

    msg[40] = 1
    msg[41] = 1

    # Status / error fields
    msg[42] = 0x00
    msg[43] = 0x00

    # Returned %R word, little endian
    set_u16le(msg, 44, value)

    return bytes(msg)


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
        description="Generate an offline GE SRTP PCAP on a custom TCP port."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=18245,
        help="Custom GE SRTP server TCP port (default: 18246)",
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=49152,
        help="Client TCP source port",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/18245_ge_srtp.pcap",
        help="Output PCAP filename",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.100",
    )

    parser.add_argument(
        "--plc-ip",
        default="192.168.10.50",
    )

    parser.add_argument(
        "--register",
        type=int,
        default=1,
        help="%%R register number to read (default: R1)",
    )

    parser.add_argument(
        "--value",
        type=lambda x: int(x, 0),
        default=0x1234,
        help="Synthetic register value returned by PLC (default: 0x1234)",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("port must be 1-65535")

    if not 1 <= args.client_port <= 65535:
        raise ValueError("client port must be 1-65535")

    client_mac = "02:00:00:00:00:01"
    plc_mac = "02:00:00:00:00:02"

    sequence = 6

    init_request = build_init_request()
    init_response = build_init_response()

    read_request = build_read_r_request(
        register=args.register,
        count=1,
        sequence=sequence,
    )

    read_response = build_read_r_response(
        value=args.value,
        sequence=sequence,
    )

    packets = []

    client_isn = 1000
    plc_isn = 9000

    cseq = client_isn
    pseq = plc_isn

    # =========================================================
    # TCP handshake
    # =========================================================

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, 0, "S"
        )
    )
    cseq += 1

    packets.append(
        tcp_packet(
            plc_mac, client_mac,
            args.plc_ip, args.client_ip,
            args.port, args.client_port,
            pseq, cseq, "SA"
        )
    )
    pseq += 1

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, pseq, "A"
        )
    )

    # =========================================================
    # SRTP INIT request
    # =========================================================

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, pseq, "PA",
            init_request,
        )
    )
    cseq += len(init_request)

    # PLC ACK
    packets.append(
        tcp_packet(
            plc_mac, client_mac,
            args.plc_ip, args.client_ip,
            args.port, args.client_port,
            pseq, cseq, "A"
        )
    )

    # =========================================================
    # SRTP INIT ACK
    # =========================================================

    packets.append(
        tcp_packet(
            plc_mac, client_mac,
            args.plc_ip, args.client_ip,
            args.port, args.client_port,
            pseq, cseq, "PA",
            init_response,
        )
    )
    pseq += len(init_response)

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, pseq, "A"
        )
    )

    # =========================================================
    # READ_SYS_MEM: client -> PLC
    # =========================================================

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, pseq, "PA",
            read_request,
        )
    )
    cseq += len(read_request)

    packets.append(
        tcp_packet(
            plc_mac, client_mac,
            args.plc_ip, args.client_ip,
            args.port, args.client_port,
            pseq, cseq, "A"
        )
    )

    # =========================================================
    # READ_SYS_MEM response: PLC -> client
    # =========================================================

    packets.append(
        tcp_packet(
            plc_mac, client_mac,
            args.plc_ip, args.client_ip,
            args.port, args.client_port,
            pseq, cseq, "PA",
            read_response,
        )
    )
    pseq += len(read_response)

    packets.append(
        tcp_packet(
            client_mac, plc_mac,
            args.client_ip, args.plc_ip,
            args.client_port, args.port,
            cseq, pseq, "A"
        )
    )

    # Give packets plausible timestamps.
    for i, pkt in enumerate(packets):
        pkt.time = 1.000 + (i * 0.010)

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print(f"GE SRTP server port : TCP/{args.port}")
    print(f"Register             : %R{args.register}")
    print(f"Synthetic value      : 0x{args.value:04x}")
    print()
    print("INIT request:")
    print(init_request.hex(" "))
    print()
    print("INIT response:")
    print(init_response.hex(" "))
    print()
    print("READ request:")
    print(read_request.hex(" "))
    print()
    print("READ response:")
    print(read_response.hex(" "))


if __name__ == "__main__":
    main()
