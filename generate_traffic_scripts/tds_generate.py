#!/usr/bin/env python3

import argparse
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap


# TDS packet types
TDS_SQL_BATCH = 0x01
TDS_RESPONSE  = 0x04
TDS_LOGIN7    = 0x10
TDS_PRELOGIN  = 0x12

# TDS status
TDS_STATUS_EOM = 0x01

# PRELOGIN option tokens
PL_VERSION    = 0x00
PL_ENCRYPTION = 0x01
PL_TERMINATOR = 0xFF

# PRELOGIN encryption values
ENCRYPT_OFF     = 0x00
ENCRYPT_ON      = 0x01
ENCRYPT_NOT_SUP = 0x02
ENCRYPT_REQ     = 0x03


def tds_packet(
    packet_type: int,
    payload: bytes,
    status: int = TDS_STATUS_EOM,
    spid: int = 0,
    packet_id: int = 1,
) -> bytes:
    """
    Build an 8-byte TDS packet header followed by payload.

        Byte 0      Type
        Byte 1      Status
        Bytes 2-3   Total packet length, big endian
        Bytes 4-5   SPID, big endian
        Byte 6      Packet ID
        Byte 7      Window
    """

    total_length = 8 + len(payload)

    header = struct.pack(
        ">BBHHBB",
        packet_type,
        status,
        total_length,
        spid,
        packet_id,
        0,          # Window
    )

    return header + payload


def build_prelogin_payload(
    version=b"\x0f\x00\x07\xd0\x00\x00",
    encryption=ENCRYPT_NOT_SUP,
):
    """
    Build a minimal but structurally valid TDS PRELOGIN structure.

    Contains:
        VERSION
        ENCRYPTION
        TERMINATOR

    PRELOGIN option offsets are relative to the beginning of the
    PRELOGIN payload.
    """

    if len(version) != 6:
        raise ValueError("TDS PRELOGIN VERSION must be 6 bytes")

    # Two option descriptors, each 5 bytes:
    #
    #   token       1
    #   offset      2
    #   length      2
    #
    # plus FF terminator.
    option_table_len = 5 + 5 + 1

    version_offset = option_table_len
    encryption_offset = version_offset + len(version)

    option_table = b"".join([
        bytes([PL_VERSION]),
        struct.pack(">HH", version_offset, len(version)),

        bytes([PL_ENCRYPTION]),
        struct.pack(">HH", encryption_offset, 1),

        bytes([PL_TERMINATOR]),
    ])

    data = version + bytes([encryption])

    return option_table + data


def build_prelogin_request():
    payload = build_prelogin_payload(
        encryption=ENCRYPT_NOT_SUP,
    )

    return tds_packet(
        packet_type=TDS_PRELOGIN,
        payload=payload,
        spid=0,
        packet_id=1,
    )


def build_prelogin_response(spid=51):
    """
    Synthetic SQL Server PRELOGIN response.

    Packet type 0x04 is used for the server response.
    """

    payload = build_prelogin_payload(
        encryption=ENCRYPT_NOT_SUP,
    )

    return tds_packet(
        packet_type=TDS_RESPONSE,
        payload=payload,
        spid=spid,
        packet_id=1,
    )


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
        description="Generate a Microsoft TDS PCAP on a custom TCP port."
    )

    parser.add_argument(
        "--port",
        type=int,
        default=1434,
        help="Custom TDS server TCP port (default: 1434)",
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=49152,
        help="Client TCP port (default: 49152)",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/1434_tds.pcap",
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

    parser.add_argument(
        "--client-mac",
        default="02:00:00:00:00:01",
    )

    parser.add_argument(
        "--server-mac",
        default="02:00:00:00:00:02",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    if not 1 <= args.client_port <= 65535:
        raise ValueError("client-port must be between 1 and 65535")

    prelogin_request = build_prelogin_request()
    prelogin_response = build_prelogin_response()

    packets = []

    client_isn = 1000
    server_isn = 9000

    cseq = client_isn
    sseq = server_isn

    # ---------------------------------------------------------
    # TCP handshake
    # ---------------------------------------------------------

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            cseq,
            0,
            "S",
        )
    )
    cseq += 1

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            sseq,
            cseq,
            "SA",
        )
    )
    sseq += 1

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            cseq,
            sseq,
            "A",
        )
    )

    # ---------------------------------------------------------
    # Client -> SQL Server: TDS PRELOGIN
    # ---------------------------------------------------------

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            cseq,
            sseq,
            "PA",
            prelogin_request,
        )
    )

    cseq += len(prelogin_request)

    # ACK
    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            sseq,
            cseq,
            "A",
        )
    )

    # ---------------------------------------------------------
    # SQL Server -> Client: PRELOGIN response
    # ---------------------------------------------------------

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            sseq,
            cseq,
            "PA",
            prelogin_response,
        )
    )

    sseq += len(prelogin_response)

    # Final ACK
    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            cseq,
            sseq,
            "A",
        )
    )

    # Give frames reasonable timestamps.
    for i, pkt in enumerate(packets):
        pkt.time = 1.000 + (i * 0.010)

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print(f"TDS server port : TCP/{args.port}")
    print(f"Client port     : TCP/{args.client_port}")
    print(f"Client          : {args.client_ip}")
    print(f"Server          : {args.server_ip}")
    print()
    print("PRELOGIN request:")
    print(prelogin_request.hex(" "))
    print()
    print("PRELOGIN response:")
    print(prelogin_response.hex(" "))


if __name__ == "__main__":
    main()
