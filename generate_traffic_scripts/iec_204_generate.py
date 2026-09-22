#!/usr/bin/env python3

import argparse
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap


# IEC 60870-5-104 U-format control bytes
STARTDT_ACT = 0x07
STARTDT_CON = 0x0B
STOPDT_ACT  = 0x13
STOPDT_CON  = 0x23
TESTFR_ACT  = 0x43
TESTFR_CON  = 0x83

# ASDU Type IDs
M_SP_NA_1 = 1       # Single-point information
C_IC_NA_1 = 100     # General interrogation

# Cause of transmission
COT_ACTIVATION             = 6
COT_ACTIVATION_CONFIRM     = 7
COT_ACTIVATION_TERMINATION = 10
COT_INTERROGATED_STATION   = 20


def iec104_u_frame(control_byte: int) -> bytes:
    """
    Build an IEC-104 U-format APDU.

    Format:
        68 04 CC 00 00 00
    """
    return bytes([
        0x68,
        0x04,
        control_byte,
        0x00,
        0x00,
        0x00,
    ])


def iec104_s_frame(rx_seq: int) -> bytes:
    """
    Build an IEC-104 S-format acknowledgement.

    Receive sequence number is encoded shifted left by one.
    """
    rx = (rx_seq & 0x7FFF) << 1

    return (
        b"\x68\x04"
        + b"\x01\x00"
        + struct.pack("<H", rx)
    )


def iec104_i_frame(
    tx_seq: int,
    rx_seq: int,
    asdu: bytes,
) -> bytes:
    """
    Build an IEC-104 I-format APDU.

    APCI:
        0x68
        APDU length
        TX sequence << 1   (little endian)
        RX sequence << 1   (little endian)

    followed by ASDU.
    """

    tx = (tx_seq & 0x7FFF) << 1
    rx = (rx_seq & 0x7FFF) << 1

    control = struct.pack("<HH", tx, rx)

    apdu_length = 4 + len(asdu)

    if apdu_length > 253:
        raise ValueError("IEC-104 APDU too large")

    return (
        bytes([0x68, apdu_length])
        + control
        + asdu
    )


def build_interrogation_asdu(
    cause: int,
    common_address: int = 1,
    originator: int = 0,
    qoi: int = 20,
) -> bytes:
    """
    C_IC_NA_1 General Interrogation ASDU.

        Type ID         100 / 0x64
        VSQ             1 object
        Cause           caller supplied
        Originator      0
        Common Address  2 bytes
        IOA             0
        QOI             20 = station interrogation
    """

    return (
        bytes([
            C_IC_NA_1,
            0x01,
            cause & 0x3F,
            originator & 0xFF,
        ])
        + struct.pack("<H", common_address)
        + b"\x00\x00\x00"       # IOA = 0
        + bytes([qoi])
    )


def build_single_point_asdu(
    ioa: int = 100,
    value: bool = True,
    common_address: int = 1,
    originator: int = 0,
) -> bytes:
    """
    Synthetic M_SP_NA_1 single-point response.

        Type ID = 1
        COT     = 20 (interrogated by station interrogation)
        IOA     = configurable
        SIQ     = ON/OFF, good quality
    """

    if not 0 <= ioa <= 0xFFFFFF:
        raise ValueError("IOA must fit in 24 bits")

    ioa_bytes = ioa.to_bytes(
        3,
        byteorder="little",
    )

    siq = 0x01 if value else 0x00

    return (
        bytes([
            M_SP_NA_1,
            0x01,
            COT_INTERROGATED_STATION,
            originator & 0xFF,
        ])
        + struct.pack("<H", common_address)
        + ioa_bytes
        + bytes([siq])
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
        Ether(
            src=src_mac,
            dst=dst_mac,
        )
        / IP(
            src=src_ip,
            dst=dst_ip,
        )
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
        description=(
            "Generate an IEC 60870-5-104 PCAP "
            "using a custom TCP server port."
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=2405,
        help="Custom IEC-104 TCP server port (default: 2405)",
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=49152,
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/2405_iec104.pcap",
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

    parser.add_argument(
        "--common-address",
        type=int,
        default=1,
        help="IEC-104 ASDU common address",
    )

    parser.add_argument(
        "--ioa",
        type=int,
        default=100,
        help="Synthetic information object address",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("port must be 1-65535")

    if not 1 <= args.client_port <= 65535:
        raise ValueError("client-port must be 1-65535")

    # ----------------------------------------------------------
    # IEC-104 application payloads
    # ----------------------------------------------------------

    startdt_act = iec104_u_frame(
        STARTDT_ACT
    )

    startdt_con = iec104_u_frame(
        STARTDT_CON
    )

    # Client I-frame sequence 0
    gi_request = iec104_i_frame(
        tx_seq=0,
        rx_seq=0,
        asdu=build_interrogation_asdu(
            cause=COT_ACTIVATION,
            common_address=args.common_address,
        ),
    )

    # Server acknowledges client's I-frame with rx_seq=1
    gi_confirm = iec104_i_frame(
        tx_seq=0,
        rx_seq=1,
        asdu=build_interrogation_asdu(
            cause=COT_ACTIVATION_CONFIRM,
            common_address=args.common_address,
        ),
    )

    # One synthetic data point
    point_response = iec104_i_frame(
        tx_seq=1,
        rx_seq=1,
        asdu=build_single_point_asdu(
            ioa=args.ioa,
            value=True,
            common_address=args.common_address,
        ),
    )

    # End of general interrogation
    gi_termination = iec104_i_frame(
        tx_seq=2,
        rx_seq=1,
        asdu=build_interrogation_asdu(
            cause=COT_ACTIVATION_TERMINATION,
            common_address=args.common_address,
        ),
    )

    # Client acknowledges all three server I-frames
    s_ack = iec104_s_frame(
        rx_seq=3,
    )

    packets = []

    client_seq = 1000
    server_seq = 9000

    # ==========================================================
    # TCP handshake
    # ==========================================================

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            client_seq,
            0,
            "S",
        )
    )
    client_seq += 1

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "SA",
        )
    )
    server_seq += 1

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            client_seq,
            server_seq,
            "A",
        )
    )

    # ==========================================================
    # STARTDT ACT
    # ==========================================================

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            client_seq,
            server_seq,
            "PA",
            startdt_act,
        )
    )
    client_seq += len(startdt_act)

    # ==========================================================
    # STARTDT CON
    # ==========================================================

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "PA",
            startdt_con,
        )
    )
    server_seq += len(startdt_con)

    # ==========================================================
    # General interrogation request
    # ==========================================================

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            client_seq,
            server_seq,
            "PA",
            gi_request,
        )
    )
    client_seq += len(gi_request)

    # ==========================================================
    # Activation confirmation
    # ==========================================================

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "PA",
            gi_confirm,
        )
    )
    server_seq += len(gi_confirm)

    # ==========================================================
    # Synthetic interrogation result
    # ==========================================================

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "PA",
            point_response,
        )
    )
    server_seq += len(point_response)

    # ==========================================================
    # Activation termination
    # ==========================================================

    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "PA",
            gi_termination,
        )
    )
    server_seq += len(gi_termination)

    # ==========================================================
    # IEC-104 S-frame acknowledgement
    # ==========================================================

    packets.append(
        tcp_packet(
            args.client_mac,
            args.server_mac,
            args.client_ip,
            args.server_ip,
            args.client_port,
            args.port,
            client_seq,
            server_seq,
            "PA",
            s_ack,
        )
    )
    client_seq += len(s_ack)

    # Final TCP acknowledgement
    packets.append(
        tcp_packet(
            args.server_mac,
            args.client_mac,
            args.server_ip,
            args.client_ip,
            args.port,
            args.client_port,
            server_seq,
            client_seq,
            "A",
        )
    )

    for i, pkt in enumerate(packets):
        pkt.time = 1.000 + i * 0.010

    wrpcap(
        args.output,
        packets,
    )

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print(f"IEC-104 server port : TCP/{args.port}")
    print(f"Client port         : TCP/{args.client_port}")
    print(f"Common address      : {args.common_address}")
    print(f"Example IOA         : {args.ioa}")

    print()
    print("STARTDT act:")
    print(startdt_act.hex(" "))

    print()
    print("STARTDT con:")
    print(startdt_con.hex(" "))

    print()
    print("General interrogation:")
    print(gi_request.hex(" "))

    print()
    print("Activation confirmation:")
    print(gi_confirm.hex(" "))

    print()
    print("Single-point response:")
    print(point_response.hex(" "))

    print()
    print("Activation termination:")
    print(gi_termination.hex(" "))


if __name__ == "__main__":
    main()
