#!/usr/bin/env python3

import argparse
import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap


# ----------------------------------------------------------------------
# BACnet/IP constants
# ----------------------------------------------------------------------

BVLC_TYPE_BACNET_IP = 0x81

BVLC_ORIGINAL_UNICAST_NPDU   = 0x0A
BVLC_ORIGINAL_BROADCAST_NPDU = 0x0B

BACNET_VERSION = 0x01

# APDU
PDU_UNCONFIRMED_REQUEST = 0x10

# Unconfirmed service choices
SERVICE_I_AM   = 0x00
SERVICE_WHO_IS = 0x08

# BACnet Device object type
OBJECT_DEVICE = 8


def bvlc(function: int, payload: bytes) -> bytes:
    """
    BACnet Virtual Link Control header.

        Byte 0      BVLC Type = 0x81
        Byte 1      Function
        Bytes 2-3   Total BVLC message length, big endian
    """

    total_length = 4 + len(payload)

    return (
        bytes([
            BVLC_TYPE_BACNET_IP,
            function,
        ])
        + struct.pack(">H", total_length)
        + payload
    )


def global_broadcast_npdu(apdu: bytes) -> bytes:
    """
    BACnet NPDU for a global broadcast.

        01        Version
        20        Control: destination specifier present
        FF FF     DNET = global broadcast
        00        DLEN = 0
        FF        Hop count
    """

    return bytes([
        BACNET_VERSION,
        0x20,
        0xFF, 0xFF,
        0x00,
        0xFF,
    ]) + apdu


def local_npdu(apdu: bytes) -> bytes:
    """
    Minimal local BACnet NPDU.

        01        BACnet version
        00        No destination/source routing fields
    """

    return bytes([
        BACNET_VERSION,
        0x00,
    ]) + apdu


def unsigned_application_tag(value: int) -> bytes:
    """
    Encode a BACnet application-tagged Unsigned Integer.

    BACnet application tag number 2.
    """

    if value <= 0xFF:
        return bytes([0x21, value])

    if value <= 0xFFFF:
        return bytes([0x22]) + struct.pack(">H", value)

    if value <= 0xFFFFFF:
        return bytes([0x23]) + value.to_bytes(3, "big")

    return bytes([0x24]) + struct.pack(">I", value)


def enumerated_application_tag(value: int) -> bytes:
    """
    Encode a BACnet application-tagged Enumerated value.

    BACnet application tag number 9.
    """

    if value <= 0xFF:
        return bytes([0x91, value])

    if value <= 0xFFFF:
        return bytes([0x92]) + struct.pack(">H", value)

    return bytes([0x94]) + struct.pack(">I", value)


def object_identifier(object_type: int, instance: int) -> bytes:
    """
    BACnet Object Identifier.

    Top 10 bits = object type
    Bottom 22 bits = object instance
    """

    if not 0 <= object_type <= 0x3FF:
        raise ValueError("object type must fit in 10 bits")

    if not 0 <= instance <= 0x3FFFFF:
        raise ValueError("instance must fit in 22 bits")

    value = (object_type << 22) | instance

    # Application tag 12 / Object Identifier / length 4
    return bytes([0xC4]) + struct.pack(">I", value)


def build_who_is() -> bytes:
    """
    Build an unrestricted BACnet Who-Is.

    No low/high device-instance limits are supplied, meaning
    all devices are eligible to respond.
    """

    apdu = bytes([
        PDU_UNCONFIRMED_REQUEST,
        SERVICE_WHO_IS,
    ])

    npdu = global_broadcast_npdu(apdu)

    return bvlc(
        BVLC_ORIGINAL_BROADCAST_NPDU,
        npdu,
    )


def build_i_am(
    device_instance: int,
    max_apdu: int,
    segmentation: int,
    vendor_id: int,
) -> bytes:
    """
    Build a BACnet I-Am APDU.

    I-Am contains:

        Device Object Identifier
        Max APDU Length Accepted
        Segmentation Supported
        Vendor ID
    """

    apdu = (
        bytes([
            PDU_UNCONFIRMED_REQUEST,
            SERVICE_I_AM,
        ])
        + object_identifier(
            OBJECT_DEVICE,
            device_instance,
        )
        + unsigned_application_tag(max_apdu)
        + enumerated_application_tag(segmentation)
        + unsigned_application_tag(vendor_id)
    )

    npdu = global_broadcast_npdu(apdu)

    return bvlc(
        BVLC_ORIGINAL_BROADCAST_NPDU,
        npdu,
    )


def make_udp_packet(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    port,
    payload,
):
    return (
        Ether(
            src=src_mac,
            dst=dst_mac,
        )
        / IP(
            src=src_ip,
            dst=dst_ip,
        )
        / UDP(
            sport=port,
            dport=port,
        )
        / Raw(payload)
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate a BACnet/IP Who-Is / I-Am PCAP "
            "using a custom UDP port."
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=47809,
        help=(
            "BACnet/IP UDP port. "
            "Standard is 47809; default here is 47809."
        ),
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/47809_bacnet.pcap",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.100",
    )

    parser.add_argument(
        "--device-ip",
        default="192.168.10.50",
    )

    parser.add_argument(
        "--broadcast-ip",
        default="192.168.10.255",
    )

    parser.add_argument(
        "--client-mac",
        default="02:00:00:00:00:01",
    )

    parser.add_argument(
        "--device-mac",
        default="02:00:00:00:00:02",
    )

    parser.add_argument(
        "--device-instance",
        type=int,
        default=1234,
        help="BACnet Device object instance",
    )

    parser.add_argument(
        "--vendor-id",
        type=int,
        default=15,
        help="Synthetic BACnet vendor ID",
    )

    parser.add_argument(
        "--max-apdu",
        type=int,
        default=1476,
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    if not 0 <= args.device_instance <= 4194303:
        raise ValueError(
            "device-instance must be between 0 and 4194303"
        )

    # ----------------------------------------------------------
    # Build application payloads
    # ----------------------------------------------------------

    who_is = build_who_is()

    i_am = build_i_am(
        device_instance=args.device_instance,
        max_apdu=args.max_apdu,

        # 3 = no segmentation supported
        segmentation=3,

        vendor_id=args.vendor_id,
    )

    # ----------------------------------------------------------
    # Who-Is
    #
    # BACnet discovery is broadcast.
    # ----------------------------------------------------------

    who_is_packet = make_udp_packet(
        src_mac=args.client_mac,
        dst_mac="ff:ff:ff:ff:ff:ff",

        src_ip=args.client_ip,
        dst_ip=args.broadcast_ip,

        port=args.port,
        payload=who_is,
    )

    # ----------------------------------------------------------
    # I-Am response
    #
    # I-Am is also represented as a BACnet broadcast here.
    # ----------------------------------------------------------

    i_am_packet = make_udp_packet(
        src_mac=args.device_mac,
        dst_mac="ff:ff:ff:ff:ff:ff",

        src_ip=args.device_ip,
        dst_ip=args.broadcast_ip,

        port=args.port,
        payload=i_am,
    )

    who_is_packet.time = 1.000
    i_am_packet.time = 1.025

    packets = [
        who_is_packet,
        i_am_packet,
    ]

    wrpcap(
        args.output,
        packets,
    )

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print("Protocol        : BACnet/IP")
    print(f"UDP port        : {args.port}")
    print(f"Device instance : {args.device_instance}")
    print(f"Vendor ID       : {args.vendor_id}")

    print()
    print("Who-Is:")
    print(who_is.hex(" "))

    print()
    print("I-Am:")
    print(i_am.hex(" "))


if __name__ == "__main__":
    main()
