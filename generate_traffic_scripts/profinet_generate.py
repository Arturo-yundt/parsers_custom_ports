#!/usr/bin/env python3

import argparse
from uuid import UUID

from scapy.all import (
    Ether,
    IP,
    UDP,
    wrpcap,
)

from scapy.layers.dcerpc import DceRpc4

# Importing this also registers the PNIO RPC payload dissectors
from scapy.contrib.pnio_rpc import (
    PNIOServiceReqPDU,
    PNIOServiceResPDU,
    IODReadReq,
    IODReadRes,
)


# ----------------------------------------------------------------------
# PROFINET / PNIO UUIDs
# ----------------------------------------------------------------------

PNIO_DEVICE_INTERFACE = UUID(
    "dea00001-6c97-11d1-8271-00a02442df7d"
)

PNIO_CONTROLLER_INTERFACE = UUID(
    "dea00002-6c97-11d1-8271-00a02442df7d"
)

# PROFINET object UUIDs begin with this namespace.
OBJECT_UUID = UUID(
    "dea00000-6c97-11d1-8271-010203040506"
)

ACTIVITY_UUID = UUID(
    "01234567-89ab-cdef-0123-456789abcdef"
)

AR_UUID = UUID(
    "fedcba98-7654-3210-fedc-ba9876543210"
)


def build_read_request(sequence=1):
    """
    Build a PROFINET PNIO Read request carried by DCE/RPC v4.

    DCE/RPC opnum 2 == Read in the Zeek PROFINET parser.

    PNIO block 0x0009 == IODReadReqHeader.
    """

    rpc = DceRpc4(
        rpc_vers=4,

        # 0 = DCE/RPC request
        ptype=0,

        # Idempotent + No FACK.
        # Typical for connectionless RPC traffic.
        flags1=0x28,
        flags2=0x00,

        # NDR little endian
        endian=1,
        encoding=0,
        float=0,

        object=OBJECT_UUID,
        if_id=PNIO_DEVICE_INTERFACE,
        act_id=ACTIVITY_UUID,

        server_boot=0,
        if_vers=1,

        seqnum=sequence,

        # PROFINET operation:
        #   0 Connect
        #   1 Release
        #   2 Read
        #   3 Write
        #   4 Control
        #   5 Read Implicit
        opnum=2,

        ihint=0xFFFF,
        ahint=0xFFFF,

        fragnum=0,
        auth_proto=0,
        serial_hi=0,
        serial_lo=0,
    )

    pnio = PNIOServiceReqPDU(
        blocks=[
            IODReadReq(
                seqNum=sequence,

                ARUUID=AR_UUID,

                API=0,

                # Example module/submodule
                slotNumber=0,
                subslotNumber=1,

                # 0xF840 is I&M0FilterData in the Zeek parser's
                # PROFINET index table.
                index=0xF840,

                # No extra record data follows this request block.
                recordDataLength=0,
            )
        ]
    )

    return rpc / pnio


def build_read_response(sequence=1):
    """
    Build a synthetic successful PNIO Read response.

    DCE/RPC packet type 2 == response.

    PNIO block 0x8009 == IODReadResHeader.
    """

    rpc = DceRpc4(
        rpc_vers=4,

        # 2 = DCE/RPC response
        ptype=2,

        flags1=0x28,
        flags2=0x00,

        endian=1,
        encoding=0,
        float=0,

        object=OBJECT_UUID,

        # Response is directed toward the IO controller.
        if_id=PNIO_CONTROLLER_INTERFACE,

        act_id=ACTIVITY_UUID,

        server_boot=1,
        if_vers=1,

        seqnum=sequence,
        opnum=2,

        ihint=0xFFFF,
        ahint=0xFFFF,

        fragnum=0,
        auth_proto=0,
        serial_hi=0,
        serial_lo=0,
    )

    pnio = PNIOServiceResPDU(
        status=0,
        blocks=[
            IODReadRes(
                seqNum=sequence,

                ARUUID=AR_UUID,

                API=0,
                slotNumber=0,
                subslotNumber=1,

                index=0xF840,

                # Keep the example response simple.
                recordDataLength=0,

                additionalValue1=0,
                additionalValue2=0,
            )
        ]
    )

    return rpc / pnio


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
        Ether(
            src=src_mac,
            dst=dst_mac,
        )
        / IP(
            src=src_ip,
            dst=dst_ip,
        )
        / UDP(
            sport=sport,
            dport=dport,
        )
        / payload
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate a PROFINET Context Manager / PNIO RPC PCAP "
            "using a custom UDP port."
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=34965,
        help=(
            "PROFINET CM server UDP port. "
            "Standard is 34964. Default: 34965"
        ),
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=49152,
        help="Client UDP port. Default: 49152",
    )

    parser.add_argument(
        "--output",
        default="generated_pcaps/34965_profinet.pcap",
        help="Output PCAP filename",
    )

    parser.add_argument(
        "--client-ip",
        default="192.168.10.100",
        help="Controller/client IPv4 address",
    )

    parser.add_argument(
        "--device-ip",
        default="192.168.10.50",
        help="PROFINET device IPv4 address",
    )

    parser.add_argument(
        "--client-mac",
        default="02:00:00:00:00:01",
    )

    parser.add_argument(
        "--device-mac",
        default="02:00:00:00:00:02",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    if not 1 <= args.client_port <= 65535:
        raise ValueError("client-port must be between 1 and 65535")

    # --------------------------------------------------------------
    # Build PNIO / DCE-RPC payloads
    # --------------------------------------------------------------

    request = build_read_request(
        sequence=1
    )

    response = build_read_response(
        sequence=1
    )

    # --------------------------------------------------------------
    # Controller -> PROFINET device
    # --------------------------------------------------------------

    request_packet = make_udp_packet(
        src_mac=args.client_mac,
        dst_mac=args.device_mac,

        src_ip=args.client_ip,
        dst_ip=args.device_ip,

        sport=args.client_port,
        dport=args.port,

        payload=request,
    )

    # --------------------------------------------------------------
    # PROFINET device -> Controller
    # --------------------------------------------------------------

    response_packet = make_udp_packet(
        src_mac=args.device_mac,
        dst_mac=args.client_mac,

        src_ip=args.device_ip,
        dst_ip=args.client_ip,

        sport=args.port,
        dport=args.client_port,

        payload=response,
    )

    request_packet.time = 1.000
    response_packet.time = 1.025

    packets = [
        request_packet,
        response_packet,
    ]

    wrpcap(
        args.output,
        packets,
    )

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print("Protocol       : PROFINET Context Manager / PNIO RPC")
    print("Transport      : DCE/RPC v4 over UDP")
    print(f"Server port    : UDP/{args.port}")
    print(f"Client port    : UDP/{args.client_port}")
    print(f"Controller     : {args.client_ip}")
    print(f"Device         : {args.device_ip}")
    print("DCE/RPC opnum  : 2 (Read)")
    print("Request block  : 0x0009 (IODReadReqHeader)")
    print("Response block : 0x8009 (IODReadResHeader)")
    print("Index          : 0xF840 (I&M0FilterData)")
    print()
    print("Request DCE/RPC payload:")
    print(bytes(request).hex(" "))
    print()
    print("Response DCE/RPC payload:")
    print(bytes(response).hex(" "))


if __name__ == "__main__":
    main()
