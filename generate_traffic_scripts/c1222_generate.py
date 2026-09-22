#!/usr/bin/env python3

import argparse
import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap


# ----------------------------------------------------------------------
# Basic BER helpers
# ----------------------------------------------------------------------

def ber_length(n: int) -> bytes:
    """Encode an ASN.1 BER length."""
    if n < 0x80:
        return bytes([n])

    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    """Build a BER TLV."""
    return bytes([tag]) + ber_length(len(value)) + value


def ber_integer(value: int) -> bytes:
    """Encode a positive BER INTEGER."""
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")

        # BER INTEGER is signed; prepend zero if MSB would imply negative.
        if raw[0] & 0x80:
            raw = b"\x00" + raw

    return tlv(0x02, raw)


# ----------------------------------------------------------------------
# C12.22 helpers
# ----------------------------------------------------------------------

def c1222_checksum(data: bytes) -> int:
    """
    C12.22 table data checksum.

    Wireshark implements this as:
        ~sum(data) + 1
    modulo 256.
    """
    return (-sum(data)) & 0xff


def ap_title(relative_oid: bytes, calling=False) -> bytes:
    """
    Encode a relative AP title.

    Called AP title:
        A2 <len> 80 <len> <relative OID>

    Calling AP title:
        A6 <len> 80 <len> <relative OID>
    """
    relative = tlv(0x80, relative_oid)
    return tlv(0xA6 if calling else 0xA2, relative)


def invocation_id(value: int) -> bytes:
    """
    Calling AP Invocation ID:
        A8 <len> 02 <len> <integer>
    """
    return tlv(0xA8, ber_integer(value))


def user_information(epsem: bytes) -> bytes:
    """
    C12.22 user-information:

        BE ...
          28 ...        EXTERNAL
            81 ...      octet-aligned EPSEM
    """
    octet_aligned = tlv(0x81, epsem)
    external = tlv(0x28, octet_aligned)
    return tlv(0xBE, external)


def c1222_message(
    epsem: bytes,
    called_title: bytes,
    calling_title: bytes,
    invocation: int
) -> bytes:
    """
    Build the outer C12.22 ACSE PDU.

        60 <length>
           A2 ... called AP title
           A6 ... calling AP title
           A8 ... calling AP invocation ID
           BE ... user information
    """
    body = (
        ap_title(called_title, calling=False)
        + ap_title(calling_title, calling=True)
        + invocation_id(invocation)
        + user_information(epsem)
    )

    # APPLICATION 0, constructed
    return tlv(0x60, body)


# ----------------------------------------------------------------------
# EPSEM messages
# ----------------------------------------------------------------------

def full_read_request(table: int) -> bytes:
    """
    Cleartext EPSEM Full Read request.

      flags          = 0x00
      service-length = 3
      command        = 0x30 (Full Read)
      table          = uint16
    """
    request = b"\x30" + struct.pack("!H", table)

    flags = b"\x00"
    return flags + ber_length(len(request)) + request


def full_read_response(data: bytes) -> bytes:
    """
    Cleartext EPSEM successful table read response.

      flags
      service-length
      00             OK
      count          uint16
      table-data
      checksum
    """
    checksum = c1222_checksum(data)

    response = (
        b"\x00"
        + struct.pack("!H", len(data))
        + data
        + bytes([checksum])
    )

    flags = b"\x00"
    return flags + ber_length(len(response)) + response


# ----------------------------------------------------------------------
# PCAP generation
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate C12.22 traffic on a custom UDP port."
    )

    parser.add_argument(
        "-o", "--output",
        default="generated_pcaps/1154_c1222.pcap",
        help="Output PCAP file"
    )

    parser.add_argument(
        "-p", "--port",
        type=int,
        default=1154,
        help="Custom C12.22 UDP server port (default: 21153)"
    )

    parser.add_argument(
        "--client-port",
        type=int,
        default=40000,
        help="Client UDP source port"
    )

    parser.add_argument(
        "--table",
        type=lambda x: int(x, 0),
        default=1,
        help="C12.22 table number (default: 1)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Network addresses
    # ------------------------------------------------------------------

    client_ip = "192.168.1.10"
    server_ip = "192.168.1.20"

    client_mac = "02:00:00:00:00:10"
    server_mac = "02:00:00:00:00:20"

    # Example relative AP titles.
    #
    # These are BER relative-OID contents, rather than ASCII strings.
    client_ap_title = bytes.fromhex("7b04")
    server_ap_title = bytes.fromhex("7bc175")

    # ------------------------------------------------------------------
    # Request: Full Read of Table 1
    # ------------------------------------------------------------------

    request_epsem = full_read_request(args.table)

    request_c1222 = c1222_message(
        epsem=request_epsem,
        called_title=server_ap_title,
        calling_title=client_ap_title,
        invocation=1
    )

    request_packet = (
        Ether(
            src=client_mac,
            dst=server_mac
        )
        / IP(
            src=client_ip,
            dst=server_ip
        )
        / UDP(
            sport=args.client_port,
            dport=args.port
        )
        / Raw(request_c1222)
    )

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------

    table_data = b"MANUFACTURER SN "

    response_epsem = full_read_response(table_data)

    response_c1222 = c1222_message(
        epsem=response_epsem,
        called_title=client_ap_title,
        calling_title=server_ap_title,
        invocation=2
    )

    response_packet = (
        Ether(
            src=server_mac,
            dst=client_mac
        )
        / IP(
            src=server_ip,
            dst=client_ip
        )
        / UDP(
            sport=args.port,
            dport=args.client_port
        )
        / Raw(response_c1222)
    )

    # ------------------------------------------------------------------
    # Give the packets realistic timestamps
    # ------------------------------------------------------------------

    request_packet.time = 1700000000.000
    response_packet.time = 1700000000.075

    packets = [
        request_packet,
        response_packet
    ]

    wrpcap(args.output, packets)

    print(f"Wrote {len(packets)} packets to {args.output}")
    print()
    print("C12.22 flow:")
    print(
        f"  {client_ip}:{args.client_port} "
        f"-> {server_ip}:{args.port}  Full Read table {args.table}"
    )
    print(
        f"  {server_ip}:{args.port} "
        f"-> {client_ip}:{args.client_port}  OK response"
    )
    print()
    print(f"Custom C12.22 port: UDP/{args.port}")


if __name__ == "__main__":
    main()
