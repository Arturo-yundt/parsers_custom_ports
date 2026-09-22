import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

HAS_INNER_DIAG_INFO = 0x40
SERVICE_FAULT = 397


def make_diag_info(depth):
    """
    Build a DiagnosticInfo containing `depth` nested inner
    DiagnosticInfo structures.

    Each non-leaf object:
        encoding_mask = 0x40  (hasInnerDiagInfo)

    Final leaf:
        encoding_mask = 0x00
    """
    return bytes([HAS_INNER_DIAG_INFO]) * depth + b"\x00"


def make_opcua_service_fault(depth):
    diag_info = make_diag_info(depth)

    #
    # ResponseHeader
    #
    # timestamp          : int64
    # request_handle     : uint32
    # service_result     : uint32
    # service_diag       : OpcUA_DiagInfo
    # string_table_size  : int32
    # additional_hdr     : uint16 + uint8 in this parser
    #
    response_header = (
        struct.pack("<q", 0)          # timestamp
        + struct.pack("<I", 1)        # request_handle
        + struct.pack("<I", 0)        # service_result = Good
        + diag_info
        + struct.pack("<i", 0)        # empty string table
        + struct.pack("<H", 0)        # additional_hdr.type_id
        + struct.pack("<B", 0)        # additional_hdr.encoding_mask
    )

    #
    # Msg_Body / Service
    #
    # 0x01 = FourByte NodeId encoding
    # namespace index = 0
    # identifier = ServiceFault (397)
    #
    service = (
        struct.pack("<B", 0x01)
        + struct.pack("<B", 0)
        + struct.pack("<H", SERVICE_FAULT)
        + response_header
    )

    #
    # MSG secure-conversation fields
    #
    msg_contents = (
        struct.pack("<I", 1)      # secure_channel_id
        + struct.pack("<I", 1)    # secure_token_id
        + struct.pack("<I", 1)    # sequence_number
        + struct.pack("<I", 1)    # request_id
        + service
    )

    #
    # OPC UA TCP MessageHeader
    #
    # "MSG" + "F" + total message size
    #
    message_size = 8 + len(msg_contents)

    return (
        b"MSG"
        + b"F"
        + struct.pack("<I", message_size)
        + msg_contents
    )


def make_pcap(filename, depth):
    payload = make_opcua_service_fault(depth)

    client_ip = "10.10.10.10"
    server_ip = "10.10.10.20"

    client_port = 40000
    server_port = 4841

    client_seq = 1000
    server_seq = 5000

    packets = []

    # TCP handshake
    packets.append(
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="S",
            seq=client_seq,
        )
    )

    packets.append(
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    packets.append(
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    # OPC UA response from server -> client
    packets.append(
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="PA",
            seq=server_seq + 1,
            ack=client_seq + 1,
        )
        / Raw(payload)
    )

    packets.append(
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1 + len(payload),
        )
    )

    wrpcap(filename, packets)

    print(f"Wrote {filename}")
    print(f"DiagnosticInfo nesting depth: {depth}")
    print(f"OPC UA message length: {len(payload)} bytes")


if __name__ == "__main__":
    make_pcap("generated_pcaps/4843_nested_diaginfo_40.pcap", 40)
