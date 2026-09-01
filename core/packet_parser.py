"""
core/packet_parser.py

Protocol decoding and packet parsing module for CodeAlpha Network Sniffer.
Parses both raw binary packet buffers (via socket/struct) and Scapy packet structures
into a unified ParsedPacket model.
"""

from dataclasses import dataclass, field
import datetime
import socket
import struct
from typing import Optional, Tuple, Dict, Any


@dataclass
class ParsedPacket:
    """Unified representation of a captured packet."""
    timestamp: float
    length: int
    src_mac: str = "00:00:00:00:00:00"
    dst_mac: str = "00:00:00:00:00:00"
    eth_proto_name: str = "Unknown"
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    ip_proto_name: str = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: str = ""
    payload: bytes = b""
    info: str = ""

    @property
    def formatted_time(self) -> str:
        """Returns ISO formatted timestamp string."""
        return datetime.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def transport_info(self) -> str:
        """Formatted source to destination socket tuple."""
        if self.src_port is not None and self.dst_port is not None:
            return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        return f"{self.src_ip} -> {self.dst_ip}"

    def to_dict(self) -> Dict[str, Any]:
        """Converts packet fields to serializable dictionary."""
        return {
            "timestamp": self.formatted_time,
            "length": self.length,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "eth_proto": self.eth_proto_name,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.ip_proto_name,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "info": self.info,
            "payload_hex": self.payload.hex(),
            "payload_ascii": extract_ascii_payload(self.payload)
        }


# Protocol Map Constants
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Tunn",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF"
}

ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN"
}


def mac_format(mac_bytes: bytes) -> str:
    """Format 6 bytes into colon-separated hex MAC address."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def extract_ascii_payload(payload: bytes, max_len: int = 256) -> str:
    """Extract printable ASCII characters from raw payload."""
    if not payload:
        return ""
    truncated = payload[:max_len]
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in truncated)


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Formats raw bytes into a traditional hex dump string (address, hex, ASCII)."""
    if not data:
        return "   [Empty Payload]"
    
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"   {i:04x}   {hex_str:<{bytes_per_line*3}}   {ascii_str}")
    return "\n".join(lines)


def parse_raw_packet(raw_bytes: bytes, timestamp: float) -> ParsedPacket:
    """
    Parses a raw Ethernet frame into a ParsedPacket dataclass using Python struct unpacking.
    Supports Ethernet, IPv4, TCP, UDP, ICMP, and ARP.
    """
    length = len(raw_bytes)
    if length < 14:
        return ParsedPacket(timestamp=timestamp, length=length, info="Truncated Frame (<14 bytes)")

    # Ethernet Header (14 bytes)
    dst_mac_b, src_mac_b, eth_proto_num = struct.unpack("! 6s 6s H", raw_bytes[:14])
    src_mac = mac_format(src_mac_b)
    dst_mac = mac_format(dst_mac_b)
    eth_proto_name = ETHER_TYPES.get(eth_proto_num, f"0x{eth_proto_num:04x}")

    packet_data = raw_bytes[14:]

    # ARP Packet
    if eth_proto_num == 0x0806 and len(packet_data) >= 28:
        hw_type, proto_type, hw_len, proto_len, opcode, s_mac, s_ip, d_mac, d_ip = struct.unpack(
            "! HHBBH 6s 4s 6s 4s", packet_data[:28]
        )
        src_ip_str = socket.inet_ntoa(s_ip)
        dst_ip_str = socket.inet_ntoa(d_ip)
        op_name = "Request" if opcode == 1 else "Reply" if opcode == 2 else f"Op:{opcode}"
        return ParsedPacket(
            timestamp=timestamp,
            length=length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_proto_name=eth_proto_name,
            src_ip=src_ip_str,
            dst_ip=dst_ip_str,
            ip_proto_name="ARP",
            info=f"ARP {op_name} ({src_ip_str} -> {dst_ip_str})"
        )

    # Non-IPv4 fallback
    if eth_proto_num != 0x0800:
        return ParsedPacket(
            timestamp=timestamp,
            length=length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_proto_name=eth_proto_name,
            payload=packet_data,
            info=f"Ethernet Frame Protocol: {eth_proto_name}"
        )

    # IPv4 Header Parsing
    if len(packet_data) < 20:
        return ParsedPacket(
            timestamp=timestamp,
            length=length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_proto_name=eth_proto_name,
            info="Malformed IPv4 Header"
        )

    version_ihl = packet_data[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(packet_data) < ihl:
        return ParsedPacket(
            timestamp=timestamp,
            length=length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_proto_name=eth_proto_name,
            info="Truncated IPv4 Header"
        )

    ttl, proto_num, src_ip_raw, dst_ip_raw = struct.unpack("! B B 2x 4s 4s", packet_data[8:20])
    src_ip = socket.inet_ntoa(src_ip_raw)
    dst_ip = socket.inet_ntoa(dst_ip_raw)
    ip_proto_name = IP_PROTOCOLS.get(proto_num, f"PROTO-{proto_num}")

    ip_payload = packet_data[ihl:]

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: str = ""
    info: str = ""
    app_payload: bytes = b""

    # TCP Parsing
    if proto_num == 6 and len(ip_payload) >= 20:
        src_port, dst_port, seq, ack_num, offset_reserved_flags = struct.unpack("! HH II H", ip_payload[:14])
        tcp_header_len = ((offset_reserved_flags >> 12) & 0x0F) * 4
        
        # Parse Flags
        flag_bits = offset_reserved_flags & 0x003F
        flag_list = []
        if flag_bits & 0x20: flag_list.append("URG")
        if flag_bits & 0x10: flag_list.append("ACK")
        if flag_bits & 0x08: flag_list.append("PSH")
        if flag_bits & 0x04: flag_list.append("RST")
        if flag_bits & 0x02: flag_list.append("SYN")
        if flag_bits & 0x01: flag_list.append("FIN")
        flags = ",".join(flag_list)

        app_payload = ip_payload[tcp_header_len:]
        info = f"TCP {src_port} -> {dst_port} [{flags}] Seq={seq}"

        # Application Protocol Detection
        if src_port in (80, 8080) or dst_port in (80, 8080):
            if app_payload.startswith(b"GET ") or app_payload.startswith(b"POST ") or app_payload.startswith(b"HTTP/"):
                host_info = ""
                payload_str = app_payload.decode("utf-8", errors="ignore")
                for line in payload_str.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host_info = f" [{line.strip()}]"
                        break
                info += f" (HTTP{host_info})"

    # UDP Parsing
    elif proto_num == 17 and len(ip_payload) >= 8:
        src_port, dst_port, udp_len = struct.unpack("! HH H 2x", ip_payload[:8])
        app_payload = ip_payload[8:]
        info = f"UDP {src_port} -> {dst_port} Len={udp_len}"

        if src_port == 53 or dst_port == 53:
            info += " (DNS)"

    # ICMP Parsing
    elif proto_num == 1 and len(ip_payload) >= 4:
        icmp_type, icmp_code = struct.unpack("! BB", ip_payload[:2])
        app_payload = ip_payload[4:]
        type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
        icmp_str = type_names.get(icmp_type, f"Type {icmp_type}")
        info = f"ICMP {icmp_str} (Code {icmp_code})"

    else:
        app_payload = ip_payload
        info = f"IP Protocol {ip_proto_name} (Length {len(ip_payload)})"

    return ParsedPacket(
        timestamp=timestamp,
        length=length,
        src_mac=src_mac,
        dst_mac=dst_mac,
        eth_proto_name=eth_proto_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_proto_name=ip_proto_name,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags,
        payload=app_payload,
        info=info
    )


def parse_scapy_packet(pkt) -> ParsedPacket:
    """Converts a Scapy packet object into a ParsedPacket model."""
    import time
    ts = float(getattr(pkt, 'time', time.time()))
    length = len(pkt)

    src_mac = "00:00:00:00:00:00"
    dst_mac = "00:00:00:00:00:00"
    eth_proto_name = "Unknown"
    
    if pkt.haslayer("Ether"):
        src_mac = pkt["Ether"].src
        dst_mac = pkt["Ether"].dst
        eth_proto_name = ETHER_TYPES.get(pkt["Ether"].type, f"0x{pkt['Ether'].type:04x}")

    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    ip_proto_name = "OTHER"
    src_port = None
    dst_port = None
    flags = ""
    info = ""
    payload = b""

    if pkt.haslayer("IP"):
        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst
        ip_proto_name = IP_PROTOCOLS.get(pkt["IP"].proto, str(pkt["IP"].proto))
    elif pkt.haslayer("IPv6"):
        src_ip = pkt["IPv6"].src
        dst_ip = pkt["IPv6"].dst
        ip_proto_name = "IPv6"
    elif pkt.haslayer("ARP"):
        src_ip = pkt["ARP"].psrc
        dst_ip = pkt["ARP"].pdst
        ip_proto_name = "ARP"
        info = f"ARP {'Request' if pkt['ARP'].op == 1 else 'Reply'} ({src_ip} -> {dst_ip})"

    if pkt.haslayer("TCP"):
        src_port = pkt["TCP"].sport
        dst_port = pkt["TCP"].dport
        flags = str(pkt["TCP"].flags)
        ip_proto_name = "TCP"
        info = f"TCP {src_port} -> {dst_port} [{flags}]"
    elif pkt.haslayer("UDP"):
        src_port = pkt["UDP"].sport
        dst_port = pkt["UDP"].dport
        ip_proto_name = "UDP"
        info = f"UDP {src_port} -> {dst_port}"
    elif pkt.haslayer("ICMP"):
        ip_proto_name = "ICMP"
        info = f"ICMP Type {pkt['ICMP'].type} Code {pkt['ICMP'].code}"

    if pkt.haslayer("Raw"):
        payload = bytes(pkt["Raw"].load)

    if not info:
        info = f"{ip_proto_name} Packet ({length} bytes)"

    return ParsedPacket(
        timestamp=ts,
        length=length,
        src_mac=src_mac,
        dst_mac=dst_mac,
        eth_proto_name=eth_proto_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_proto_name=ip_proto_name,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags,
        payload=payload,
        info=info
    )
