"""
utils/formatter.py

Terminal output formatting utility for CodeAlpha Network Sniffer.
Provides colorized output, banners, and packet detail display.
"""

import sys
from typing import Optional

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class DummyColor:
        def __getattr__(self, name):
            return ""

    Fore = DummyColor()
    Style = DummyColor()


def get_protocol_color(protocol: str) -> str:
    """Return color string corresponding to network protocol."""
    proto = protocol.upper()
    if "TCP" in proto:
        return Fore.CYAN
    elif "UDP" in proto:
        return Fore.GREEN
    elif "ICMP" in proto:
        return Fore.YELLOW
    elif "ARP" in proto:
        return Fore.MAGENTA
    elif "HTTP" in proto:
        return Fore.LIGHTBLUE_EX
    elif "DNS" in proto:
        return Fore.LIGHTGREEN_EX
    return Fore.WHITE


def print_banner():
    """Prints tool banner."""
    banner = f"""
{Fore.CYAN}================================================================={Style.RESET_ALL}
{Fore.GREEN}        CodeAlpha Cybersecurity Internship - Task 1{Style.RESET_ALL}
{Fore.YELLOW}                  BASIC NETWORK SNIFFER{Style.RESET_ALL}
{Fore.CYAN}================================================================={Style.RESET_ALL}
{Fore.WHITE}Author: CodeAlpha Intern
License: MIT Educational Use
Features: Real-time Packet Capture | BPF Filtering | PCAP Logging{Style.RESET_ALL}
{Fore.CYAN}-----------------------------------------------------------------{Style.RESET_ALL}
"""
    print(banner)


def format_packet_summary(pkt_num: int, packet) -> str:
    """Formats single-line summary of captured packet."""
    color = get_protocol_color(packet.ip_proto_name)
    
    src_str = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip
    dst_str = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip

    summary = (
        f"{Fore.WHITE}[#{pkt_num:04d}]{Style.RESET_ALL} "
        f"[{packet.formatted_time}] "
        f"{color}{packet.ip_proto_name:<5}{Style.RESET_ALL} "
        f"{src_str:<21} -> {dst_str:<21} "
        f"Len: {packet.length:<4} "
        f"{packet.info}"
    )
    return summary


def print_packet_detail(pkt_num: int, packet, show_hex: bool = True):
    """Prints full multi-line details for a captured packet."""
    color = get_protocol_color(packet.ip_proto_name)
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}PACKET #{pkt_num:04d} DETAILS{Style.RESET_ALL} | Timestamp: {packet.formatted_time} | Length: {packet.length} bytes")
    print(f"{Fore.CYAN}{'-'*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Ethernet Layer:{Style.RESET_ALL} MAC {packet.src_mac} -> {packet.dst_mac} ({packet.eth_proto_name})")
    
    if packet.src_port and packet.dst_port:
        print(f"  {Fore.WHITE}IP/Transport Layer:{Style.RESET_ALL} {color}{packet.ip_proto_name}{Style.RESET_ALL} {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
    else:
        print(f"  {Fore.WHITE}IP Layer:{Style.RESET_ALL} {color}{packet.ip_proto_name}{Style.RESET_ALL} {packet.src_ip} -> {packet.dst_ip}")
        
    if packet.flags:
        print(f"  {Fore.WHITE}TCP Flags:{Style.RESET_ALL} {packet.flags}")
        
    print(f"  {Fore.WHITE}Info:{Style.RESET_ALL} {packet.info}")

    if packet.payload:
        print(f"\n  {Fore.YELLOW}Payload ({len(packet.payload)} bytes):{Style.RESET_ALL}")
        from core.packet_parser import format_hex_dump, extract_ascii_payload
        
        ascii_view = extract_ascii_payload(packet.payload, max_len=128)
        print(f"  {Fore.GREEN}ASCII Preview:{Style.RESET_ALL} {ascii_view}")
        
        if show_hex:
            print(f"  {Fore.WHITE}Hex Dump:{Style.RESET_ALL}")
            print(format_hex_dump(packet.payload[:128]))
    else:
        print(f"  {Fore.WHITE}Payload:{Style.RESET_ALL} [No Payload]")
        
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
