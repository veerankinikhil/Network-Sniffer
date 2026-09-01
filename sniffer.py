#!/usr/bin/env python3
"""
sniffer.py

Main CLI Application for CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer.

Usage:
  sudo python3 sniffer.py [options]

Examples:
  sudo python3 sniffer.py --interface eth0 --count 10
  sudo python3 sniffer.py --filter "tcp port 80" --verbose
  sudo python3 sniffer.py --output-json logs/packets.json --output-pcap logs/capture.pcap
  python3 sniffer.py --demo
"""

import argparse
import os
import sys
import time

# Ensure package root is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.packet_parser import ParsedPacket, parse_raw_packet
from utils.formatter import print_banner, format_packet_summary, print_packet_detail
from utils.logger import PacketLogger


def is_root() -> bool:
    """Check if script is executed with root / administrator privileges."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return True


def run_demo_mode(logger: PacketLogger, verbose: bool):
    """Generates synthetic network packets for demonstration without requiring root privileges."""
    print("[*] Running in DEMO / SIMULATION Mode (No root required)")
    print("[*] Generating synthetic Ethernet, IPv4, TCP, UDP, ICMP, and HTTP packets...\n")

    synthetic_frames = [
        # TCP HTTP GET request packet
        bytes.fromhex("000c29402941005056c0000808004500003c1c2d40004006b9e2c0a80105c0a80101005001bb0000000100000000a002faf0b8a40000020405b40402080a001122330000000001030307474554202f20485454502f312e310d0a"),
        # UDP DNS Query packet
        bytes.fromhex("000c29402941005056c000080800450000392b1a00004017367ec0a80105080808081f4000530025a1b21234010000010000000000000377777706676f6f676c6503636f6d0000010001"),
        # ICMP Echo Request packet
        bytes.fromhex("000c29402941005056c000080800450000544f4e4000400192eac0a80105c0a8010108004d5b0001000065a25b650000000056781234567812345678123456781234567812345678123456781234"),
        # ARP Request packet
        bytes.fromhex("ffffffffffff000c2940294108060001080006040001000c29402941c0a80105000000000000c0a80101"),
    ]

    for idx, raw_frame in enumerate(synthetic_frames, start=1):
        ts = time.time()
        parsed = parse_raw_packet(raw_frame, ts)
        
        logger.log_packet(parsed)

        if verbose:
            print_packet_detail(idx, parsed, show_hex=True)
        else:
            print(format_packet_summary(idx, parsed))
        
        time.sleep(0.5)

    print("\n[+] Demo simulation complete!")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1: Basic Network Sniffer in Python",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-i", "--interface", type=str, help="Network interface to bind (e.g. eth0, wlan0, en0)")
    parser.add_argument("-f", "--filter", type=str, help="BPF filter expression (e.g. 'tcp', 'udp port 53', 'host 192.168.1.1')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 = unlimited)")
    parser.add_argument("-o", "--output-json", type=str, help="Save parsed packet log to JSON file path")
    parser.add_argument("-p", "--output-pcap", type=str, help="Export captured raw packets to PCAP file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed multi-line payload & hex dumps")
    parser.add_argument("--raw-socket", action="store_true", help="Use native Python raw socket engine instead of Scapy")
    parser.add_argument("--demo", action="store_true", help="Run synthetic simulation without needing root privileges")

    args = parser.parse_args()

    logger = PacketLogger(json_filepath=args.output_json, pcap_filepath=args.output_pcap)

    if args.demo:
        run_demo_mode(logger, args.verbose)
        logger.save()
        sys.exit(0)

    # Check for root privilege
    if not is_root():
        print("[!] ERROR: Packet sniffing requires Administrator / root privileges.")
        print("[!] Please run with sudo:")
        print(f"    sudo python3 {' '.join(sys.argv)}")
        print("\n[*] Or run in simulation mode without root:")
        print("    python3 sniffer.py --demo\n")
        sys.exit(1)

    # Packet process callback
    def packet_callback(pkt_num: int, parsed_pkt: ParsedPacket, scapy_pkt=None):
        logger.log_packet(parsed_pkt, scapy_pkt)
        if args.verbose:
            print_packet_detail(pkt_num, parsed_pkt)
        else:
            print(format_packet_summary(pkt_num, parsed_pkt))

    # Engine selection
    use_scapy = not args.raw_socket
    if use_scapy:
        try:
            import scapy.all
        except ImportError:
            print("[!] Scapy package not detected. Falling back to native raw socket engine.")
            use_scapy = False

    if use_scapy:
        from core.scapy_engine import ScapySnifferEngine
        engine = ScapySnifferEngine(
            interface=args.interface,
            bpf_filter=args.filter,
            packet_count=args.count,
            callback=packet_callback
        )
    else:
        from core.raw_socket_engine import RawSocketEngine
        engine = RawSocketEngine(
            interface=args.interface,
            packet_count=args.count,
            callback=packet_callback
        )

    try:
        engine.start()
    except Exception as e:
        print(f"[-] Execution error: {e}")
    finally:
        logger.save()


if __name__ == "__main__":
    main()
