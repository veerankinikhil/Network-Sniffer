"""
core/scapy_engine.py

Scapy-powered network packet capture engine.
Supports network interface binding, BPF filtering, count limits, and PCAP logging.
"""

import sys
import time
from typing import Callable, Optional
from core.packet_parser import parse_scapy_packet, ParsedPacket


class ScapySnifferEngine:
    """Sniffer engine powered by Scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        timeout: Optional[int] = None,
        callback: Optional[Callable[[int, ParsedPacket, any], None]] = None
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.timeout = timeout
        self.callback = callback
        self.captured_count = 0
        self.is_running = False

    def start(self):
        """Starts sniffing using Scapy sniff function."""
        try:
            from scapy.all import sniff, conf
        except ImportError:
            raise RuntimeError("Scapy is not installed. Please install scapy using 'pip install scapy'.")

        self.is_running = True
        self.captured_count = 0

        print(f"[*] Initializing Scapy Sniffer Engine...")
        if self.interface:
            print(f"[*] Bound to Network Interface: {self.interface}")
        else:
            default_iface = conf.iface
            print(f"[*] Using Default Network Interface: {default_iface}")

        if self.bpf_filter:
            print(f"[*] Applied BPF Filter: '{self.bpf_filter}'")

        if self.packet_count > 0:
            print(f"[*] Target Packet Count: {self.packet_count}")
        else:
            print("[*] Capturing continuously. Press Ctrl+C to stop.")

        def _packet_handler(pkt):
            if not self.is_running:
                return
            self.captured_count += 1
            parsed = parse_scapy_packet(pkt)
            if self.callback:
                self.callback(self.captured_count, parsed, pkt)

        try:
            sniff_args = {
                "prn": _packet_handler,
                "store": False
            }
            if self.interface:
                sniff_args["iface"] = self.interface
            if self.bpf_filter:
                sniff_args["filter"] = self.bpf_filter
            if self.packet_count > 0:
                sniff_args["count"] = self.packet_count
            if self.timeout is not None:
                sniff_args["timeout"] = self.timeout

            sniff(**sniff_args)
        except KeyboardInterrupt:
            print("\n[*] Sniffing stopped by user (Ctrl+C).")
        except Exception as e:
            print(f"[-] Scapy capture error: {e}")
        finally:
            self.is_running = False
            print(f"[*] Scapy session completed. Total packets captured: {self.captured_count}")
