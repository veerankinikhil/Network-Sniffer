"""
utils/logger.py

Logging and packet dump utility for CodeAlpha Network Sniffer.
Handles writing session packet logs to JSON and saving PCAP files.
"""

import json
import os
from typing import List, Optional
from core.packet_parser import ParsedPacket


class PacketLogger:
    """Handles logging parsed packets to JSON and PCAP output files."""

    def __init__(self, json_filepath: Optional[str] = None, pcap_filepath: Optional[str] = None):
        self.json_filepath = json_filepath
        self.pcap_filepath = pcap_filepath
        self.packets_data: List[dict] = []
        self.scapy_packets = []

    def log_packet(self, parsed_pkt: ParsedPacket, scapy_pkt=None):
        """Append parsed packet details to internal log buffer."""
        self.packets_data.append(parsed_pkt.to_dict())
        if scapy_pkt is not None:
            self.scapy_packets.append(scapy_pkt)

    def save(self):
        """Write accumulated packet logs to specified file formats."""
        if self.json_filepath:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.json_filepath)), exist_ok=True)
                with open(self.json_filepath, "w", encoding="utf-8") as f:
                    json.dump(self.packets_data, f, indent=2)
                print(f"[+] Saved {len(self.packets_data)} packet logs to JSON: {self.json_filepath}")
            except Exception as e:
                print(f"[-] Failed to save JSON log: {e}")

        if self.pcap_filepath and self.scapy_packets:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.pcap_filepath)), exist_ok=True)
                from scapy.all import wrpcap
                wrpcap(self.pcap_filepath, self.scapy_packets)
                print(f"[+] Exported {len(self.scapy_packets)} packets to PCAP: {self.pcap_filepath}")
            except Exception as e:
                print(f"[-] Failed to save PCAP file: {e}")
