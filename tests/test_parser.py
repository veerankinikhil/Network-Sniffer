"""
tests/test_parser.py

Unit test suite for CodeAlpha Network Sniffer packet parsing & logger logic.
Runs without administrative / root permissions using synthetic binary frames.
"""

import json
import os
import tempfile
import time
import unittest

from core.packet_parser import (
    parse_raw_packet,
    extract_ascii_payload,
    format_hex_dump,
    ParsedPacket,
    ETHER_TYPES,
    IP_PROTOCOLS
)
from utils.logger import PacketLogger


class TestPacketParser(unittest.TestCase):
    """Test suite for binary packet parsing and protocol decoding."""

    def setUp(self):
        # Synthetic Ethernet + IPv4 + TCP packet frame
        self.tcp_frame = bytes.fromhex(
            "000c29402941005056c000080800"  # Ethernet Header: Dest MAC, Src MAC, EthType 0x0800 (IPv4)
            "4500003c1c2d40004006b9e2c0a80105c0a80101"  # IPv4 Header: Src IP 192.168.1.5, Dst IP 192.168.1.1, Proto TCP (6)
            "005001bb0000000100000000a002faf0b8a40000"  # TCP Header: Src Port 80, Dst Port 443, SYN flag
            "020405b40402080a001122330000000001030307"  # TCP Options
            "48656c6c6f20576f726c64"                    # Payload: "Hello World"
        )

        # Synthetic Ethernet + ARP Request frame
        self.arp_frame = bytes.fromhex(
            "ffffffffffff000c294029410806"              # Ethernet: Broadcast, EthType 0x0806 (ARP)
            "0001080006040001"                          # ARP Hardware/Proto type, lengths, Opcode 1 (Request)
            "000c29402941c0a80105"                      # Sender MAC/IP (192.168.1.5)
            "000000000000c0a80101"                      # Target MAC/IP (192.168.1.1)
        )

    def test_tcp_packet_parsing(self):
        ts = time.time()
        parsed = parse_raw_packet(self.tcp_frame, ts)

        self.assertEqual(parsed.eth_proto_name, "IPv4")
        self.assertEqual(parsed.src_ip, "192.168.1.5")
        self.assertEqual(parsed.dst_ip, "192.168.1.1")
        self.assertEqual(parsed.ip_proto_name, "TCP")
        self.assertEqual(parsed.src_port, 80)
        self.assertEqual(parsed.dst_port, 443)
        self.assertIn("SYN", parsed.flags)
        self.assertEqual(parsed.payload, b"Hello World")

    def test_arp_packet_parsing(self):
        ts = time.time()
        parsed = parse_raw_packet(self.arp_frame, ts)

        self.assertEqual(parsed.eth_proto_name, "ARP")
        self.assertEqual(parsed.ip_proto_name, "ARP")
        self.assertEqual(parsed.src_ip, "192.168.1.5")
        self.assertEqual(parsed.dst_ip, "192.168.1.1")
        self.assertIn("Request", parsed.info)

    def test_ascii_extraction(self):
        payload = b"Hello\x00World\x07!"
        ascii_text = extract_ascii_payload(payload)
        self.assertEqual(ascii_text, "Hello.World.!")

    def test_hex_dump_formatting(self):
        payload = b"Test Payload Data 12345"
        hex_dump = format_hex_dump(payload)
        self.assertIn("54 65 73 74", hex_dump)
        self.assertIn("Test Payload", hex_dump)

    def test_logger_json_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "test_log.json")
            logger = PacketLogger(json_filepath=json_path)

            ts = time.time()
            parsed = parse_raw_packet(self.tcp_frame, ts)
            logger.log_packet(parsed)
            logger.save()

            self.assertTrue(os.path.exists(json_path))
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.assertEqual(len(data), 1)
                self.assertEqual(data[0]["protocol"], "TCP")
                self.assertEqual(data[0]["src_ip"], "192.168.1.5")


if __name__ == "__main__":
    unittest.main()
