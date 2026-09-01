"""
core/raw_socket_engine.py

Pure Python raw socket network packet capture engine.
Uses native socket and struct unpacking without third-party library dependencies.
"""

import sys
import socket
import time
from typing import Callable, Optional
from core.packet_parser import parse_raw_packet, ParsedPacket


class RawSocketEngine:
    """Fallback sniffer engine using Python's native socket module."""

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_count: int = 0,
        callback: Optional[Callable[[int, ParsedPacket, any], None]] = None
    ):
        self.interface = interface
        self.packet_count = packet_count
        self.callback = callback
        self.captured_count = 0
        self.is_running = False

    def _create_raw_socket(self) -> socket.socket:
        """Create OS-appropriate raw socket."""
        try:
            # Linux raw packet socket
            if hasattr(socket, "AF_PACKET"):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    sock.bind((self.interface, 0))
                return sock
            # macOS / BSD / Windows raw socket
            elif sys.platform == "darwin" or sys.platform.startswith("freebsd"):
                # On macOS raw BPF socket or AF_INET raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                return sock
            elif sys.platform == "win32":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind(("0.0.0.0", 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                return sock
        except PermissionError:
            raise PermissionError("Raw socket creation requires administrator/root privileges (sudo).")
        except Exception as e:
            raise RuntimeError(f"Failed to create raw socket: {e}")

    def start(self):
        """Start raw socket packet capture loop."""
        sock = self._create_raw_socket()
        self.is_running = True
        self.captured_count = 0

        print(f"[*] Initializing Native Raw Socket Engine...")
        if self.interface:
            print(f"[*] Interface: {self.interface}")
        if self.packet_count > 0:
            print(f"[*] Target Packet Count: {self.packet_count}")
        else:
            print("[*] Capturing continuously. Press Ctrl+C to stop.")

        try:
            while self.is_running:
                raw_data, _ = sock.recvfrom(65535)
                ts = time.time()
                self.captured_count += 1
                
                parsed = parse_raw_packet(raw_data, ts)
                if self.callback:
                    self.callback(self.captured_count, parsed, None)

                if self.packet_count > 0 and self.captured_count >= self.packet_count:
                    break
        except KeyboardInterrupt:
            print("\n[*] Raw socket sniffing stopped by user (Ctrl+C).")
        except Exception as e:
            print(f"[-] Raw socket capture error: {e}")
        finally:
            self.is_running = False
            if sys.platform == "win32":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            sock.close()
            print(f"[*] Native raw socket session completed. Total packets: {self.captured_count}")
