# CodeAlpha Task 1: Basic Network Sniffer

A feature-rich, cross-platform Python Network Sniffer built for the **CodeAlpha Cybersecurity Internship**. This application captures live network traffic packets, decodes protocol headers across multiple network layers (Ethernet, IPv4, ARP, TCP, UDP, ICMP, HTTP, DNS), provides payload hex/ASCII inspection, supports BPF filtering, and logs output to JSON & `.pcap` files compatible with Wireshark.

---

## 🚀 Features

- **Multi-Protocol Packet Analysis**: Decodes Ethernet II, ARP, IPv4, TCP (ports & flags), UDP, ICMP, HTTP, and DNS.
- **Dual Sniffer Engines**:
  - **Scapy Engine**: High-level capture engine supporting Berkeley Packet Filters (BPF) and PCAP file exporting.
  - **Native Raw Socket Fallback**: Pure Python standard library (`socket` + `struct`) fallback for environments without external dependencies.
- **Payload Hex & ASCII Inspection**: Displays side-by-side hex dump and ASCII printable text for deep packet inspection.
- **Filtering & Controls**: BPF filtering strings (`tcp`, `udp port 53`, `host 192.168.1.1`), packet count limits (`-c`), and interface binding (`-i`).
- **Export & Logging**: Exports session packet summaries to structured `.json` and raw captures to `.pcap` format.
- **Non-Root Demo Mode**: Built-in `--demo` mode generates synthetic multi-protocol packets so you can run, test, and evaluate the sniffer without `sudo` privileges.

---

## 🛠️ Repository Structure

```text
CodeAlpha_BasicNetworkSniffer/
│── core/
│   ├── __init__.py
│   ├── packet_parser.py     # Binary packet header decoding & Scapy packet parser
│   ├── scapy_engine.py      # Scapy-powered packet capture engine
│   └── raw_socket_engine.py # Native Python raw socket fallback engine
│── utils/
│   ├── __init__.py
│   ├── formatter.py         # Colorized terminal output & hex dump formatter
│   └── logger.py            # JSON & PCAP logging module
│── tests/
│   ├── __init__.py
│   └── test_parser.py       # Automated unit tests with synthetic packet frames
│── sniffer.py               # Main CLI executable
│── requirements.txt         # Python package dependencies (scapy, colorama)
└── README.md                # Project documentation
```

---

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/YourUsername/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
```

### 2. Create a Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🖥️ Usage Guide

### 🌐 Web Dashboard (Browser UI Interface)
Start the real-time web dashboard:
```bash
PORT=5050 ./venv/bin/python3 web_app.py
```
Open your browser at **`http://127.0.0.1:5050`** to view live traffic streams, protocol breakdown pie charts, bandwidth graphs, and payload hex dumps.

---

> **Note**: Live raw packet sniffing requires root/administrator privileges (`sudo`). Demo simulation mode can be run without root.

### 1. Run Simulation / Demo Mode (No Root Required)
To verify formatting, packet parsing, and logging without `sudo`:
```bash
python3 sniffer.py --demo --verbose
```

### 2. Basic Live Packet Capture (Requires Root)
Capture 10 packets on default interface:
```bash
sudo ./venv/bin/python3 sniffer.py --count 10
```

### 3. Specify Network Interface & BPF Filter
Capture HTTP traffic on interface `eth0` (or `wlan0` / `en0` on macOS):
```bash
sudo ./venv/bin/python3 sniffer.py --interface eth0 --filter "tcp port 80"
```

### 4. Detailed Multi-Line Inspection with Payload Hex Dumps
```bash
sudo ./venv/bin/python3 sniffer.py --verbose --count 5
```

### 5. Save Captured Packets to JSON & PCAP Files
```bash
sudo ./venv/bin/python3 sniffer.py --count 20 --output-json logs/capture.json --output-pcap logs/capture.pcap
```

---

## 🧪 Running Automated Tests

You can run the unit test suite without root privileges using `unittest`:
```bash
python3 -m unittest discover tests
```

Sample output:
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.005s

OK
```

---

## 📊 Sample Output

```text
=================================================================
        CodeAlpha Cybersecurity Internship - Task 1
                  BASIC NETWORK SNIFFER
=================================================================
Author: CodeAlpha Intern
License: MIT Educational Use
Features: Real-time Packet Capture | BPF Filtering | PCAP Logging
-----------------------------------------------------------------

[#0001] [10:41:11.275] TCP   192.168.1.5:80        -> 192.168.1.1:443       Len: 90   TCP 80 -> 443 [SYN] Seq=1 (HTTP)
[#0002] [10:41:11.782] UDP   192.168.1.5:5353      -> 224.0.0.251:5353      Len: 74   UDP 5353 -> 5353 (DNS)
[#0003] [10:41:12.289] ICMP  192.168.1.5           -> 192.168.1.1           Len: 78   ICMP Echo Request (Code 0)
[#0004] [10:41:12.802] ARP   192.168.1.5           -> 192.168.1.1           Len: 42   ARP Request (192.168.1.5 -> 192.168.1.1)

[+] Saved 4 packet logs to JSON: logs/capture.json
[+] Exported 4 packets to PCAP: logs/capture.pcap
```

---

## 🔍 Wireshark Integration

Packets saved with `--output-pcap logs/capture.pcap` can be opened directly in **Wireshark** or analyzed using `tshark`:
```bash
tshark -r logs/capture.pcap
```

---

## ⚠️ Ethical Disclaimer & Usage

This tool is created strictly for **educational and research purposes** as part of the CodeAlpha Cybersecurity Internship Program. Capturing network traffic on networks without authorization is illegal and violates privacy policies. Always obtain explicit permission before monitoring network traffic.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.
