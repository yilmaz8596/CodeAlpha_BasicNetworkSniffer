# CodeAlpha — Basic Network Sniffer

A Python IPv4 packet sniffer for Windows, built with **only the Python standard library**. This project demonstrates raw socket capture, packet parsing, protocol identification, IPv4 fragmentation handling, and safe traffic summaries.

## Features

- Capture a chosen number of IPv4 packets from a local Windows network adapter.
- Read source/destination IP addresses, packet sizes, and protocol names (TCP, UDP, ICMP).
- Decode TCP/UDP source and destination port numbers when the first fragment has enough header data.
- Decode ICMP type and code.
- Calculate TCP, UDP, and ICMP payload sizes and optionally display the **first 16 bytes** as hexadecimal.
- Validate basic IPv4 header fields and avoid misinterpreting non-initial fragments.
- Display aggregate packet counts by protocol.
- Stop with Ctrl+C and clean up the raw socket.

## Requirements

- Windows with Python 3 installed (Python launcher `py` is fine).
- Administrator privileges to open a raw socket.
- No external packages required.

**Important:** This uses Windows `SIO_RCVALL` and IPv4 raw sockets. It does not capture Ethernet headers, MAC addresses, or IPv6 packets. Coverage is limited to IPv4 traffic visible to the selected adapter; it is not a full Wireshark replacement.

## Run

Open **PowerShell as Administrator** from the project directory. Use `ipconfig` to find the IPv4 address of the adapter you intend to monitor, then:

```powershell
py main.py --ip 192.168.1.114 --count 10
```

The address above is an **example from the development environment**; replace it if your adapter IP changes.

To opt in to a limited payload preview on traffic you are authorized to inspect:

```powershell
py main.py --ip 192.168.1.114 --count 10 --show-payload
```

To generate test traffic in a second PowerShell window:

```powershell
ping 192.168.1.1
```

Sample format (illustrative, not a claimed live capture):

```text
--- Packet 1 ---
Source IP:       192.168.1.114
Destination IP:  192.168.1.1
Protocol:        ICMP
Packet length:   60 bytes
ICMP type/code:  8/0
Payload length:  32 bytes

=== Capture summary ===
Valid IPv4 packets: 10
ICMP: 8
TCP: 2
```

## Offline tests

The parser can be tested on any operating system (no administrator permissions required):

```powershell
py -m unittest discover -s tests -v
```

The tests use generated example packet bytes and do not capture live traffic.

## How it works

1. `main.py` accepts command-line arguments.
2. `sniffer/capture.py` opens an IPv4 raw socket, binds to the selected IP address, and enables `SIO_RCVALL`.
3. `parse_packet()` validates IPv4 headers and extracts protocol-specific metadata.
4. `display_packet()` prints readable fields without dumping raw packet contents.
5. `start_capture()` records a protocol count and closes the socket in `finally`.

## Project structure

```text
CodeAlpha_BasicNetworkSniffer/
├── main.py
├── sniffer/
│   ├── __init__.py
│   └── capture.py
├── tests/
│   └── test_parser.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Security and limitations

Only monitor your own systems or networks for which you have explicit authorization. Use a controlled test such as pinging your own router. Even a small hex preview can disclose confidential data: do not enable `--show-payload` on sensitive traffic or upload such output to public repositories. Avoid publicly sharing private packet captures, authentication material, or personal network data. This tool performs basic parsing, not forensic-grade IPv4 reassembly or threat detection. The local IP may change when switching networks.

## CodeAlpha submission

1. Test live capture on Windows and run the offline unit tests.
2. Capture a screenshot of sanitized output (prefer the default mode **without** `--show-payload`).
3. Publish the repository as `CodeAlpha_BasicNetworkSniffer`.
4. Record a brief screen demonstration explaining raw socket capture and showing sanitized results; share the GitHub link in the LinkedIn post as requested in the CodeAlpha instructions.
5. Submit the task through the official form shared by CodeAlpha in its WhatsApp group.

**Submission status:** Source code and local unit tests are provided here. Live Windows behavior and the final submission must be verified by the intern.
