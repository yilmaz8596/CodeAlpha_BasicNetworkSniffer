"""Windows IPv4 raw-socket sniffer using only the Python standard library."""

import socket
from collections import Counter

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
MAX_PREVIEW_BYTES = 16


def parse_packet(packet, show_payload=False):
    """Decode safe metadata from one IPv4 packet; return None if malformed."""
    if len(packet) < 20:
        return None

    first_byte = packet[0]
    ip_version = first_byte >> 4
    ihl = first_byte & 0x0F
    if ip_version != 4 or ihl < 5:
        return None

    header_length = ihl * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if total_length < header_length or len(packet) < total_length:
        return None
    packet = packet[:total_length]  

    protocol_number = packet[9]
    flags_fragment = int.from_bytes(packet[6:8], "big")
    fragment_offset = flags_fragment & 0x1FFF
    more_fragments = bool(flags_fragment & 0x2000)

    info = {
        "source_ip": socket.inet_ntoa(packet[12:16]),
        "destination_ip": socket.inet_ntoa(packet[16:20]),
        "protocol": PROTOCOL_NAMES.get(protocol_number, f"Other ({protocol_number})"),
        "length": total_length,
        "fragment_offset": fragment_offset,
        "more_fragments": more_fragments,
        "source_port": None,
        "destination_port": None,
        "icmp_type": None,
        "icmp_code": None,
        "payload_size": None,
        "payload_preview": None,
        "note": None,
    }

    if fragment_offset != 0:
        info["note"] = "Non-initial IPv4 fragment; transport fields omitted"
        return info

    payload_start = None
    if protocol_number in (6, 17):
        if len(packet) < header_length + 4:
            info["note"] = "Incomplete TCP/UDP port fields"
            return info

        info["source_port"] = int.from_bytes(
            packet[header_length:header_length + 2], "big"
        )
        info["destination_port"] = int.from_bytes(
            packet[header_length + 2:header_length + 4], "big"
        )

        if protocol_number == 17:  
            if len(packet) >= header_length + 8:
                payload_start = header_length + 8
            else:
                info["note"] = "Incomplete UDP header"
        else:  
            if len(packet) >= header_length + 20:
                tcp_header_length = (packet[header_length + 12] >> 4) * 4
                if tcp_header_length >= 20 and len(packet) >= header_length + tcp_header_length:
                    payload_start = header_length + tcp_header_length
                else:
                    info["note"] = "Invalid or incomplete TCP header"
            else:
                info["note"] = "Incomplete TCP header"

    elif protocol_number == 1:  
        if len(packet) >= header_length + 2:
            info["icmp_type"] = packet[header_length]
            info["icmp_code"] = packet[header_length + 1]
        if len(packet) >= header_length + 8:
            payload_start = header_length + 8
        else:
            info["note"] = "Incomplete ICMP header"

    if payload_start is not None:
        payload = packet[payload_start:]
        info["payload_size"] = len(payload)
        if show_payload and payload:
            info["payload_preview"] = payload[:MAX_PREVIEW_BYTES].hex(" ")

    return info


def display_packet(info, packet_number, show_payload=False):
    """Print a human-readable packet summary, without dumping raw bytes."""
    print(f"\n--- Packet {packet_number} ---")
    print(f"Source IP:       {info['source_ip']}")
    print(f"Destination IP:  {info['destination_ip']}")
    print(f"Protocol:        {info['protocol']}")
    print(f"Packet length:   {info['length']} bytes")
    if info["source_port"] is not None:
        print(f"Source port:     {info['source_port']}")
        print(f"Destination port:{info['destination_port']:>6}")
    if info["icmp_type"] is not None:
        print(f"ICMP type/code:  {info['icmp_type']}/{info['icmp_code']}")
    if info["fragment_offset"] or info["more_fragments"]:
        print(f"Fragment offset: {info['fragment_offset']} (8-byte units)")
        print(f"More fragments:  {info['more_fragments']}")
    if info["payload_size"] is not None:
        print(f"Payload length:  {info['payload_size']} bytes")
    if show_payload and info["payload_preview"]:
        print(f"Payload preview: {info['payload_preview']} (hex, max {MAX_PREVIEW_BYTES} bytes)")
    if info["note"]:
        print(f"Note:            {info['note']}")


def start_capture(interface_ip, packet_limit=10, show_payload=False):
    """Capture IPv4 packets from a local Windows adapter using a raw socket."""
    if not hasattr(socket, "SIO_RCVALL"):
        raise OSError("This capture mode requires Windows (SIO_RCVALL).")

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    receive_all_enabled = False
    counts = Counter()
    packet_count = 0

    try:
        raw_socket.bind((interface_ip, 0))
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        receive_all_enabled = True
        print(f"Listening on {interface_ip}; target: {packet_limit} valid IPv4 packets")
        print("Press Ctrl+C to stop early.\n")

        try:
            while packet_count < packet_limit:
                packet, _address = raw_socket.recvfrom(65535)
                info = parse_packet(packet, show_payload)
                if info is None:
                    continue

                packet_count += 1
                counts[info["protocol"]] += 1
                display_packet(info, packet_count, show_payload)
        except KeyboardInterrupt:
            print("\nCapture interrupted by user.")

        print("\n=== Capture summary ===")
        print(f"Valid IPv4 packets: {packet_count}")
        for protocol, count in sorted(counts.items()):
            print(f"{protocol}: {count}")

    finally:
        try:
            if receive_all_enabled:
                raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        finally:
            raw_socket.close()
