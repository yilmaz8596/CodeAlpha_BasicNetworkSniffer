"""Command-line entry point for the CodeAlpha Basic Network Sniffer."""

import argparse

from sniffer.capture import start_capture


def main():
    parser = argparse.ArgumentParser(
        description="Capture and inspect IPv4 packets on a Windows network adapter."
    )
    parser.add_argument(
        "--ip", required=True,
        help="Local IPv4 address of the Windows adapter (find it with ipconfig)."
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of valid IPv4 packets to capture (default: 10)."
    )
    parser.add_argument(
        "--show-payload", action="store_true",
        help="Show up to 16 payload bytes as hex (only on authorized traffic)."
    )
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    print("=== CodeAlpha Basic Network Sniffer ===")
    try:
        start_capture(args.ip, args.count, args.show_payload)
    except OSError as exc:
        parser.exit(
            1,
            f"Network capture failed: {exc}\n"
            "Run PowerShell as Administrator, and check the adapter IP with ipconfig.\n"
        )


if __name__ == "__main__":
    main()
