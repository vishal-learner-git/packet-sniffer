import argparse
import os
import sys
import threading
import time

from netsentry.api.routes import create_app
from netsentry.core.logger import close_pcap_writers, log_alert, log_packet, log_raw_packet
from netsentry.core.parser import parse_packet
from netsentry.core.pipeline import process_packet
from netsentry.core.sniffer import replay_pcap, start_sniffing
from netsentry.detection.engine import DetectionEngine
from netsentry.utils.config import DEFAULT_CAPTURE_PCAP_FILE
from netsentry.utils.stats import StatsAggregator


def build_packet_pipeline(engine, stats, save_pcap_path=None):
    """Return one shared pipeline callback for live capture and PCAP replay."""

    def packet_callback(packet):
        process_packet(
            packet=packet,
            parser=parse_packet,
            stats=stats,
            detection_engine=engine,
            packet_logger=log_packet,
            alert_logger=log_alert,
            raw_packet_logger=(lambda raw_packet: log_raw_packet(raw_packet, save_pcap_path)) if save_pcap_path else None,
        )

    return packet_callback


def start_dashboard(engine, stats, port):
    """Run the Flask dashboard in a background thread."""
    app = create_app(engine, stats)
    api_thread = threading.Thread(
        target=app.run,
        kwargs={"host": "0.0.0.0", "port": port, "debug": False, "use_reloader": False},
    )
    api_thread.daemon = True
    api_thread.start()
    print(f"[*] Dashboard API live at http://127.0.0.1:{port}")
    return api_thread


def keep_dashboard_alive():
    """Keep the process alive after batch PCAP replay so the UI can be explored."""
    print("[*] PCAP analysis finished. Dashboard remains available until you press Ctrl+C.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down NetSentry...")


def validate_args(args):
    if args.pcap_file and args.interface:
        print("[!] Use either live capture (--interface) or offline analysis (--pcap-file), not both.")
        sys.exit(1)

    if args.pcap_file and not os.path.exists(args.pcap_file):
        print(f"[!] PCAP file not found: {args.pcap_file}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="NetSentry: Professional Network Threat Monitor"
    )
    parser.add_argument("--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("--count", type=int, help="Number of packets to capture or replay (0 for all)", default=0)
    parser.add_argument("--port", type=int, help="Dashboard API port", default=5001)
    parser.add_argument("--no-ui", action="store_true", help="Run without the dashboard API")
    parser.add_argument("--pcap-file", help="Analyze packets from an existing PCAP file instead of live capture")
    parser.add_argument(
        "--save-pcap",
        nargs="?",
        const=DEFAULT_CAPTURE_PCAP_FILE,
        default=None,
        help="Optionally save processed raw packets to a PCAP file. If no path is given, logs/captured_traffic.pcap is used.",
    )
    args = parser.parse_args()

    validate_args(args)

    engine = DetectionEngine()
    stats = StatsAggregator()
    packet_callback = build_packet_pipeline(engine, stats, save_pcap_path=args.save_pcap)

    if not args.no_ui:
        start_dashboard(engine, stats, args.port)

    try:
        if args.pcap_file:
            replay_pcap(packet_callback, args.pcap_file, count=args.count)
            if args.no_ui:
                print("[*] PCAP analysis complete.")
            else:
                keep_dashboard_alive()
        else:
            start_sniffing(packet_callback, count=args.count, interface=args.interface)
    except KeyboardInterrupt:
        print("\n[!] Shutting down NetSentry...")
        sys.exit(0)
    finally:
        close_pcap_writers()


if __name__ == "__main__":
    main()
