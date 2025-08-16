#!/usr/bin/env python3
import argparse, json, sys, time
from datetime import datetime

# Try scapy first
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap
    SCAPY_OK = True
except Exception as e:
    SCAPY_OK = False

def packet_to_record(pkt):
    rec = {
        "ts": datetime.utcfromtimestamp(float(pkt.time)).isoformat() + "Z" if hasattr(pkt, "time") else datetime.utcnow().isoformat() + "Z",
        "length": int(len(pkt)) if hasattr(pkt, "__len__") else None,
        "layers": [],
    }
    try:
        if IP in pkt:
            rec["src"] = pkt[IP].src
            rec["dst"] = pkt[IP].dst
            rec["proto"] = pkt[IP].proto
            rec["layers"].append("IP")
        if TCP in pkt:
            rec["sport"] = int(pkt[TCP].sport)
            rec["dport"] = int(pkt[TCP].dport)
            rec["layers"].append("TCP")
        if UDP in pkt:
            rec["sport"] = int(pkt[UDP].sport)
            rec["dport"] = int(pkt[UDP].dport)
            rec["layers"].append("UDP")
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            rec["payload_len"] = len(payload)
            # do not print raw payload by default for safety/privacy
            rec["has_payload"] = True
            rec["layers"].append("Raw")
    except Exception as e:
        rec["error"] = str(e)
    return rec

def main():
    ap = argparse.ArgumentParser(description="Basic Network Sniffer (CodeAlpha)")
    ap.add_argument("--iface", default=None, help="Interface to capture on (e.g., eth0, wlan0)")
    ap.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    ap.add_argument("--filter", default=None, help="BPF filter (e.g., 'tcp port 80')")
    ap.add_argument("--pcap", default=None, help="Write packets to PCAP file")
    ap.add_argument("--json", default=None, help="Write packet summary to JSON Lines")
    ap.add_argument("--quiet", action="store_true", help="Suppress console printing")
    args = ap.parse_args()

    if not SCAPY_OK:
        print("Scapy not available. Please `pip install scapy`.", file=sys.stderr)
        sys.exit(2)

    json_fh = open(args.json, "w", encoding="utf-8") if args.json else None
    captured = []

    def handle(pkt):
        rec = packet_to_record(pkt)
        if not args.quiet:
            print(json.dumps(rec, ensure_ascii=False))
        if json_fh:
            json_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        captured.append(pkt)

    sniff_kwargs = {"prn": handle, "count": args.count if args.count > 0 else 0}
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print("PermissionError: try running with sudo/admin privileges.", file=sys.stderr)
    finally:
        if args.pcap and captured:
            try:
                wrpcap(args.pcap, captured)
                if not args.quiet:
                    print(f"Wrote PCAP: {args.pcap}")
            except Exception as e:
                print(f"Failed to write PCAP: {e}", file=sys.stderr)
        if json_fh:
            json_fh.close()

if __name__ == "__main__":
    main()
