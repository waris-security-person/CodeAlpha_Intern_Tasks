#!/usr/bin/env python3
import argparse, json, collections, os, sys

def analyze_json(json_path):
    protos = collections.Counter()
    talkers = collections.Counter()
    n = 0
    with open(json_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n += 1
            src = rec.get("src", "?")
            dst = rec.get("dst", "?")
            proto = rec.get("proto", "?")
            talkers[src] += 1
            protos[proto] += 1
    return n, protos, talkers

def main():
    ap = argparse.ArgumentParser(description="Analyze captured packets")
    ap.add_argument("--json", help="JSONL file produced by sniffer.py", default=None)
    ap.add_argument("--pcap", help="Optional PCAP path (not required for basic analysis)", default=None)
    args = ap.parse_args()

    if not args.json or not os.path.exists(args.json):
        print("Provide --json JSONL path from sniffer.py", file=sys.stderr); sys.exit(2)

    n, protos, talkers = analyze_json(args.json)

    print(f"Packets analyzed: {n}")
    print("\nTop protocols:")
    for k, v in protos.most_common(10):
        print(f"  {k}: {v}")
    print("\nTop talkers (src IP):")
    for k, v in talkers.most_common(10):
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
