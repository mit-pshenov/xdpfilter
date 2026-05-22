#!/usr/bin/env python3
"""
read_stats.py — read the pinned `stats` BPF_MAP_TYPE_ARRAY via bpftool.

Usage:
    sudo python3 read_stats.py <pin_path>

The map (per design §3.4) is a 3-entry array of u64 counters keyed by
u32 indices STAT_PASS=0, STAT_DROP_DENY=1, STAT_DROP_MALFORMED=2.

Prints one line: "<pass> <drop_deny> <drop_malformed>".

Exit codes:
    0  on success
    2  if bpftool cannot read the map (pin missing, perms, etc.)
    3  if the JSON shape was not what we expected
"""
import json
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: read_stats.py <pin_path>", file=sys.stderr)
        return 1
    pin = sys.argv[1]

    try:
        out = subprocess.check_output(
            ["bpftool", "map", "dump", "pinned", pin, "--json"],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(f"bpftool failed: {e.stderr.decode(errors='replace').strip()}",
              file=sys.stderr)
        return 2

    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        print(f"bpftool emitted invalid JSON: {e}", file=sys.stderr)
        return 3

    # bpftool may wrap the array in a containing object on some versions.
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                data = v
                break

    stats: dict[int, int] = {}
    for entry in data:
        try:
            key_bytes = [int(x, 0) for x in entry["key"]]
            val_bytes = [int(x, 0) for x in entry["value"]]
        except (KeyError, TypeError, ValueError) as e:
            print(f"unexpected entry shape: {entry!r} ({e})", file=sys.stderr)
            return 3
        # key is u32 little-endian (4 bytes)
        k = 0
        for i in range(min(4, len(key_bytes))):
            k |= key_bytes[i] << (8 * i)
        # value is u64 little-endian (8 bytes)
        v = 0
        for i, b in enumerate(val_bytes[:8]):
            v |= b << (8 * i)
        stats[k] = v

    print(stats.get(0, 0), stats.get(1, 0), stats.get(2, 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
