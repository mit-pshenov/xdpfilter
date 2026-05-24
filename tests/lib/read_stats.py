#!/usr/bin/env python3
"""
read_stats.py — read the pinned `stats` BPF_MAP_TYPE_PERCPU_ARRAY via bpftool.

Usage:
    sudo python3 read_stats.py <pin_path>
    sudo python3 read_stats.py --include-pass-cidr <pin_path>   # §5.27 (MVP-3.2)

The map (per design §3.4, post-§5.23 MVP-2 Perf, post-§5.27 MVP-3.2) is a
PERCPU array of u64 counters keyed by u32 indices STAT_PASS=0,
STAT_DROP_DENY=1, STAT_DROP_MALFORMED=2, STAT_PASS_CIDR=3 (§5.27 NEW).
Each entry has a per-CPU `values` array (plural — schema differs from
non-PERCPU maps' singular `value`); we SUM across CPUs.

Default output (back-compat with all pre-§5.27 callers — PI-13-3.2):
    "<pass> <drop_deny> <drop_malformed>"

With --include-pass-cidr (§5.27 opt-in 4-column reader):
    "<pass> <drop_deny> <drop_malformed> <pass_cidr>"

Exit codes:
    0  on success
    1  on argument-parse error
    2  if bpftool cannot read the map (pin missing, perms, etc.)
    3  if the JSON shape was not what we expected
"""
import json
import subprocess
import sys


def _decode_le_u64(byte_seq) -> int:
    """Convert a little-endian byte array (list of "0xNN" strings or ints)
    into a u64. Tolerates short arrays by zero-padding to 8 bytes."""
    v = 0
    for i, b in enumerate(byte_seq[:8]):
        if isinstance(b, str):
            b = int(b, 0)
        v |= b << (8 * i)
    return v


def _decode_key_u32(byte_seq) -> int:
    """Convert a little-endian byte array into a u32 (first 4 bytes)."""
    k = 0
    for i in range(min(4, len(byte_seq))):
        b = byte_seq[i]
        if isinstance(b, str):
            b = int(b, 0)
        k |= b << (8 * i)
    return k


def main() -> int:
    # §5.27 (MVP-3.2): accept optional `--include-pass-cidr` flag in either
    # position relative to <pin_path>. Default output (no flag) is BYTE-
    # IDENTICAL to pre-§5.27 — PI-13-3.2 back-compat for the 27 existing
    # ctests that read the 3-column shape.
    include_pass_cidr = False
    argv = sys.argv[1:]
    filtered = []
    for arg in argv:
        if arg == "--include-pass-cidr":
            include_pass_cidr = True
        else:
            filtered.append(arg)
    if len(filtered) != 1:
        print("usage: read_stats.py [--include-pass-cidr] <pin_path>", file=sys.stderr)
        return 1
    pin = filtered[0]

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
            key_bytes = entry["key"]
        except (KeyError, TypeError) as e:
            print(f"unexpected entry shape (no key): {entry!r} ({e})",
                  file=sys.stderr)
            return 3
        k = _decode_key_u32(key_bytes)

        # PERCPU schema: entry["values"] is a list of per-CPU records,
        # each shaped {"cpu": <int>, "value": [<bytes>]}. Sum across CPUs.
        # Defensive fallback: if some bpftool version emits singular "value"
        # for a PERCPU map, treat that as a single-CPU shape.
        total = 0
        if "values" in entry:
            try:
                for per_cpu in entry["values"]:
                    total += _decode_le_u64(per_cpu["value"])
            except (KeyError, TypeError, ValueError) as e:
                print(f"unexpected per-cpu entry shape: {entry!r} ({e})",
                      file=sys.stderr)
                return 3
        elif "value" in entry:
            try:
                total = _decode_le_u64(entry["value"])
            except (TypeError, ValueError) as e:
                print(f"unexpected value shape: {entry!r} ({e})",
                      file=sys.stderr)
                return 3
        else:
            print(f"entry missing both 'values' and 'value': {entry!r}",
                  file=sys.stderr)
            return 3

        stats[k] = total

    if include_pass_cidr:
        print(stats.get(0, 0), stats.get(1, 0), stats.get(2, 0), stats.get(3, 0))
    else:
        print(stats.get(0, 0), stats.get(1, 0), stats.get(2, 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
