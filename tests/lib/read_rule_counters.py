#!/usr/bin/env python3
"""
read_rule_counters.py — read the pinned `rule_counters` BPF_MAP_TYPE_PERCPU_ARRAY
via bpftool, summing across CPUs.

Sister tool to read_stats.py (design §5.31 / MVP-3.4b cycle 1).

The map (per design §5.31 DataStructures) is a PERCPU_ARRAY of __u64
counters with max_entries = XDPMF_ALLOWLIST_MAX = 64. Index k is the
operator's YAML `id:` field for the rule that matched (per Q5 R1).
Pinned at ${PIN_DIR}/<iface>/rule_counters.

Usage:
    sudo python3 read_rule_counters.py <pin_path>          # all 64 slots
    sudo python3 read_rule_counters.py <pin_path> <id>     # single slot

Output:
    Without <id>:   64 space-separated u64 counts on a single line, in
                    index order (slot 0 first, slot 63 last). Slots
                    not present in the dump (e.g., if bpftool ever
                    skips zero slots) default to 0.
    With <id>:      single u64 count on a line.

Exit codes:
    0  on success
    1  on argument-parse error
    2  if bpftool cannot read the map (pin missing, perms, etc.)
    3  if the JSON shape was not what we expected
"""
import json
import subprocess
import sys

XDPMF_ALLOWLIST_MAX = 64


def _decode_le_u64(byte_seq) -> int:
    """Convert a little-endian byte array (list of "0xNN" strings or ints)
    into a u64. Tolerates short arrays by zero-padding."""
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
    if len(sys.argv) not in (2, 3):
        print("usage: read_rule_counters.py <pin_path> [rule_id]",
              file=sys.stderr)
        return 1
    pin = sys.argv[1]
    target_id = None
    if len(sys.argv) == 3:
        try:
            target_id = int(sys.argv[2])
        except ValueError:
            print(f"rule_id must be integer, got {sys.argv[2]!r}",
                  file=sys.stderr)
            return 1
        if target_id < 0 or target_id >= XDPMF_ALLOWLIST_MAX:
            print(f"rule_id {target_id} out of range [0, "
                  f"{XDPMF_ALLOWLIST_MAX - 1}]", file=sys.stderr)
            return 1

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

    counters = [0] * XDPMF_ALLOWLIST_MAX
    for entry in data:
        # Prefer BTF-decoded formatted.key (integer); fall back to LE bytes.
        k = None
        formatted = entry.get("formatted") if isinstance(entry, dict) else None
        if isinstance(formatted, dict) and "key" in formatted:
            try:
                k = int(formatted["key"])
            except (TypeError, ValueError):
                k = None
        if k is None:
            key_bytes = entry.get("key")
            if key_bytes is None:
                print(f"unexpected entry shape (no key): {entry!r}",
                      file=sys.stderr)
                return 3
            if isinstance(key_bytes, int):
                k = key_bytes
            else:
                k = _decode_key_u32(key_bytes)
        if k < 0 or k >= XDPMF_ALLOWLIST_MAX:
            # Out-of-range key — skip (defensive).
            continue

        # PERCPU schema: entry["values"] is a list of per-CPU records,
        # each shaped {"cpu": <int>, "value": [<bytes>]}. Sum across CPUs.
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

        counters[k] = total

    if target_id is not None:
        print(counters[target_id])
    else:
        print(" ".join(str(c) for c in counters))
    return 0


if __name__ == "__main__":
    sys.exit(main())
