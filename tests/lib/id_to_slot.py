#!/usr/bin/env python3
"""
id_to_slot.py — resolve an operator rule `id` to its internal bit-vector
`slot` by reading the pinned `slot_rule_id` BPF_MAP_TYPE_ARRAY via bpftool.

Design §5.61 (MVP-4.21 / B30 — D-mvp-4.21-Q1 / D-mvp-4.21-RAWMAP-REMAP):
post-B30 the raw `rule_counters` / `rules_inner` maps are SLOT-keyed
(slot = a rule's rank in ascending-id order), NOT id-keyed. A test that
peeks those maps by operator id must first remap id->slot through the
`slot_rule_id` map's ACTIVE half — exactly as the production exporter
does. This tool is that remap, factored out for reuse by common.sh.

The map (per §5.61 DataStructures) is an ARRAY of __u32 with
max_entries = XDPMF_RULESET_COUNT * XDPMF_ALLOWLIST_MAX (= 2 * 64 = 128).
Layout: slot_rule_id[half * 64 + slot] == the operator id occupying that
slot in ruleset half `half` (0 -> *_a, 1 -> *_b), or XDPMF_SLOT_ID_EMPTY
(0xFFFFFFFF) for unoccupied slots. `half` is the value of the shared
active_idx for the inner being read.

Usage:
    sudo python3 id_to_slot.py <slot_rule_id_pin> <half> <target_id>

Output:
    On success: the slot index (0..63) whose slot_rule_id value == target_id,
                printed on a single line.
Exit codes:
    0  slot found (printed)
    1  argument-parse error
    2  bpftool could not read the map (pin missing, perms, etc.)
    3  JSON shape unexpected
    4  target_id not present in that half (NOTHING printed — caller treats
       as "rule not loaded in this half")
"""
import json
import subprocess
import sys

XDPMF_ALLOWLIST_MAX = 64
XDPMF_SLOT_ID_EMPTY = 0xFFFFFFFF


def _decode_le_u32(byte_seq) -> int:
    v = 0
    for i in range(min(4, len(byte_seq))):
        b = byte_seq[i]
        if isinstance(b, str):
            b = int(b, 0)
        v |= b << (8 * i)
    return v


def _as_int(formatted_field):
    try:
        return int(formatted_field)
    except (TypeError, ValueError):
        return None


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: id_to_slot.py <slot_rule_id_pin> <half> <target_id>",
              file=sys.stderr)
        return 1
    pin = sys.argv[1]
    try:
        half = int(sys.argv[2])
        target_id = int(sys.argv[3])
    except ValueError:
        print("half and target_id must be integers", file=sys.stderr)
        return 1
    if half not in (0, 1):
        print(f"half must be 0 or 1, got {half}", file=sys.stderr)
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

    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                data = v
                break

    # Build {array_index: value_u32}.
    table = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        k = None
        val = None
        formatted = entry.get("formatted")
        if isinstance(formatted, dict):
            if "key" in formatted:
                k = _as_int(formatted["key"])
            if "value" in formatted:
                val = _as_int(formatted["value"])
        if k is None:
            kb = entry.get("key")
            if isinstance(kb, int):
                k = kb
            elif kb is not None:
                k = _decode_le_u32(kb)
        if val is None:
            vb = entry.get("value")
            if isinstance(vb, int):
                val = vb
            elif vb is not None:
                val = _decode_le_u32(vb)
        if k is None or val is None:
            continue
        table[k] = val

    if not table:
        print(f"slot_rule_id dump empty/unparseable: {pin}", file=sys.stderr)
        return 3

    base = half * XDPMF_ALLOWLIST_MAX
    for slot in range(XDPMF_ALLOWLIST_MAX):
        val = table.get(base + slot)
        if val is None:
            continue
        if val == XDPMF_SLOT_ID_EMPTY:
            continue
        if val == target_id:
            print(slot)
            return 0

    # Not found in this half — rule not loaded there.
    return 4


if __name__ == "__main__":
    sys.exit(main())
