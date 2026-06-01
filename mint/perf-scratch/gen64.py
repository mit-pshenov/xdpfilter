#!/usr/bin/env python3
"""Generate a dense 64-rule config: 64 distinct dst_cidr /24 rules, all pass.
The test packet (v_v4_64rule.bin) has dst 10.0.0.5 -> matches the id0 rule
(10.0.0.0/24). But for WORST CASE we want max LPM trie population + a full
64-bit accumulator. The bit-vector AND is O(num_axes) not O(num_rules) at
match time, but LPM trie depth & map population grow. To stress the highest
id, also add a rule matching dst 10.0.63.0/24 and aim the packet there."""
import os
OUT = os.path.dirname(os.path.abspath(__file__))

lines = ["schema_version: 2", "default_action: drop", "rules:"]
for i in range(64):
    lines.append(f"  - id: {i}")
    lines.append(f"    action: pass")
    lines.append(f"    match:")
    lines.append(f'      dst_cidr: "10.0.{i}.0/24"')
cfg = "\n".join(lines) + "\n"
with open(os.path.join(OUT, "config_64rule.yaml"), "w") as f:
    f.write(cfg)
print(f"config_64rule.yaml: 64 dst_cidr /24 rules (10.0.0.0/24 .. 10.0.63.0/24)")
