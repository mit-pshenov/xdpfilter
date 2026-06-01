#!/usr/bin/env python3
"""Build a v6+ext-header frame matching config_valid_andv6.yaml id0 (FULL v6 AND).
id0: dst6 2001:db8:1::/48 AND src6 2001:db8:5::/48 AND tcp AND dport 1000-2000 AND vlan 100.
Add hbh+dstopt ext headers so the datapath ext-walk must run to find true L4=TCP."""
import os
from scapy.all import Ether, Dot1Q, IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, TCP, Raw

OUT = os.path.dirname(os.path.abspath(__file__))

pkt = (Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
       / Dot1Q(vlan=100)
       / IPv6(src="2001:db8:5::99", dst="2001:db8:1::42")
       / IPv6ExtHdrHopByHop()
       / IPv6ExtHdrDestOpt()
       / TCP(sport=4444, dport=1500))
raw = bytes(pkt)
if len(raw) < 60:
    raw += b"\x00" * (60 - len(raw))
with open(os.path.join(OUT, "v_v6_ext.bin"), "wb") as f:
    f.write(raw)
print(f"v_v6_ext.bin {len(raw)}B  (vlan100/2001:db8:5->1/hbh+dstopt/tcp:1500)")
