#!/usr/bin/env python3
"""
inject_runt.py — attempt to send a sub-14-byte ("malformed") frame.

Usage:
    sudo python3 inject_runt.py <iface>

Per design §6.5: tests STAT_DROP_MALFORMED. Note that recent Linux
kernels pad short frames to dev->hard_header_len (14 for Ethernet) when
the caller has CAP_SYS_RAWIO — see dev_validate_header().  In that case
XDP will see a 14-byte frame and the malformed counter will NOT bump
(STAT_DROP_DENY will instead, since the padded src MAC won't match the
allow-list).  The calling test detects that situation and reports SKIP.

We deliberately use byte values that, after zero-padding, would produce
a src MAC of 02:00:00:00:00:00 (NOT MAC_BAD, NOT MAC_GOOD) so the test
can unambiguously distinguish "malformed dropped" vs "kernel padded →
denied".  The wire payload is 13 bytes — full 6-byte dst MAC + full
6-byte src MAC + 1 ethertype byte — one byte short of a valid Ethernet
header.
"""
import socket
import sys


ETH_P_ALL = 0x0003


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: inject_runt.py <iface>", file=sys.stderr)
        return 1
    iface = sys.argv[1]
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((iface, 0))
        # 13 bytes: full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte.
        # Designed so that even if the kernel zero-pads to 14 bytes, the
        # resulting src MAC is 02:00:00:00:00:00 (neither MAC_GOOD nor
        # MAC_BAD), so a STAT_DROP_DENY caused by padding is unambiguous.
        runt = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x88])
        try:
            sock.send(runt)
        except OSError as e:
            # On some kernels the send is rejected entirely (EINVAL/EMSGSIZE)
            # before the frame reaches the peer.  We still exit 0; the
            # caller will detect "no counter delta" and SKIP.
            print(f"inject_runt: send failed (kernel rejected): {e}",
                  file=sys.stderr)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
