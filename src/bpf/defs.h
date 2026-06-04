#pragma once
/*
 * defs.h — BPF-target constant shims + branch hint + walk-depth tunables.
 *
 * Moved verbatim from xdpfilter.bpf.c (MVP-4.29 / B34b, §5.69): the
 * environment shims the BPF target lacks (no linux/if_ether.h / linux/in.h)
 * plus the unlikely() branch hint and the bounded-walk depth caps. Pure
 * #define wall with no project dependency. Pure #include split: byte-
 * identical post-preprocessing (xdp section stays 3658 insns).
 */

/* §5.30 HK-5 (MVP-3.4.5): leaf-null-check / bounds-check branch hint. All
 * six call sites below mark verifier-MANDATED checks that are expected NOT
 * to fire under normal operation (userspace populates both ruleset slots
 * before first attach; valid Ethernet/IPv4 frames have well-formed bounds).
 * The hint affects JIT code layout (fall-through preferred for the common
 * non-error path); functional verdict is byte-equivalent (PI-28). */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Protocol / EtherType constants defined inline: vmlinux.h is BTF-derived
 * (types only, no CPP macros) and linux/if_ether.h + linux/in.h are unavailable
 * in the BPF-target build. All values are byte-equivalent to their IANA /
 * IEEE 802.1Q assignments. Trace: §5.27 (ETH_P_IP), §5.51/S1 (ETH_P_IPV6),
 * §5.41/MVP-4.1 (VLAN TPIDs), §5.44 (IPPROTO_TCP/UDP), §5.55/S6 (ext-hdr protos). */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
/* §5.41: 802.1Q (C-TAG) + one stacked QinQ (S-TAG) ⇒ walk depth 2; the single
 * source of truth for the #pragma unroll count (HG-mvp-4.1-1). */
#define XDPMF_VLAN_MAX_DEPTH 2
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
/* §5.55: IPv6 ext-hdr protos for the bounded walk. HOPOPTS/ROUTING/DSTOPTS use
 * ipv6_opt_hdr (len (hdrlen+1)*8); FRAGMENT = frag_hdr (fixed 8B); NONE terminal. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

/* §5.55 (MVP-4.15 / S6) D-mvp-4.15-MAXHOPS: ext-header walk hop cap. Single
 * source of truth for the #pragma unroll count. Spike-validated at 8 (rc=0,
 * 26548/1M insns, stack 280/512, max_states 12 on the 6.1 host); 8 covers all
 * realistic chains with huge verifier headroom. A chain exceeding the cap
 * fail-safes to a non-L4 residual proto ⇒ has_port=0 (D-mvp-4.15-Q2-CAP). */
#define MAX_EXT_HOPS 8
