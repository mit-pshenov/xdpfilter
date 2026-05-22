# Task brief — MVP-1: L2 MAC allow-list XDP filter

## Goal

Build the simplest possible vertical slice of an XDP-based packet filter: drop or pass incoming Ethernet frames on a given network interface based on source MAC address membership in a runtime-supplied allow-list.

This is MVP-1 in a series — first "reincarnation" of the pktgate concept, intentionally minimal to validate the mint multi-agent dev workflow on real C/BPF code.

## Constraints

- **Language**: BPF C (kernel-side), C++23 (userspace loader). No JSON, no scripting wrappers.
- **Platform**: Linux x86_64, kernel ≥ 5.15 (for BPF features needed).
- **Build**: CMake, out-of-source build in `build/`.
- **Configuration**: command-line arguments only — no config file, no JSON, no hot reload in this slice.
- **Dependencies**: libbpf 1.1+, libelf, bpftool, clang-19 (all installed on host).

## Acceptance criteria

A successful MVP-1 satisfies all of:

1. Program builds clean (zero warnings under flags from `lang/cpp.md` pack).
2. BPF object loads and attaches to a given network interface via XDP.
3. Frame with allowed source MAC → **passes** (observable via counter or pcap on peer interface).
4. Frame with disallowed source MAC → **dropped** (observable via drop counter).
5. Malformed frame (truncated below valid Ethernet header) → **dropped** (counted separately if practical, OR included in drop count — architect decides).
6. **Idempotent attach**: running the loader twice in sequence (each followed by exit) leaves no leaked kernel objects (verified via `bpftool prog show` count returning to baseline).
7. **Negation control test**: at least one test exists where a known-bad input MUST fail its assertion — proves the test suite isn't a no-op.

## Out of scope (anti-drift fence — architect may expand)

- L3/L4 filtering (IPv4/IPv6/TCP/UDP) — MVP-2+
- IPv6 EtherType handling, VLAN unwrap — MVP-2+
- JSON config file — MVP-3
- Hot reload (inotify/SIGHUP) — MVP-3
- Per-CPU counter maps (single shared counter sufficient for this slice) — MVP-2
- Prometheus metrics endpoint — MVP-3
- Multi-interface attach — MVP-2
- TC ingress hook (XDP only this slice)
- Performance benchmarking, perf tuning — out of MVP series scope

## References

- Inspirational predecessor: pktgate concept — eBPF/XDP packet filter genre. Architecture/Config docs exist elsewhere on this host; **intentionally NOT linked** to avoid copying past design decisions. This is a clean redesign.
- libbpf documentation: https://libbpf.readthedocs.io/
- BPF kernel docs: https://docs.kernel.org/bpf/
- Example minimal libbpf programs: https://github.com/libbpf/libbpf-bootstrap (xdp example patterns)

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []                                       # designs at abstract level
  impl:       [lang/cpp.md, lang/bpf.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []                                       # generic framework + LSP tool
```

## Notes for architect

- Userspace loader is C++23 (not C). Use modern RAII for libbpf object lifetimes.
- Test fixture uses veth pair (see `test/bpf-xdp.md` for tester). Architect's TestStrategy must specify which veth-pair direction is injection vs observation per test.
- Acceptance criterion 6 ("idempotent reload") requires an explicit design decision: HOW does the loader detect existing attached program and detach before re-attaching (vs refuse with clear error)? Put the choice + rationale in your Decisions section.
- The MAC allow-list size is a design choice (8? 64? 256?) — pick what suits the verifier's stack budget and document in Decisions.
