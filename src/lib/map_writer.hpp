/*
 * map_writer.hpp — PRIVATE header (not exported, not installed).
 *
 * §5.77 (MVP-4.37 / B44) D-mvp-4.37-Q1-OBJSEAM: the OBJECT SEAM that lets the
 * ONE production binary issue EITHER live `bpf_map_*` writes (normal apply) OR a
 * recorded `(map,key,value)` trace (dry-run / harness), chosen at RUNTIME — no
 * link-time symbol swap (B43's mechanism, which the production binary cannot use
 * because it links real libbpf).
 *
 * The seam = a single installed active `MapWriter` + free-fn wrappers (`map_*`)
 * that `materialize.cpp` calls after the body-only `bpf_*`→`map_*` swap. Because
 * the wrappers keep EVERY `materialize`/`populate_*` SIGNATURE byte-identical,
 * loader.cpp's apply call sites + materialize.hpp are UNTOUCHED ⇒
 * PI-mvp-4.37-LIVE-IDENTITY is preserved structurally.
 *
 * libbpf-FREE: fwd-decls `struct bpf_map;`; the live writer (the only TU that
 * references libbpf) lives in live_map_writer.cpp and is NEVER linked by the
 * libbpf-free harness (PI-mvp-4.37-LIBBPF-FREE). `xdpfilter.skel.h` is pulled in
 * by map_writer.cpp for the `xdpfilter_bpf` TYPE only (SPIKE-1 — the skel's
 * libbpf-calling fns stay inline + unreferenced ⇒ zero libbpf link symbols).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "loader.hpp"  // LoaderError

struct bpf_map;        // libbpf map handle — fwd-decl keeps this header libbpf-free
struct xdpfilter_bpf;  // generated skeleton type; full definition only in map_writer.cpp

namespace xdpmf {

/* §5.77.3(1): the runtime render sink. A writer abstracts EVERY kernel-facing
 * render primitive in the apply subset (4 map ops + ifindex resolve) — no other
 * libbpf call exists in that subset (§5.76.9 #5). */
struct MapWriter {
    virtual ~MapWriter() = default;
    virtual int fd(bpf_map* m)                                                = 0;
    virtual int update(int fd, const void* key, const void* value,
                       std::uint64_t flags)                                   = 0;
    virtual int next_key(int fd, const void* prev, void* next)               = 0;
    virtual int del(int fd, const void* key)                                 = 0;
    virtual int resolve_ifindex(const std::string& iface, LoaderError on_fail) = 0;
};

/* §5.77.4(1) free-fn wrappers — what materialize.cpp calls after the swap. Each
 * dispatches to the installed active writer. FAIL-CLOSED (PI-mvp-4.37-FAILCLOSED):
 * if no writer is installed each wrapper hard-fails (`abort` with the literal
 * diagnostic "map writer not installed") — NEVER null-derefs, silently no-ops,
 * or falls back to a libbpf call. */
int map_fd(bpf_map* m);
int map_update(int fd, const void* key, const void* value, std::uint64_t flags);
int map_next_key(int fd, const void* prev, void* next);
int map_delete(int fd, const void* key);
[[nodiscard]] int map_resolve_ifindex(const std::string& iface, LoaderError on_fail);

/* Install the process-global active writer. set_active_writer returns the
 * PREVIOUS writer (RecordingScope restores it). */
MapWriter* set_active_writer(MapWriter* w);

/* §5.77.4(2): installs a process-lifetime LiveMapWriter as the active writer.
 * Defined in live_map_writer.cpp (the ONLY new TU that references libbpf); called
 * ONCE from main() before dispatch (D-mvp-4.37-INSTALL). */
void install_live_map_writer();

/* §5.77.3(4): the dumb trace element (relocated from fake_bpf.hpp; production-
 * owned now). One record per recorded map write, in CALL (issue) order. */
struct RecordedWrite {
    std::uint32_t             map_tag;  // → kMapCatalog {name,key_sz,val_sz}
    std::vector<std::uint8_t> key;      // key_sz raw stored bytes
    std::vector<std::uint8_t> value;    // val_sz raw stored bytes
};

/* §5.77.3(5): the production CATALOG. Enumerates EXACTLY the 14 slot-0 written
 * maps (guard #10). `tag` doubles as the sentinel `bpf_map*` value the dry-run
 * skel stores in maps.X AND the recorded fake-fd handle. key_sz/val_sz are
 * `sizeof` the real value structs (zero magic numbers). */
struct MapDesc {
    std::uint32_t tag;
    const char*   name;
    std::uint32_t key_sz;
    std::uint32_t val_sz;
};
extern const MapDesc     kMapCatalog[];
extern const std::size_t kMapCatalogCount;

/* Decode a recorded tag → its descriptor, or nullptr if the tag is not one of
 * the 14 expected write targets (a write to an unexpected map ⇒ spec violation;
 * surfaced via RecordingMapWriter::unexpected_write()). */
const MapDesc* desc_for_tag(std::uint32_t tag);

/* §5.77.3(3): the dumb capture (guard #36 — capture is DUMB; the golden's
 * within-map sort + hex formatting is a SEPARATE policy applied at format time in
 * map_image.cpp). Records one RecordedWrite per update in call order; bulk-clear
 * iteration over empty sentinel inners is a no-op (D-mvp-4.36-CLEAR-EMPTY). */
class RecordingMapWriter : public MapWriter {
public:
    int fd(bpf_map* m) override;
    int update(int fd, const void* key, const void* value, std::uint64_t flags) override;
    int next_key(int fd, const void* prev, void* next) override;
    int del(int fd, const void* key) override;
    int resolve_ifindex(const std::string& iface, LoaderError on_fail) override;

    const std::vector<RecordedWrite>& writes() const { return writes_; }
    const std::string& resolved_ifindex_name() const { return resolved_name_; }
    bool unexpected_write() const { return unexpected_; }

private:
    std::vector<RecordedWrite> writes_;
    std::string                resolved_name_;
    bool                       unexpected_ = false;
};

/* §5.77.3(6) RAII: ctor installs the given RecordingMapWriter as the active
 * writer, dtor restores the prior writer. The dry-run branch's ONLY state
 * mutation. */
class RecordingScope {
public:
    explicit RecordingScope(RecordingMapWriter& w) : prev_(set_active_writer(&w)) {}
    ~RecordingScope() { set_active_writer(prev_); }
    RecordingScope(const RecordingScope&)            = delete;
    RecordingScope& operator=(const RecordingScope&) = delete;

private:
    MapWriter* prev_;
};

/* §5.77.3(7): build an xdpfilter_bpf whose 24 maps.X members are distinct
 * non-null sentinel `bpf_map*` (cast small tags) — NO libbpf open/load (SPIKE-1).
 * Caller frees with free_dryrun_skel. Mirrors the B43 make_fake_skel, relocated
 * to production. */
xdpfilter_bpf* make_dryrun_skel();
void           free_dryrun_skel(xdpfilter_bpf* skel);

}  // namespace xdpmf
