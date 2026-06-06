/*
 * live_map_writer.cpp — §5.77 (MVP-4.37 / B44) the LIVE map writer.
 *
 * The ONLY new TU that references libbpf (PI-mvp-4.37-LIBBPF-FREE: the libbpf-free
 * harness NEVER links this object). Each method forwards VERBATIM to the real
 * libbpf symbol / the real xdpmf::resolve_ifindex (loader.cpp if_nametoindex) —
 * so the live apply write-set is byte-identical to pre-B44 (PI-mvp-4.37-LIVE-
 * IDENTITY): the `map_*` wrappers + LiveMapWriter forward args unchanged to the
 * same symbols the old materialize.cpp called directly.
 *
 * install_live_map_writer() installs a process-lifetime LiveMapWriter as the
 * active writer; called ONCE from main() before dispatch (D-mvp-4.37-INSTALL).
 * The explicit install (NOT static-init) keeps the wrapper TU libbpf-free and
 * avoids static-init-order questions.
 */
#include "map_writer.hpp"
#include "materialize.hpp"  // xdpmf::resolve_ifindex (the live if_nametoindex def in loader.cpp)

#include <cstdint>
#include <string>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf {

namespace {

class LiveMapWriter : public MapWriter {
public:
    int fd(bpf_map* m) override { return bpf_map__fd(m); }

    int update(int fd, const void* key, const void* value, std::uint64_t flags) override
    {
        return bpf_map_update_elem(fd, key, value, flags);
    }

    int next_key(int fd, const void* prev, void* next) override
    {
        return bpf_map_get_next_key(fd, prev, next);
    }

    int del(int fd, const void* key) override
    {
        return bpf_map_delete_elem(fd, key);
    }

    int resolve_ifindex(const std::string& iface, LoaderError on_fail) override
    {
        return xdpmf::resolve_ifindex(iface, on_fail);
    }
};

// Process-lifetime singleton — installed as the active writer for the whole run.
LiveMapWriter g_live_writer;

}  // namespace

void install_live_map_writer() { set_active_writer(&g_live_writer); }

}  // namespace xdpmf
