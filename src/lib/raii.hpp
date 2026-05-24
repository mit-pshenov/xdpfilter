/*
 * raii.hpp — RAII wrappers for libbpf resources, the XDP attach slot, and
 * the per-iface bpffs directory used as ownership marker (design §5.4).
 *
 * These wrappers MUST be the only owners of their underlying resources;
 * loader.cpp never calls raw libbpf cleanup directly (design §4.3).
 * Move-only, copy-deleted. Destructors are noexcept and best-effort:
 * failures in cleanup paths are silenced because we are unwinding.
 */
#pragma once

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include <bpf/libbpf.h>

extern "C" {
#include "mac_filter.skel.h"
}

namespace xdpmf {

/* ---------- libbpf skeleton ownership ---------- */

class BpfSkeleton {
public:
    BpfSkeleton() noexcept = default;
    explicit BpfSkeleton(mac_filter_bpf* raw) noexcept : skel_(raw) {}

    BpfSkeleton(const BpfSkeleton&)            = delete;
    BpfSkeleton& operator=(const BpfSkeleton&) = delete;

    BpfSkeleton(BpfSkeleton&& other) noexcept : skel_(other.skel_) {
        other.skel_ = nullptr;
    }
    BpfSkeleton& operator=(BpfSkeleton&& other) noexcept {
        if (this != &other) {
            reset();
            skel_ = other.skel_;
            other.skel_ = nullptr;
        }
        return *this;
    }

    ~BpfSkeleton() noexcept { reset(); }

    void reset() noexcept {
        if (skel_) {
            mac_filter_bpf__destroy(skel_);
            skel_ = nullptr;
        }
    }

    [[nodiscard]] mac_filter_bpf* get() const noexcept { return skel_; }
    [[nodiscard]] mac_filter_bpf* operator->() const noexcept { return skel_; }
    [[nodiscard]] explicit operator bool() const noexcept { return skel_ != nullptr; }

private:
    mac_filter_bpf* skel_ = nullptr;
};

/* ---------- XDP attachment slot on a netif ---------- */

/*
 * Holds the (ifindex, flags) needed to detach. By default the destructor
 * detaches; call release() after a successful attach where the kernel
 * is meant to retain the XDP program (design §5.9: loader exits, kernel
 * keeps the program live via the netif reference).
 */
class XdpAttachment {
public:
    XdpAttachment() noexcept = default;
    XdpAttachment(int ifindex, std::uint32_t flags) noexcept
        : ifindex_(ifindex), flags_(flags), attached_(true) {}

    XdpAttachment(const XdpAttachment&)            = delete;
    XdpAttachment& operator=(const XdpAttachment&) = delete;

    XdpAttachment(XdpAttachment&& other) noexcept
        : ifindex_(other.ifindex_), flags_(other.flags_), attached_(other.attached_) {
        other.attached_ = false;
    }
    XdpAttachment& operator=(XdpAttachment&& other) noexcept {
        if (this != &other) {
            reset();
            ifindex_       = other.ifindex_;
            flags_         = other.flags_;
            attached_      = other.attached_;
            other.attached_ = false;
        }
        return *this;
    }

    ~XdpAttachment() noexcept { reset(); }

    /* Drop ownership without detaching — kernel keeps the program. */
    void release() noexcept { attached_ = false; }

    /* Detach if still owned; silence errors (we are in destructor path). */
    void reset() noexcept {
        if (attached_) {
            (void)bpf_xdp_detach(ifindex_, flags_, nullptr);
            attached_ = false;
        }
    }

private:
    int           ifindex_  = -1;
    std::uint32_t flags_    = 0;
    bool          attached_ = false;
};

/* ---------- Bpffs per-iface directory (ownership marker) ---------- */

/*
 * Tracks the lifetime of /sys/fs/bpf/xdpmacfilter/<iface>/ for cleanup
 * purposes. This class does NOT create the directory — creation happens
 * in loader.cpp via std::filesystem::create_directories() before the
 * BpffsDir is armed. The owner workflow is:
 *   1) construct BpffsDir with the target path,
 *   2) std::filesystem::create_directories(path) in loader.cpp,
 *   3) arm() to enable removal-on-destruction (rollback path),
 *   4) on success: release() so the dir survives loader exit
 *      (kernel keeps the pinned maps live).
 * If arm() was called but release() was not (e.g. throw during attach),
 * the destructor removes the dir tree.
 */
class BpffsDir {
public:
    BpffsDir() noexcept = default;
    explicit BpffsDir(std::string path) : path_(std::move(path)) {}

    BpffsDir(const BpffsDir&)            = delete;
    BpffsDir& operator=(const BpffsDir&) = delete;

    BpffsDir(BpffsDir&& other) noexcept
        : path_(std::move(other.path_)), armed_(other.armed_) {
        other.armed_ = false;
    }
    BpffsDir& operator=(BpffsDir&& other) noexcept {
        if (this != &other) {
            reset();
            path_       = std::move(other.path_);
            armed_      = other.armed_;
            other.armed_ = false;
        }
        return *this;
    }

    ~BpffsDir() noexcept { reset(); }

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

    /* Mark this dir as owned-and-removable on destruction. Called after
     * we have successfully created or claimed the dir. */
    void arm() noexcept { armed_ = true; }

    /* Drop ownership — caller has committed and the dir should persist. */
    void release() noexcept { armed_ = false; }

    /* Remove the directory tree if armed; silence errors. */
    void reset() noexcept {
        if (armed_ && !path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
            armed_ = false;
        }
    }

private:
    std::string path_;
    bool        armed_ = false;
};

}  // namespace xdpmf
