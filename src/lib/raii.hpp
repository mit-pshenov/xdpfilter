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
#include <string>
#include <system_error>
#include <utility>

#include <bpf/libbpf.h>

extern "C" {
#include "xdpfilter.skel.h"
}

namespace xdpmf {

/* ---------- libbpf skeleton ownership ---------- */

class BpfSkeleton {
public:
    BpfSkeleton() noexcept = default;
    explicit BpfSkeleton(xdpfilter_bpf* raw) noexcept : skel_(raw) {}

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
            xdpfilter_bpf__destroy(skel_);
            skel_ = nullptr;
        }
    }

    [[nodiscard]] xdpfilter_bpf* get() const noexcept { return skel_; }
    [[nodiscard]] xdpfilter_bpf* operator->() const noexcept { return skel_; }
    [[nodiscard]] explicit operator bool() const noexcept { return skel_ != nullptr; }

private:
    xdpfilter_bpf* skel_ = nullptr;
};

}  // namespace xdpmf
