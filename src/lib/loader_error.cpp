/*
 * loader_error.cpp — host-only std::error_category machinery for LoaderError.
 *
 * §5.76 (MVP-4.36) B43 D-mvp-4.36-Q1-A1: MOVED verbatim from loader.cpp's
 * anon-namespace (`class LoaderCategory`, `loader_error_category()`, `classify`,
 * `throw_loader`). No libbpf, no fd, no skeleton — a pure host TU so the
 * libbpf-free materialize.cpp + dryrun_harness can resolve the error path
 * without linking loader.cpp. The bodies are byte-identical to the originals
 * (guard #9: MOVE, not re-implement); `classify`/`throw_loader` are promoted
 * from internal to external linkage (declared in loader_error.hpp);
 * `loader_error_category()` keeps its public loader.hpp decl (PI-7).
 */
#include "loader_error.hpp"

#include <cerrno>
#include <string>
#include <system_error>
#include <utility>

namespace xdpmf {

namespace {

/* Single category instance — see loader.hpp. */
class LoaderCategory final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "xdpmf.loader"; }
    [[nodiscard]] std::string message(int ev) const override
    {
        switch (static_cast<LoaderError>(ev)) {
            case LoaderError::LoadFailed:         return "BPF object load failed";
            case LoaderError::AttachFailed:       return "XDP attach failed";
            case LoaderError::AttachRefusedAlien: return "alien XDP program already attached";
            case LoaderError::DetachFailed:       return "detach failed";
            case LoaderError::Permission:         return "permission denied (need CAP_BPF / CAP_NET_ADMIN)";
            case LoaderError::KernelUnsupported:  return "kernel version too old for xdpfilter";
            case LoaderError::PathRefused:        return "bpffs path refused (symlink or non-directory at the bpffs root or per-iface entry)";
            case LoaderError::ConfigError:        return "config error (YAML parse / schema / trust_model violation)";
        }
        return "unknown loader error";
    }
};

}  // namespace

const std::error_category& loader_error_category() noexcept
{
    static const LoaderCategory cat;
    return cat;
}

/* Translate libbpf -errno into a LoaderError suitable for the given step.
 * EPERM/EACCES always map to LoaderError::Permission so users see the
 * "run as root" diagnostic regardless of which step rejected them. */
[[nodiscard]] LoaderError classify(int neg_errno, LoaderError fallback) noexcept
{
    const int e = neg_errno < 0 ? -neg_errno : neg_errno;
    if (e == EPERM || e == EACCES) {
        return LoaderError::Permission;
    }
    return fallback;
}

[[noreturn]] void throw_loader(LoaderError code, std::string what)
{
    throw std::system_error(make_error_code(code), std::move(what));
}

}  // namespace xdpmf
