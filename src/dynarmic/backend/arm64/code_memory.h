/* This file is part of the dynarmic project.
 * SPDX-License-Identifier: 0BSD
 */

#pragma once

#include <cstddef>
#include <optional>

#include <mcl/stdint.hpp>
#include <oaknut/code_block.hpp>

#if defined(__APPLE__)
#    include <libkern/OSCacheControl.h>
#endif
#if !defined(_WIN32)
#    include <sys/mman.h>
#endif

namespace Dynarmic::Backend::Arm64 {

/// The code cache. Either memory dynarmic maps itself, or memory the host hands it (see UserConfig::code_cache_rw).
class CodeMemory {
public:
    CodeMemory(std::size_t size, void* host_rw, void* host_rx)
            : size(size) {
        if (host_rw && host_rx) {
            rw = static_cast<u32*>(host_rw);
            rx = static_cast<u32*>(host_rx);
        } else {
            owned.emplace(size);
            rw = rx = owned->ptr();
        }
    }

    CodeMemory(const CodeMemory&) = delete;
    CodeMemory& operator=(const CodeMemory&) = delete;

    /// Write code through this pointer.
    u32* wptr() const { return rw; }

    /// Run code from this pointer.
    u32* xptr() const { return rx; }

    void protect() {
        if (owned) {
#if defined(DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT) || defined(__APPLE__) || defined(__OpenBSD__)
            owned->protect();
#endif
        } else if (rw == rx) {
            Reprotect(true);
        }
    }

    void unprotect() {
        if (owned) {
#if defined(DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT) || defined(__APPLE__) || defined(__OpenBSD__)
            owned->unprotect();
#endif
        } else if (rw == rx) {
            Reprotect(false);
        }
    }

    void invalidate(u32* mem, std::size_t length) {
        if (owned) {
            owned->invalidate(mem, length);
        } else {
#if defined(_WIN32)
            FlushInstructionCache(GetCurrentProcess(), mem, length);
#elif defined(__APPLE__)
            sys_icache_invalidate(mem, length);
#else
            __builtin___clear_cache(reinterpret_cast<char*>(mem), reinterpret_cast<char*>(mem) + length);
#endif
        }
    }

    void invalidate_all() {
        invalidate(rx, size);
    }

private:
    // A single mapping from the host can't be writable and executable at once.
    void Reprotect(bool executable) {
#if defined(_WIN32)
        DWORD old;
        VirtualProtect(rx, size, executable ? PAGE_EXECUTE_READ : PAGE_READWRITE, &old);
#else
        mprotect(rx, size, executable ? PROT_READ | PROT_EXEC : PROT_READ | PROT_WRITE);
#endif
    }

    std::size_t size;
    std::optional<oaknut::CodeBlock> owned;
    u32* rw;
    u32* rx;
};

}  // namespace Dynarmic::Backend::Arm64
