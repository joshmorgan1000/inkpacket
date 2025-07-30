/**
 * @file macos.cpp
 * @brief macOS-specific implementations for ink packet
 */

#include "../../include/ink_packet.hpp"
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/sysctl.h>
#include <unistd.h>

namespace ink {
namespace platform {

/**
 * @brief Get base address of current process
 */
uintptr_t get_base_address() {
    const struct mach_header* header = _dyld_get_image_header(0);
    return reinterpret_cast<uintptr_t>(header);
}

/**
 * @brief Check if running under lldb
 */
bool is_lldb_present() {
    // Check parent process
    pid_t ppid = getppid();
    
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid };
    
    if (sysctl(mib, 4, &info, &size, nullptr, 0) == 0) {
        // Check if parent is lldb
        if (strstr(info.kp_proc.p_comm, "lldb") != nullptr) {
            return true;
        }
    }
    
    // Check environment
    if (getenv("LLDB_DEBUGSERVER_PATH") != nullptr) {
        return true;
    }
    
    return false;
}

/**
 * @brief Hide symbols from dynamic linker
 */
void hide_symbols(void* handle) {
    if (!handle) return;
    
    // macOS doesn't have dlinfo, but we can use other techniques
    // For now, we rely on strip and visibility attributes
}

/**
 * @brief Check code signature validity
 */
bool verify_code_signature() {
    // Could use Security framework to verify code signature
    // For now, return true
    return true;
}

} // namespace platform
} // namespace ink