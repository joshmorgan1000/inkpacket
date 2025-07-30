/**
 * @file linux.cpp
 * @brief Linux-specific implementations for ink packet
 */

#include "../../include/ink_packet.hpp"
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <fcntl.h>

namespace ink {
namespace platform {

/**
 * @brief Get base address of current process
 */
uintptr_t get_base_address() {
    return getauxval(AT_PHDR) - sizeof(Elf64_Ehdr);
}

/**
 * @brief Check if running under valgrind
 */
bool is_valgrind_present() {
    const char* ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strstr(ld_preload, "valgrind")) {
        return true;
    }
    
    // Check /proc/self/maps for valgrind
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[256];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "valgrind") || strstr(line, "vgpreload")) {
                fclose(maps);
                return true;
            }
        }
        fclose(maps);
    }
    
    return false;
}

/**
 * @brief Hide symbols from dynamic linker
 */
void hide_symbols(void* handle) {
    if (!handle) return;
    
    // Get link map
    struct link_map* map = nullptr;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0) {
        return;
    }
    
    // Could implement symbol hiding here if needed
    // For now, we rely on strip and visibility attributes
}

} // namespace platform
} // namespace ink