/**
 * @file ink_packet_memory.cpp
 * @brief Memory protection utilities for secure code execution
 */

#include "../include/ink_packet.hpp"
#include <cstring>

#if defined(_WIN32)
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <errno.h>
#endif

namespace ink {
namespace memory {

bool lock_pages(void* addr, size_t size) {
    if (!addr || size == 0) return false;
    
#if defined(_WIN32)
    // Windows: VirtualLock
    return VirtualLock(addr, size) != 0;
#else
    // Unix: mlock
    return mlock(addr, size) == 0;
#endif
}

bool unlock_pages(void* addr, size_t size) {
    if (!addr || size == 0) return false;
    
#if defined(_WIN32)
    // Windows: VirtualUnlock
    return VirtualUnlock(addr, size) != 0;
#else
    // Unix: munlock
    return munlock(addr, size) == 0;
#endif
}

bool mark_non_dumpable(void* addr, size_t size) {
    if (!addr || size == 0) return false;
    
#if defined(_WIN32)
    // Windows: Set page protection to exclude from minidump
    DWORD old_protect;
    return VirtualProtect(addr, size, PAGE_READWRITE | PAGE_GUARD, &old_protect) != 0;
#elif defined(__linux__)
    // Linux: Use madvise with MADV_DONTDUMP
    return madvise(addr, size, MADV_DONTDUMP) == 0;
#elif defined(__APPLE__)
    // macOS: Use madvise with MADV_ZERO_WIRED_PAGES
    return madvise(addr, size, MADV_ZERO_WIRED_PAGES) == 0;
#else
    // Other Unix: Try generic madvise
    return madvise(addr, size, MADV_DONTNEED) == 0;
#endif
}

void* alloc_executable(size_t size) {
    if (size == 0) return nullptr;
    
    // Round up to page size
    size_t page_size;
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = si.dwPageSize;
#else
    page_size = sysconf(_SC_PAGESIZE);
#endif
    
    size_t alloc_size = ((size + page_size - 1) / page_size) * page_size;
    
#if defined(_WIN32)
    // Windows: VirtualAlloc with execute permission
    void* mem = VirtualAlloc(nullptr, alloc_size, 
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    
    // Clear memory
    std::memset(mem, 0, alloc_size);
    return mem;
#else
    // Unix: mmap with execute permission
    void* mem = mmap(nullptr, alloc_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    
    if (mem == MAP_FAILED) return nullptr;
    
    // Clear memory
    std::memset(mem, 0, alloc_size);
    
    // Try to lock pages to prevent swapping
    lock_pages(mem, alloc_size);
    
    return mem;
#endif
}

void free_executable(void* addr, size_t size) {
    if (!addr || size == 0) return;
    
    // Round up to page size
    size_t page_size;
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = si.dwPageSize;
#else
    page_size = sysconf(_SC_PAGESIZE);
#endif
    
    size_t alloc_size = ((size + page_size - 1) / page_size) * page_size;
    
    // Clear memory before freeing
    volatile uint8_t* p = static_cast<volatile uint8_t*>(addr);
    for (size_t i = 0; i < alloc_size; ++i) {
        p[i] = 0;
    }
    
#if defined(_WIN32)
    // Windows: VirtualFree
    VirtualFree(addr, 0, MEM_RELEASE);
#else
    // Unix: munmap
    unlock_pages(addr, alloc_size);
    munmap(addr, alloc_size);
#endif
}

} // namespace memory
} // namespace ink