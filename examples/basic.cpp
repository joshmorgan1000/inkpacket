/**
 * @file basic.cpp
 * @brief Basic example demonstrating inkpacket self-verification
 */

#include <ink_packet.hpp>
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "=== InkPacket Basic Example ===" << std::endl;
    
    // Calculate hash of self
    std::cout << "\n1. Calculating hash of this binary..." << std::endl;
    auto hash = ink::verify::hash_self(0);
    
    if (hash.empty()) {
        std::cerr << "   ERROR: Failed to calculate hash" << std::endl;
        return 1;
    }
    
    std::cout << "   Hash (SHA-256): ";
    for (auto byte : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
    
    // Check integrity
    std::cout << "\n2. Checking binary integrity..." << std::endl;
    if (ink::verify::check_integrity()) {
        std::cout << "   ✓ Integrity check passed" << std::endl;
    } else {
        std::cout << "   ✗ Integrity check failed" << std::endl;
    }
    
    // Check for debugger
    std::cout << "\n3. Checking for debugger..." << std::endl;
    if (ink::verify::is_debugger_present()) {
        std::cout << "   ⚠️  Debugger detected!" << std::endl;
    } else {
        std::cout << "   ✓ No debugger detected" << std::endl;
    }
    
    // Memory protection demo
    std::cout << "\n4. Testing memory protection..." << std::endl;
    
    // Allocate some sensitive data
    const size_t secret_size = 1024;
    void* secret_memory = ink::memory::alloc_executable(secret_size);
    
    if (secret_memory) {
        std::cout << "   ✓ Allocated executable memory" << std::endl;
        
        // Lock pages
        if (ink::memory::lock_pages(secret_memory, secret_size)) {
            std::cout << "   ✓ Locked memory pages (won't swap to disk)" << std::endl;
        }
        
        // Mark non-dumpable
        if (ink::memory::mark_non_dumpable(secret_memory, secret_size)) {
            std::cout << "   ✓ Marked memory as non-dumpable" << std::endl;
        }
        
        // Clean up
        ink::memory::unlock_pages(secret_memory, secret_size);
        ink::memory::free_executable(secret_memory, secret_size);
        std::cout << "   ✓ Cleaned up protected memory" << std::endl;
    }
    
    std::cout << "\n=== Example completed successfully ===" << std::endl;
    return 0;
}