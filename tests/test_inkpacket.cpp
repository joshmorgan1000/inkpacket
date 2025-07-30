/**
 * @file test_inkpacket.cpp
 * @brief Basic tests for ink packet functionality
 */

#include "../include/ink_packet.hpp"
#include <iostream>
#include <cassert>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

/**
 * @brief Create a simple test executable
 */
bool create_test_binary(const std::string& path) {
    const char* code = R"(
#include <iostream>
int main() {
    std::cout << "Hello from test binary!" << std::endl;
    return 0;
}
)";
    
    std::string cpp_file = path + ".cpp";
    std::ofstream out(cpp_file);
    out << code;
    out.close();
    
    std::string cmd = "c++ -o " + path + " " + cpp_file;
    int result = std::system(cmd.c_str());
    
    fs::remove(cpp_file);
    return result == 0;
}

/**
 * @brief Create a simple test library
 */
bool create_test_library(const std::string& path) {
    const char* code = R"(
#include <iostream>
extern "C" void test_function() {
    std::cout << "Hello from protected library!" << std::endl;
}
)";
    
    std::string cpp_file = path + ".cpp";
    std::ofstream out(cpp_file);
    out << code;
    out.close();
    
    std::string cmd = "c++ -shared -fPIC -o " + path + " " + cpp_file;
    int result = std::system(cmd.c_str());
    
    fs::remove(cpp_file);
    return result == 0;
}

void test_binary_analysis() {
    std::cout << "Test: Binary analysis...";
    
    // Create test binary
    std::string test_bin = "test_analyze";
    assert(create_test_binary(test_bin));
    
    // Analyze it
    ink::InkPacketPatcher::PatchConfig config;
    config.binary_path = test_bin;
    
    ink::InkPacketPatcher patcher(config);
    auto info = patcher.analyze_binary();
    
    assert(info.app_size > 0);
    assert(!info.has_existing_payload);
    
    fs::remove(test_bin);
    std::cout << " PASSED" << std::endl;
}

void test_hash_functions() {
    std::cout << "Test: Hash functions...";
    
    // Test SHA-256
    auto hash1 = ink::verify::hash_self(0);
    assert(!hash1.empty());
    assert(hash1.size() == 32);
    
    // Hash should be consistent
    auto hash2 = ink::verify::hash_self(0);
    assert(hash1 == hash2);
    
    std::cout << " PASSED" << std::endl;
}

void test_memory_protection() {
    std::cout << "Test: Memory protection...";
    
    // Allocate executable memory
    size_t size = 4096;
    void* mem = ink::memory::alloc_executable(size);
    assert(mem != nullptr);
    
    // Should be able to write
    std::memset(mem, 0x90, size); // NOP instructions
    
    // Lock pages
    assert(ink::memory::lock_pages(mem, size));
    
    // Unlock pages
    assert(ink::memory::unlock_pages(mem, size));
    
    // Free memory
    ink::memory::free_executable(mem, size);
    
    std::cout << " PASSED" << std::endl;
}

void test_verification() {
    std::cout << "Test: Verification utilities...";
    
    // Basic integrity check (will fail for unpacked binary)
    bool integrity = ink::verify::check_integrity();
    // This is expected to fail for a normal binary
    assert(!integrity);
    
    // Debugger check
    bool debugger = ink::verify::is_debugger_present();
    // Should be false in normal execution
    // (might be true if running under debugger)
    
    std::cout << " PASSED" << std::endl;
}

void test_full_workflow() {
    std::cout << "Test: Full ink packet workflow...";
    
    // Create test files
    std::string test_bin = "test_workflow";
    std::string test_lib = "test_workflow.so";
    
    assert(create_test_binary(test_bin));
    assert(create_test_library(test_lib));
    
    // Patch the binary
    ink::InkPacketPatcher::PatchConfig config;
    config.binary_path = test_bin;
    config.payload_path = test_lib;
    config.verify_after = true;
    
    ink::InkPacketPatcher patcher(config);
    
    // Should succeed
    if (!patcher.patch()) {
        std::cerr << "Patch failed: " << patcher.get_error() << std::endl;
        // Clean up anyway
        fs::remove(test_bin);
        fs::remove(test_lib);
        assert(false);
    }
    
    // Verify the patched binary can be analyzed
    auto info = patcher.analyze_binary();
    assert(info.has_existing_payload);
    
    // Clean up
    fs::remove(test_bin);
    fs::remove(test_lib);
    
    std::cout << " PASSED" << std::endl;
}

int main() {
    std::cout << "Running ink packet tests...\n" << std::endl;
    
    try {
        test_binary_analysis();
        test_hash_functions();
        test_memory_protection();
        test_verification();
        test_full_workflow();
        
        std::cout << "\nAll tests passed!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nTest failed with exception: " << e.what() << std::endl;
        return 1;
    }
}