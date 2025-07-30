/**
 * @file ink_patch.cpp
 * @brief Command-line tool for patching ink packet protected binaries
 * 
 * This tool performs post-build patching to embed encryption keys and
 * hash values directly into compiled binaries for hybrid protection.
 */

#include "../include/ink_packet.hpp"
#include <iostream>
#include <string>
#include <cstring>

void print_usage(const char* program) {
    std::cout << "Ink Packet Binary Patcher v3.0\n";
    std::cout << "================================\n\n";
    std::cout << "Usage: " << program << " [options] <binary> <payload>\n";
    std::cout << "\nArguments:\n";
    std::cout << "  binary               Path to compiled binary to patch\n";
    std::cout << "  payload              Path to shared library payload to embed\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --no-verify         Skip verification after patching\n";
    std::cout << "  --no-backup         Don't create backup of original binary\n";
    std::cout << "  --find-only         Only find placeholder locations, don't patch\n";
    std::cout << "  -v, --verbose       Verbose output\n";
    std::cout << "  -h, --help          Show this help\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program << " myapp libcritical.so\n";
    std::cout << "\nThe binary must contain the required placeholder patterns.\n";
    std::cout << "After patching, the binary will be self-protecting and tamper-resistant.\n";
}

void print_verbose_info() {
    std::cout << "\nInk Packet Protection System\n";
    std::cout << "============================\n";
    std::cout << "This tool embeds encrypted payloads and self-verification\n";
    std::cout << "data directly into compiled binaries. The resulting binary:\n\n";
    std::cout << "• Verifies its own integrity at runtime\n";
    std::cout << "• Becomes completely unusable if tampered with\n";
    std::cout << "• Decrypts critical code into memory only\n";
    std::cout << "• Includes anti-debugging protections\n\n";
    std::cout << "Security features:\n";
    std::cout << "• SHA-256 hash verification\n";
    std::cout << "• AES-256-GCM encryption\n";
    std::cout << "• Constant-time comparisons\n";
    std::cout << "• Memory protection and cleanup\n";
    std::cout << "• Multiple integrity checkpoints\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse arguments
    ink::InkPacketPatcher::PatchConfig config;
    bool verbose = false;
    bool find_only = false;
    
    int arg_idx = 1;
    while (arg_idx < argc) {
        std::string arg = argv[arg_idx];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
            print_verbose_info();
        }
        else if (arg == "--no-verify") {
            config.verify_after = false;
        }
        else if (arg == "--no-backup") {
            config.backup_original = false;
        }
        else if (arg == "--find-only") {
            find_only = true;
        }
        else if (arg[0] != '-' && config.binary_path.empty()) {
            config.binary_path = arg;
        }
        else if (arg[0] != '-' && config.payload_path.empty()) {
            config.payload_path = arg;
        }
        
        ++arg_idx;
    }
    
    // Validate arguments
    if (config.binary_path.empty()) {
        std::cerr << "Error: No binary specified\n";
        return 1;
    }
    
    // Create patcher
    ink::InkPacketPatcher patcher(config);
    
    // Analyze binary
    if (verbose || find_only) {
        std::cout << "\nAnalyzing binary...\n";
        auto info = patcher.analyze_binary();
        
        std::cout << "Binary info:\n";
        std::cout << "  Application size: " << info.app_size << " bytes\n";
        std::cout << "  Total size: " << info.total_size << " bytes\n";
        std::cout << "  Has payload: " << (info.has_existing_payload ? "yes" : "no") << "\n";
        std::cout << "  Size placeholder offset: 0x" << std::hex << info.size_placeholder_offset << std::dec << "\n";
        
        if (find_only) {
            return 0;
        }
    }
    
    if (config.payload_path.empty()) {
        std::cerr << "Error: No payload specified\n";
        return 1;
    }
    
    // Perform patching
    std::cout << "\nPatching binary...\n";
    if (!patcher.patch()) {
        std::cerr << "Patching failed: " << patcher.get_error() << "\n";
        return 1;
    }
    
    std::cout << "Successfully patched: " << config.binary_path << "\n";
    
    if (config.verify_after) {
        std::cout << "Verification passed.\n";
    }
    
    std::cout << "\nThe binary is now self-protecting and tamper-resistant.\n";
    
    return 0;
}