/**
 * @file simple_patcher.cpp
 * @brief Simple demonstration of the patcher functionality
 */

#include <ink_packet.hpp>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {
    std::cout << "=== InkPacket Simple Patcher ===" << std::endl;
    
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <binary> <payload>" << std::endl;
        std::cerr << "Example: " << argv[0] << " myapp secret.so" << std::endl;
        return 1;
    }
    
    // Configure the patcher
    ink::InkPacketPatcher::PatchConfig config;
    config.binary_path = argv[1];
    config.payload_path = argv[2];
    config.base_key = "inkpacket-demo";
    config.verify_after = false; // Don't verify for now
    config.backup_original = true;
    
    std::cout << "\nConfiguration:" << std::endl;
    std::cout << "  Binary: " << config.binary_path << std::endl;
    std::cout << "  Payload: " << config.payload_path << std::endl;
    std::cout << "  Backup: " << (config.backup_original ? "yes" : "no") << std::endl;
    
    // Analyze the binary first
    ink::InkPacketPatcher patcher(config);
    auto info = patcher.analyze_binary();
    
    std::cout << "\nBinary analysis:" << std::endl;
    std::cout << "  Total size: " << info.total_size << " bytes" << std::endl;
    std::cout << "  Has payload: " << (info.has_existing_payload ? "yes" : "no") << std::endl;
    if (info.size_placeholder_offset != 0) {
        std::cout << "  Size placeholder at: 0x" << std::hex << info.size_placeholder_offset << std::dec << std::endl;
    }
    
    // Patch the binary
    std::cout << "\nPatching binary..." << std::endl;
    if (patcher.patch()) {
        std::cout << "\n✅ Success! Binary has been protected." << std::endl;
        std::cout << "The payload will only decrypt if the binary is unmodified." << std::endl;
    } else {
        std::cerr << "\n❌ Error: " << patcher.get_error() << std::endl;
        return 1;
    }
    
    return 0;
}