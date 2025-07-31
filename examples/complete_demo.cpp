/**
 * @file complete_demo.cpp
 * @brief Complete demonstration of InkPacket protection system
 */

#include <ink_packet.hpp>
#include <ink_crypto.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>

// Embedded size for self-protection
namespace ink {
    // This will be found and patched by the patcher
    alignas(8) static volatile uint64_t demo_app_size = 0xDEADC0DEDEADC0DE;
}

// Global argv for get_self_path
static char** g_argv = nullptr;

void print_hex(const std::string& label, std::span<const uint8_t> data, size_t max_bytes = 32) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_bytes) std::cout << "...";
    std::cout << std::dec << " (" << data.size() << " bytes)" << std::endl;
}

bool check_for_payload() {
    // Try to find our own payload
    std::ifstream self(g_argv[0], std::ios::binary);
    if (!self) return false;
    
    self.seekg(0, std::ios::end);
    size_t file_size = self.tellg();
    
    // Look for metadata at expected position
    if (file_size > sizeof(ink::InkPacketMetadata) + 28) {
        self.seekg(-(sizeof(ink::InkPacketMetadata) + 28 + 166), std::ios::end); // 166 is typical payload
        ink::InkPacketMetadata metadata;
        self.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
        
        if (metadata.version == ink::INK_PACKET_VERSION) {
            return true;
        }
    }
    
    return false;
}

void load_and_execute_payload() {
    std::cout << "\n🔓 Attempting to load protected payload..." << std::endl;
    
    // Get our own path
    std::string self_path = g_argv[0];
    if (self_path.empty()) {
        std::cerr << "Failed to get self path!" << std::endl;
        return;
    }
    
    std::ifstream file(self_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open self!" << std::endl;
        return;
    }
    
    // Get actual app size
    uint64_t app_size = ink::demo_app_size;
    if (app_size == 0xDEADC0DEDEADC0DE) {
        std::cout << "Warning: Size not patched, using file size" << std::endl;
        file.seekg(0, std::ios::end);
        app_size = file.tellg();
    } else {
        std::cout << "Using patched app size: " << app_size << " bytes" << std::endl;
    }
    
    // Read and hash app portion
    file.seekg(0);
    std::vector<uint8_t> app_data(app_size);
    file.read(reinterpret_cast<char*>(app_data.data()), app_size);
    
    auto app_hash = ink::crypto::sha256(app_data);
    print_hex("App hash", app_hash, 16);
    
    // Read metadata
    file.seekg(app_size);
    ink::InkPacketMetadata metadata;
    file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
    
    // Read crypto parameters
    std::array<uint8_t, 12> nonce;
    file.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    
    std::array<uint8_t, 16> tag;
    file.read(reinterpret_cast<char*>(tag.data()), tag.size());
    
    std::vector<uint8_t> ciphertext(metadata.payload_size);
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    
    // Derive key and decrypt
    auto key = ink::crypto::derive_key(app_hash, "inkpacket-demo");
    auto decrypted = ink::crypto::aes_gcm_decrypt(ciphertext, key, nonce, tag);
    
    if (!decrypted.empty()) {
        std::cout << "\n✅ Payload decrypted successfully!" << std::endl;
        std::cout << "\nProtected content:" << std::endl;
        std::cout << "=================" << std::endl;
        std::cout << std::string(decrypted.begin(), decrypted.end());
        std::cout << "=================" << std::endl;
    } else {
        std::cout << "\n❌ Decryption failed! Binary may have been tampered with." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Make argv[0] available globally
    g_argv = argv;
    
    std::cout << "=== InkPacket Complete Demo ===" << std::endl;
    std::cout << "This binary can protect itself!" << std::endl;
    
    // Show current state
    std::cout << "\n📊 Binary info:" << std::endl;
    std::cout << "  Path: " << argv[0] << std::endl;
    std::cout << "  Embedded size value: 0x" << std::hex << ink::demo_app_size << std::dec << std::endl;
    
    if (ink::demo_app_size == 0xDEADC0DEDEADC0DE) {
        std::cout << "  Status: Not protected (size not patched)" << std::endl;
    } else {
        std::cout << "  Status: Protected (size = " << ink::demo_app_size << " bytes)" << std::endl;
    }
    
    // Calculate our hash
    auto self_hash = ink::verify::hash_self(0);
    if (!self_hash.empty()) {
        print_hex("  Self hash", self_hash, 16);
    }
    
    // Check if we have a payload
    if (check_for_payload()) {
        std::cout << "\n🔐 Protected payload detected!" << std::endl;
        load_and_execute_payload();
    } else {
        std::cout << "\n📝 No protected payload found." << std::endl;
        std::cout << "To protect this binary:" << std::endl;
        std::cout << "  1. Create a payload file with secret content" << std::endl;
        std::cout << "  2. Run: ./example_patcher " << argv[0] << " payload.txt" << std::endl;
        std::cout << "  3. Run the protected binary again" << std::endl;
    }
    
    // Demonstrate tampering
    if (argc > 1 && std::string(argv[1]) == "--tamper-test") {
        std::cout << "\n🧪 Tamper test mode!" << std::endl;
        std::cout << "Modifying one byte of this binary would break decryption..." << std::endl;
        std::cout << "Try: echo 'X' | dd of=" << argv[0] << " bs=1 seek=1000 count=1 conv=notrunc" << std::endl;
        std::cout << "Then run again to see decryption fail!" << std::endl;
    }
    
    std::cout << "\n✨ Demo complete!" << std::endl;
    return 0;
}

