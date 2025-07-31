/**
 * @file crypto_demo.cpp
 * @brief Demonstrates the encryption/decryption workflow
 */

#include <ink_packet.hpp>
#include <ink_crypto.hpp>
#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>

void print_hex(const std::string& label, std::span<const uint8_t> data) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), size_t(32)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::dec << " (" << data.size() << " bytes)" << std::endl;
}

int main() {
    std::cout << "=== InkPacket Crypto Demo ===" << std::endl;
    
    // 1. Simulate a "protected" function
    const std::string secret_code = R"(
#include <iostream>
void secret_function() {
    std::cout << "🔓 This is the protected function!" << std::endl;
    std::cout << "🔐 It was encrypted and is now running!" << std::endl;
}
)";
    
    std::cout << "\n1. Original secret code:" << std::endl;
    std::cout << "---" << std::endl << secret_code << "---" << std::endl;
    
    // 2. Calculate hash of "binary" (using this executable)
    std::cout << "\n2. Calculating hash of this binary..." << std::endl;
    auto binary_hash = ink::verify::hash_self(0);
    if (binary_hash.empty()) {
        std::cerr << "Failed to hash binary!" << std::endl;
        return 1;
    }
    print_hex("Binary SHA-256", binary_hash);
    
    // 3. Derive encryption key from hash
    std::cout << "\n3. Deriving encryption key from binary hash..." << std::endl;
    std::array<uint8_t, 32> hash_array;
    std::copy_n(binary_hash.begin(), 32, hash_array.begin());
    auto key = ink::crypto::derive_key(hash_array, "inkpacket-demo");
    print_hex("Derived key", key);
    
    // 4. Encrypt the secret code
    std::cout << "\n4. Encrypting secret code with AES-256-GCM..." << std::endl;
    std::vector<uint8_t> plaintext(secret_code.begin(), secret_code.end());
    auto encrypted = ink::crypto::aes_gcm_encrypt(plaintext, key);
    
    print_hex("Nonce", encrypted.nonce);
    print_hex("Tag", encrypted.tag);
    print_hex("Ciphertext", encrypted.ciphertext);
    
    // 5. Simulate binary modification (would break decryption)
    std::cout << "\n5. Simulating tamper detection..." << std::endl;
    
    // First, decrypt with correct key (should work)
    auto decrypted = ink::crypto::aes_gcm_decrypt(
        encrypted.ciphertext, key, encrypted.nonce, encrypted.tag);
    
    if (!decrypted.empty()) {
        std::cout << "✅ Decryption successful with correct binary hash!" << std::endl;
        std::cout << "Decrypted size: " << decrypted.size() << " bytes" << std::endl;
    } else {
        std::cout << "❌ Decryption failed!" << std::endl;
    }
    
    // Now simulate wrong key (tampered binary)
    std::cout << "\n6. Testing with tampered binary (wrong hash)..." << std::endl;
    std::array<uint8_t, 32> fake_hash;
    fake_hash.fill(0xFF); // Fake hash
    auto wrong_key = ink::crypto::derive_key(fake_hash, "inkpacket-demo");
    
    auto failed_decrypt = ink::crypto::aes_gcm_decrypt(
        encrypted.ciphertext, wrong_key, encrypted.nonce, encrypted.tag);
    
    if (failed_decrypt.empty()) {
        std::cout << "✅ Tamper detection works! Wrong key = no decryption" << std::endl;
    } else {
        std::cout << "❌ ERROR: Decryption should have failed!" << std::endl;
    }
    
    // 7. Create a simple "ink packet" structure
    std::cout << "\n7. Creating ink packet structure..." << std::endl;
    
    // Write to file to simulate protected binary
    std::ofstream out("demo_packet.ink", std::ios::binary);
    
    // Write metadata
    ink::InkPacketMetadata metadata{};
    metadata.version = ink::INK_PACKET_VERSION;
    metadata.payload_size = encrypted.ciphertext.size();
    metadata.hash_algo = 0; // SHA-256
    metadata.enc_algo = 0;  // AES-GCM
    metadata.flags = 0;
    
    out.write(reinterpret_cast<const char*>(&metadata), sizeof(metadata));
    out.write(reinterpret_cast<const char*>(encrypted.nonce.data()), encrypted.nonce.size());
    out.write(reinterpret_cast<const char*>(encrypted.tag.data()), encrypted.tag.size());
    out.write(reinterpret_cast<const char*>(encrypted.ciphertext.data()), encrypted.ciphertext.size());
    out.close();
    
    std::cout << "✅ Created demo_packet.ink (" 
              << (sizeof(metadata) + encrypted.nonce.size() + encrypted.tag.size() + encrypted.ciphertext.size()) 
              << " bytes)" << std::endl;
    
    std::cout << "\n=== Demo completed! ===" << std::endl;
    std::cout << "\nKey insight: The binary IS the password!" << std::endl;
    std::cout << "- Any modification to the binary changes its hash" << std::endl;
    std::cout << "- Wrong hash = wrong key = decryption fails" << std::endl;
    std::cout << "- This provides automatic tamper detection! 🛡️" << std::endl;
    
    return 0;
}