/**
 * @file wrong_key_demo.cpp
 * @brief Demonstrates what happens when using the wrong decryption key
 */

#include <ink_packet.hpp>
#include <ink_crypto.hpp>
#include <iostream>
#include <fstream>
#include <array>

int main() {
    std::cout << "=== Wrong Key Demo ===" << std::endl;
    std::cout << "This demonstrates what happens with an incorrect decryption key.\n" << std::endl;
    
    // 1. Create some test data
    std::string secret = "This is a secret message!";
    std::vector<uint8_t> plaintext(secret.begin(), secret.end());
    
    // 2. Create correct key
    std::array<uint8_t, 32> correct_hash;
    correct_hash.fill(0xAA); // Simulated correct hash
    auto correct_key = ink::crypto::derive_key(correct_hash, "inkpacket-demo");
    
    std::cout << "📝 Original message: " << secret << std::endl;
    
    // 3. Encrypt with correct key
    auto encrypted = ink::crypto::aes_gcm_encrypt(plaintext, correct_key);
    std::cout << "🔐 Encrypted successfully" << std::endl;
    
    // 4. Try to decrypt with correct key (should work)
    std::cout << "\n✅ Decrypting with CORRECT key:" << std::endl;
    auto decrypted_correct = ink::crypto::aes_gcm_decrypt(
        encrypted.ciphertext, correct_key, encrypted.nonce, encrypted.tag);
    
    if (!decrypted_correct.empty()) {
        std::cout << "   Success! Message: " << std::string(decrypted_correct.begin(), decrypted_correct.end()) << std::endl;
    } else {
        std::cout << "   Failed (this shouldn't happen!)" << std::endl;
    }
    
    // 5. Try to decrypt with wrong key (should fail)
    std::cout << "\n❌ Decrypting with WRONG key (simulating tampered binary):" << std::endl;
    std::array<uint8_t, 32> wrong_hash;
    wrong_hash.fill(0xBB); // Different hash = wrong key
    auto wrong_key = ink::crypto::derive_key(wrong_hash, "inkpacket-demo");
    
    auto decrypted_wrong = ink::crypto::aes_gcm_decrypt(
        encrypted.ciphertext, wrong_key, encrypted.nonce, encrypted.tag);
    
    if (decrypted_wrong.empty()) {
        std::cout << "   Failed as expected! Wrong key = no decryption" << std::endl;
        std::cout << "   This is what happens when the binary is tampered with." << std::endl;
    } else {
        std::cout << "   ERROR: Decryption should have failed!" << std::endl;
    }
    
    std::cout << "\n🔑 Key insight: Any change to the binary changes its hash," << std::endl;
    std::cout << "   which changes the key, which breaks decryption!" << std::endl;
    
    return 0;
}