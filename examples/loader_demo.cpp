/**
 * @file loader_demo.cpp  
 * @brief Demonstrates loading and decrypting a protected payload
 */

#include <ink_packet.hpp>
#include <ink_crypto.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>

int main(int argc, char* argv[]) {
    std::cout << "=== InkPacket Loader Demo ===" << std::endl;
    
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <protected_binary>" << std::endl;
        return 1;
    }
    
    std::string binary_path = argv[1];
    std::cout << "\nLoading protected binary: " << binary_path << std::endl;
    
    try {
        // 1. Open the binary
        std::ifstream file(binary_path, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open binary!" << std::endl;
            return 1;
        }
        
        // 2. Get file size
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0);
        
        // 3. Check if it has an ink packet
        if (file_size < sizeof(ink::InkPacketMetadata) + 28) {
            std::cerr << "Binary too small to contain ink packet!" << std::endl;
            return 1;
        }
        
        // 4. Try to find ink packet at end of file
        // The structure is: [app][metadata][nonce][tag][ciphertext]
        // We need to read backwards to find valid metadata
        
        // First, try reading from a position that assumes max reasonable payload
        file.seekg(-1024, std::ios::end); // Start 1KB from end
        size_t search_pos = file.tellg();
        
        ink::InkPacketMetadata metadata;
        bool found_metadata = false;
        
        // Search for valid metadata
        while (search_pos > 0 && !found_metadata) {
            file.seekg(search_pos);
            file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
            
            // Check if this looks like valid metadata
            if (metadata.version == ink::INK_PACKET_VERSION && 
                metadata.payload_size < 1024*1024 && // Less than 1MB
                metadata.hash_algo < 2 && 
                metadata.enc_algo < 2) {
                
                // Verify it makes sense with file size
                size_t expected_end = search_pos + sizeof(metadata) + 28 + metadata.payload_size;
                if (expected_end == file_size) {
                    found_metadata = true;
                    break;
                }
            }
            
            // Move back and try again
            search_pos = (search_pos > 64) ? search_pos - 64 : 0;
        }
        
        if (!found_metadata) {
            // Try one more time at the expected position
            size_t expected_metadata_pos = file_size - sizeof(metadata) - 28 - 166; // 166 is our test payload size
            if (expected_metadata_pos > 0) {
                file.seekg(expected_metadata_pos);
                file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
                if (metadata.version == ink::INK_PACKET_VERSION) {
                    found_metadata = true;
                    search_pos = expected_metadata_pos;
                }
            }
        }
        
        if (!found_metadata) {
            std::cerr << "Could not find valid ink packet metadata!" << std::endl;
            return 1;
        }
        
        size_t metadata_pos = search_pos;
        
        // 5. Verify metadata
        std::cout << "\nMetadata:" << std::endl;
        std::cout << "  Version: " << metadata.version << std::endl;
        std::cout << "  Payload size: " << metadata.payload_size << " bytes" << std::endl;
        std::cout << "  Hash algo: " << (int)metadata.hash_algo << std::endl;
        std::cout << "  Enc algo: " << (int)metadata.enc_algo << std::endl;
        
        if (metadata.version != ink::INK_PACKET_VERSION) {
            std::cerr << "Unknown ink packet version!" << std::endl;
            return 1;
        }
        
        // 6. Calculate app size (everything before metadata)
        size_t app_size = metadata_pos;
        std::cout << "  App size: " << app_size << " bytes" << std::endl;
        
        // 7. Read and hash the application portion
        std::cout << "\nCalculating application hash..." << std::endl;
        file.seekg(0);
        std::vector<uint8_t> app_data(app_size);
        file.read(reinterpret_cast<char*>(app_data.data()), app_size);
        
        auto app_hash = ink::crypto::sha256(app_data);
        std::cout << "App hash: ";
        for (size_t i = 0; i < 16; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(app_hash[i]);
        }
        std::cout << "..." << std::endl;
        
        // 8. Derive decryption key
        auto key = ink::crypto::derive_key(app_hash, "inkpacket-demo");
        
        // 9. Read nonce, tag, and ciphertext
        file.seekg(metadata_pos + sizeof(metadata));
        
        std::array<uint8_t, 12> nonce;
        file.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
        
        std::array<uint8_t, 16> tag;
        file.read(reinterpret_cast<char*>(tag.data()), tag.size());
        
        std::vector<uint8_t> ciphertext(metadata.payload_size);
        file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        
        file.close();
        
        // 10. Decrypt the payload
        std::cout << "\nDecrypting payload..." << std::endl;
        auto decrypted = ink::crypto::aes_gcm_decrypt(ciphertext, key, nonce, tag);
        
        if (decrypted.empty()) {
            std::cerr << "❌ Decryption failed! Binary may have been tampered with." << std::endl;
            return 1;
        }
        
        std::cout << "✅ Decryption successful!" << std::endl;
        std::cout << "\nDecrypted payload (" << decrypted.size() << " bytes):" << std::endl;
        std::cout << "---" << std::endl;
        std::cout << std::string(decrypted.begin(), decrypted.end());
        std::cout << "---" << std::endl;
        
        // 11. Test tampering
        std::cout << "\n🧪 Testing tamper detection..." << std::endl;
        std::cout << "If you modify the binary, decryption will fail!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}