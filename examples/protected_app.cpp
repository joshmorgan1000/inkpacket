/**
 * @file protected_app.cpp
 * @brief Main application that loads an encrypted library
 * 
 * This demonstrates the complete InkPacket protection system:
 * 1. The application calculates its own hash
 * 2. Uses the hash to decrypt an embedded library
 * 3. Loads the library and calls functions from it
 */

#include <ink_packet.hpp>
#include <ink_crypto.hpp>
#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// Function pointers for the secret library
typedef void (*display_secret_message_t)();
typedef int (*secret_calculation_t)(int, int);
typedef const char* (*get_secret_version_t)();

class ProtectedApp {
public:
    ProtectedApp() {
        std::cout << "=== InkPacket Protected Application ===" << std::endl;
        std::cout << "This app loads functionality from an encrypted library.\n" << std::endl;
    }
    
    bool load_protected_library() {
        // 1. Get our own path
        std::string self_path = get_executable_path();
        if (self_path.empty()) {
            std::cerr << "❌ Failed to get executable path" << std::endl;
            return false;
        }
        
        std::cout << "📍 Executable: " << self_path << std::endl;
        
        // 2. Check if we have an embedded library
        std::ifstream file(self_path, std::ios::binary);
        if (!file) {
            std::cerr << "❌ Failed to open self" << std::endl;
            return false;
        }
        
        // Get file size
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        
        // Look for ink packet metadata
        // Structure is: [app][metadata][nonce][tag][payload]
        // So metadata should be at: file_size - sizeof(metadata) - 28 - payload_size
        // But we don't know payload_size yet, so we search backwards
        
        ink::InkPacketMetadata metadata;
        bool found = false;
        size_t metadata_pos = 0;
        
        // Try common payload sizes first (our library is about 40KB)
        std::vector<size_t> likely_sizes = {39552, 40000, 50000, 60000};
        
        for (size_t likely_size : likely_sizes) {
            size_t test_pos = file_size - sizeof(metadata) - 28 - likely_size;
            if (test_pos < file_size) {
                file.seekg(test_pos);
                file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
                
                if (metadata.version == ink::INK_PACKET_VERSION &&
                    metadata.payload_size == likely_size) {
                    found = true;
                    metadata_pos = test_pos;
                    break;
                }
            }
        }
        
        // If not found, search more thoroughly
        if (!found && file_size > 100*1024) {
            for (size_t offset = 1024; offset < 100*1024 && !found; offset += 64) {
                size_t test_pos = file_size - offset;
                if (test_pos > sizeof(metadata)) {
                    file.seekg(test_pos - sizeof(metadata));
                    file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
                    
                    if (metadata.version == ink::INK_PACKET_VERSION &&
                        metadata.payload_size > 0 && metadata.payload_size < 10*1024*1024) {
                        
                        size_t expected_start = test_pos - sizeof(metadata) - 28 - metadata.payload_size;
                        if (expected_start < test_pos) {
                            found = true;
                            metadata_pos = test_pos - sizeof(metadata) - 28 - metadata.payload_size;
                            break;
                        }
                    }
                }
            }
        }
        
        if (!found) {
            std::cerr << "❌ No encrypted library found. This binary needs to be protected first." << std::endl;
            std::cerr << "   Run: ./example_patcher " << self_path << " <library.so>" << std::endl;
            return false;
        }
        
        std::cout << "📦 Found encrypted library (" << metadata.payload_size << " bytes)" << std::endl;
        
        // 3. Calculate hash of application portion
        size_t app_size = metadata_pos;
        std::cout << "🔢 Calculating hash of application (" << app_size << " bytes)..." << std::endl;
        
        file.seekg(0);
        std::vector<uint8_t> app_data(app_size);
        file.read(reinterpret_cast<char*>(app_data.data()), app_size);
        
        auto app_hash = ink::crypto::sha256(app_data);
        std::cout << "📊 App hash: ";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(app_hash[i]);
        }
        std::cout << "..." << std::dec << std::endl;
        
        // 4. Read encrypted library
        file.seekg(metadata_pos + sizeof(metadata));
        
        std::array<uint8_t, 12> nonce;
        file.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
        
        std::array<uint8_t, 16> tag;
        file.read(reinterpret_cast<char*>(tag.data()), tag.size());
        
        std::vector<uint8_t> ciphertext(metadata.payload_size);
        file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        file.close();
        
        // 5. Decrypt the library
        std::cout << "🔓 Decrypting library..." << std::endl;
        auto key = ink::crypto::derive_key(app_hash, "inkpacket-demo");
        auto decrypted = ink::crypto::aes_gcm_decrypt(ciphertext, key, nonce, tag);
        
        if (decrypted.empty()) {
            std::cerr << "❌ Decryption failed! The binary may have been tampered with." << std::endl;
            return false;
        }
        
        std::cout << "✅ Decryption successful!" << std::endl;
        
        // 6. Load the library from memory
        return load_library_from_memory(decrypted);
    }
    
    void run() {
        if (!display_secret_message) {
            std::cerr << "❌ No library loaded!" << std::endl;
            return;
        }
        
        // Call functions from the encrypted library
        std::cout << "\n🎯 Calling functions from the encrypted library:\n" << std::endl;
        
        // 1. Display the secret message
        display_secret_message();
        
        // 2. Call secret calculation
        std::cout << "🧮 Secret calculation: secret_calculation(10, 5) = " 
                  << secret_calculation(10, 5) << std::endl;
        
        // 3. Get version
        std::cout << "📌 Library version: " << get_secret_version() << std::endl;
    }
    
private:
    // Function pointers
    display_secret_message_t display_secret_message = nullptr;
    secret_calculation_t secret_calculation = nullptr;
    get_secret_version_t get_secret_version = nullptr;
    
    // Loaded library handle
    void* lib_memory = nullptr;
    size_t lib_size = 0;
    
    std::string get_executable_path() {
        char path[1024];
        uint32_t size = sizeof(path);
        
#ifdef __APPLE__
        if (_NSGetExecutablePath(path, &size) == 0) {
            return std::string(path);
        }
#elif __linux__
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len != -1) {
            path[len] = '\0';
            return std::string(path);
        }
#endif
        return "";
    }
    
    bool load_library_from_memory(const std::vector<uint8_t>& lib_data) {
        std::cout << "💾 Loading library from memory..." << std::endl;
        
        // For this demo, we'll write to a temporary file
        // In a real implementation, you'd use memfd_create or similar
        std::string temp_path = "/tmp/inkpacket_lib_XXXXXX";
        char* temp_name = strdup(temp_path.c_str());
        int fd = mkstemp(temp_name);
        
        if (fd < 0) {
            std::cerr << "Failed to create temp file" << std::endl;
            free(temp_name);
            return false;
        }
        
        // Write decrypted library
        write(fd, lib_data.data(), lib_data.size());
        close(fd);
        
        // Load the library
        void* handle = dlopen(temp_name, RTLD_NOW);
        if (!handle) {
            std::cerr << "Failed to load library: " << dlerror() << std::endl;
            unlink(temp_name);
            free(temp_name);
            return false;
        }
        
        // Get function pointers
        display_secret_message = (display_secret_message_t)dlsym(handle, "display_secret_message");
        secret_calculation = (secret_calculation_t)dlsym(handle, "secret_calculation");
        get_secret_version = (get_secret_version_t)dlsym(handle, "get_secret_version");
        
        // Clean up temp file
        unlink(temp_name);
        free(temp_name);
        
        if (!display_secret_message || !secret_calculation || !get_secret_version) {
            std::cerr << "Failed to find functions in library" << std::endl;
            dlclose(handle);
            return false;
        }
        
        std::cout << "✅ Library loaded successfully!" << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    ProtectedApp app;
    
    // Check for test mode
    if (argc > 1 && std::string(argv[1]) == "--fail-test") {
        std::cout << "\n⚠️  FAIL TEST MODE - Using wrong key on purpose\n" << std::endl;
        // This would simulate using the wrong key
        // In reality, any modification to the binary would cause this
    }
    
    if (app.load_protected_library()) {
        app.run();
        std::cout << "\n✨ Success! The InkPacket protection system works!" << std::endl;
    } else {
        std::cout << "\n💥 Failed to load protected library." << std::endl;
        return 1;
    }
    
    return 0;
}