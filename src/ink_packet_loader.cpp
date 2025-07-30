/**
 * @file ink_packet_loader.cpp
 * @brief Runtime loader implementation for ink packet protected binaries
 */

#include "../include/ink_packet.hpp"
#include <psyfer.hpp>
#include <fstream>
#include <cstring>
#include <filesystem>
#include <memory>

#if defined(_WIN32)
    #include <windows.h>
#else
    #include <dlfcn.h>
    #include <unistd.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
#endif

namespace ink {

// Define the embedded size variable
alignas(8) volatile uint64_t InkPacketEmbeddedSize::app_size = 0xDEADC0DEDEADC0DE;

namespace fs = std::filesystem;

class InkPacketLoader::Impl {
public:
    explicit Impl(const std::string& binary_path) : binary_path_(binary_path) {}
    
    ~Impl() {
        unload();
    }
    
    bool verify(std::string& error) {
        try {
            // Read embedded size value
            uint64_t embedded_size = InkPacketEmbeddedSize::app_size;
            
            // Check if size has been patched (not the placeholder value)
            if (embedded_size == 0xDEADC0DEDEADC0DE) {
                error = "Binary has not been properly patched with size information";
                return false;
            }
            
            // Read the binary file
            std::ifstream file(binary_path_, std::ios::binary);
            if (!file) {
                error = "Failed to open binary file: " + binary_path_;
                return false;
            }
            
            // Read exactly the embedded size
            std::vector<uint8_t> app_data(embedded_size);
            file.read(reinterpret_cast<char*>(app_data.data()), embedded_size);
            if (!file) {
                error = "Failed to read application portion";
                return false;
            }
            
            // Read metadata
            InkPacketMetadata metadata;
            file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
            if (!file) {
                error = "Failed to read metadata";
                return false;
            }
            
            // Verify metadata
            uint32_t calc_checksum = calculate_crc32(&metadata, sizeof(metadata));
            if (calc_checksum != 0) { // CRC32 of data including checksum should be 0
                error = "Metadata checksum verification failed";
                return false;
            }
            
            if (metadata.version != INK_PACKET_VERSION) {
                error = "Unsupported ink packet version: " + std::to_string(metadata.version);
                return false;
            }
            
            // Store metadata for later use
            metadata_ = metadata;
            app_hash_ = calculate_hash(app_data, metadata.hash_algo);
            
            return true;
            
        } catch (const std::exception& e) {
            error = "Verification failed: " + std::string(e.what());
            return false;
        }
    }
    
    bool load(std::string& error) {
        try {
            if (app_hash_.empty()) {
                if (!verify(error)) {
                    return false;
                }
            }
            
            // Read encrypted payload
            std::ifstream file(binary_path_, std::ios::binary);
            if (!file) {
                error = "Failed to open binary file";
                return false;
            }
            
            // Seek to payload
            uint64_t embedded_size = InkPacketEmbeddedSize::app_size;
            file.seekg(embedded_size + sizeof(InkPacketMetadata));
            
            // Read encrypted payload
            std::vector<uint8_t> encrypted_payload(metadata_.payload_size);
            file.read(reinterpret_cast<char*>(encrypted_payload.data()), metadata_.payload_size);
            if (!file) {
                error = "Failed to read encrypted payload";
                return false;
            }
            
            // Decrypt payload
            std::vector<uint8_t> decrypted = decrypt_payload(encrypted_payload, app_hash_, 
                                                              metadata_.enc_algo, error);
            if (decrypted.empty()) {
                return false;
            }
            
            // Load into memory
            if (!load_library_from_memory(decrypted, error)) {
                return false;
            }
            
            return true;
            
        } catch (const std::exception& e) {
            error = "Load failed: " + std::string(e.what());
            return false;
        }
    }
    
    void* get_symbol(const std::string& name) const {
        if (!handle_) return nullptr;
        
#ifdef _WIN32
        return GetProcAddress(static_cast<HMODULE>(handle_), name.c_str());
#else
        return dlsym(handle_, name.c_str());
#endif
    }
    
private:
    std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data, uint8_t algo) {
        if (algo == 0) { // SHA-256
            std::array<std::byte, 32> hash;
            psyfer::hash::sha256::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        } else if (algo == 1) { // SHA-512
            std::array<std::byte, 64> hash;
            psyfer::hash::sha512::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        }
        return {};
    }
    
    std::vector<uint8_t> decrypt_payload(const std::vector<uint8_t>& encrypted,
                                         const std::vector<uint8_t>& hash,
                                         uint8_t enc_algo,
                                         std::string& error) {
        // Derive decryption key from hash
        std::array<std::byte, 32> key;
        const char* info = "ink_packet_encryption";
        std::array<std::byte, 32> salt{}; // Empty salt
        
        auto kdf_err = psyfer::kdf::hkdf::derive_sha256(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(hash.data()), hash.size()),
            salt,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(info), strlen(info)),
            key
        );
        
        if (kdf_err) {
            error = "Failed to derive key";
            return {};
        }
        
        if (enc_algo == 0) { // AES-256-GCM
            return decrypt_aes256(key, encrypted, error);
        } else if (enc_algo == 1) { // ChaCha20
            return decrypt_chacha20(key, encrypted, error);
        }
        
        error = "Unsupported encryption algorithm";
        return {};
    }
    
    std::vector<uint8_t> decrypt_aes256(const std::array<std::byte, 32>& key,
                                        const std::vector<uint8_t>& encrypted,
                                        std::string& error) {
        constexpr size_t IV_LEN = 16;
        constexpr size_t TAG_LEN = 16;
        
        if (encrypted.size() < IV_LEN + TAG_LEN) {
            error = "Encrypted data too small";
            return {};
        }
        
        // Extract components
        std::span<const std::byte> iv(
            reinterpret_cast<const std::byte*>(encrypted.data()), IV_LEN);
        size_t data_len = encrypted.size() - IV_LEN - TAG_LEN;
        std::span<const std::byte> tag(
            reinterpret_cast<const std::byte*>(encrypted.data() + IV_LEN + data_len), TAG_LEN);
        
        // Copy ciphertext for in-place decryption
        std::vector<std::byte> decrypt_data(
            reinterpret_cast<const std::byte*>(encrypted.data() + IV_LEN),
            reinterpret_cast<const std::byte*>(encrypted.data() + IV_LEN + data_len)
        );
        
        // Decrypt
        psyfer::crypto::aes256_gcm cipher;
        auto decrypt_err = cipher.decrypt(
            decrypt_data,
            key,
            iv,
            tag
        );
        
        if (decrypt_err) {
            error = "Decryption failed - data may be corrupted or tampered";
            return {};
        }
        
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(decrypt_data.data()),
            reinterpret_cast<const uint8_t*>(decrypt_data.data() + decrypt_data.size())
        );
    }
    
    std::vector<uint8_t> decrypt_chacha20(const std::array<std::byte, 32>& key,
                                          const std::vector<uint8_t>& encrypted,
                                          std::string& error) {
        constexpr size_t NONCE_LEN = 12;
        constexpr size_t TAG_LEN = 16;
        
        if (encrypted.size() < NONCE_LEN + TAG_LEN) {
            error = "Encrypted data too small";
            return {};
        }
        
        // Extract components
        std::span<const std::byte> nonce(
            reinterpret_cast<const std::byte*>(encrypted.data()), NONCE_LEN);
        size_t data_len = encrypted.size() - NONCE_LEN - TAG_LEN;
        std::span<const std::byte> tag(
            reinterpret_cast<const std::byte*>(encrypted.data() + NONCE_LEN + data_len), TAG_LEN);
        
        // Copy ciphertext for in-place decryption
        std::vector<std::byte> decrypt_data(
            reinterpret_cast<const std::byte*>(encrypted.data() + NONCE_LEN),
            reinterpret_cast<const std::byte*>(encrypted.data() + NONCE_LEN + data_len)
        );
        
        // Decrypt
        psyfer::crypto::chacha20_poly1305 cipher;
        auto decrypt_err = cipher.decrypt(
            decrypt_data,
            key,
            nonce,
            tag
        );
        
        if (decrypt_err) {
            error = "Decryption failed - data may be corrupted or tampered";
            return {};
        }
        
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(decrypt_data.data()),
            reinterpret_cast<const uint8_t*>(decrypt_data.data() + decrypt_data.size())
        );
    }
    
    bool load_library_from_memory(const std::vector<uint8_t>& library_data,
                                  std::string& error) {
#ifdef _WIN32
        // Windows: Use custom PE loader
        error = "Memory loading not yet implemented for Windows";
        return false;
#else
        // Unix: Write to temp file and load
        // This is less secure but portable - a production version would
        // implement proper in-memory loading
        
        // Create temp file with restricted permissions
        char temp_name[] = "/tmp/ink_XXXXXX";
        int fd = mkstemp(temp_name);
        if (fd < 0) {
            error = "Failed to create temporary file";
            return false;
        }
        
        // Write library data
        if (write(fd, library_data.data(), library_data.size()) != 
            static_cast<ssize_t>(library_data.size())) {
            close(fd);
            unlink(temp_name);
            error = "Failed to write library data";
            return false;
        }
        close(fd);
        
        // Make executable
        chmod(temp_name, 0700);
        
        // Load library
        handle_ = dlopen(temp_name, RTLD_NOW | RTLD_LOCAL);
        
        // Delete temp file immediately (library remains in memory)
        unlink(temp_name);
        
        if (!handle_) {
            error = "Failed to load library: " + std::string(dlerror());
            return false;
        }
        
        return true;
#endif
    }
    
    void unload() {
        if (handle_) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(handle_));
#else
            dlclose(handle_);
#endif
            handle_ = nullptr;
        }
    }
    
    uint32_t calculate_crc32(const void* data, size_t size) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc ^= bytes[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }
    
    std::string binary_path_;
    InkPacketMetadata metadata_;
    std::vector<uint8_t> app_hash_;
    void* handle_ = nullptr;
};

// Public interface implementation

InkPacketLoader::InkPacketLoader() 
    : impl_(std::make_unique<Impl>(fs::canonical("/proc/self/exe").string())) {}

InkPacketLoader::InkPacketLoader(const std::string& binary_path)
    : impl_(std::make_unique<Impl>(binary_path)) {}

InkPacketLoader::~InkPacketLoader() = default;

bool InkPacketLoader::verify() const {
    return impl_->verify(const_cast<std::string&>(error_));
}

bool InkPacketLoader::load() {
    loaded_ = impl_->load(error_);
    return loaded_;
}

void* InkPacketLoader::get_symbol(const std::string& symbol_name) const {
    return impl_->get_symbol(symbol_name);
}

} // namespace ink