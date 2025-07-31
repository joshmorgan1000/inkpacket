/**
 * @file ink_packet_patcher.cpp
 * @brief Post-build binary patcher for creating self-protecting executables
 */

#include "../include/ink_packet.hpp"
#include <psyfer.hpp>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <iomanip>

namespace ink {

namespace fs = std::filesystem;

class InkPacketPatcher::Impl {
public:
    explicit Impl(const PatchConfig& cfg) : config(cfg) {}
    
    bool patch(std::string& error) {
        try {
            // Analyze binary first
            BinaryInfo info = analyze_binary_internal(error);
            if (info.app_size == 0) {
                return false;
            }
            
            // Check if already has payload
            if (info.has_existing_payload) {
                error = "Binary already contains an ink packet payload";
                return false;
            }
            
            // Create backup if requested
            if (config.backup_original) {
                fs::path backup = fs::path(config.binary_path).string() + ".orig";
                fs::copy_file(config.binary_path, backup, 
                              fs::copy_options::overwrite_existing);
            }
            
            // Read binary and payload
            std::vector<uint8_t> binary_data = read_file(config.binary_path);
            std::vector<uint8_t> payload_data = read_file(config.payload_path);
            
            if (binary_data.empty() || payload_data.empty()) {
                error = "Failed to read input files";
                return false;
            }
            
            // Find and patch size placeholder
            if (!patch_size_placeholder(binary_data, binary_data.size(), error)) {
                return false;
            }
            
            // Calculate hash of patched binary
            std::vector<uint8_t> app_hash = calculate_hash(binary_data, config.hash_algo);
            
            // Encrypt payload
            std::vector<uint8_t> encrypted_payload = encrypt_payload(payload_data, app_hash);
            
            // Create metadata
            InkPacketMetadata metadata = {};
            metadata.version = INK_PACKET_VERSION;
            metadata.payload_size = encrypted_payload.size();
            metadata.hash_algo = config.hash_algo;
            metadata.enc_algo = config.enc_algo;
            metadata.flags = 0;
            metadata.checksum = 0;
            metadata.checksum = calculate_crc32(&metadata, sizeof(metadata));
            
            // Assemble final binary
            std::vector<uint8_t> final_binary;
            final_binary.reserve(binary_data.size() + sizeof(metadata) + encrypted_payload.size());
            
            // Append components
            final_binary.insert(final_binary.end(), binary_data.begin(), binary_data.end());
            final_binary.insert(final_binary.end(), 
                                reinterpret_cast<uint8_t*>(&metadata),
                                reinterpret_cast<uint8_t*>(&metadata) + sizeof(metadata));
            final_binary.insert(final_binary.end(), encrypted_payload.begin(), encrypted_payload.end());
            
            // Write patched binary
            std::ofstream out(config.binary_path, std::ios::binary);
            if (!out) {
                error = "Failed to write patched binary";
                return false;
            }
            
            out.write(reinterpret_cast<const char*>(final_binary.data()), final_binary.size());
            out.close();
            
            // Verify if requested
            if (config.verify_after) {
                InkPacketLoader loader(config.binary_path);
                if (!loader.verify()) {
                    error = "Verification failed after patching: " + loader.get_error();
                    return false;
                }
            }
            
            return true;
            
        } catch (const std::exception& e) {
            error = "Patch failed: " + std::string(e.what());
            return false;
        }
    }
    
    BinaryInfo analyze_binary_internal(std::string& error) {
        BinaryInfo info = {};
        
        try {
            std::vector<uint8_t> data = read_file(config.binary_path);
            if (data.empty()) {
                error = "Failed to read binary";
                return info;
            }
            
            // Find size placeholder pattern
            const char* pattern = InkPacketSizePlaceholder::PATTERN;
            auto it = std::search(data.begin(), data.end(), pattern, pattern + 16);
            
            if (it != data.end()) {
                info.size_placeholder_offset = std::distance(data.begin(), it);
                
                // Check if there's a size value after the pattern
                if (info.size_placeholder_offset + 16 + 8 <= data.size()) {
                    uint64_t embedded_size = *reinterpret_cast<uint64_t*>(&data[info.size_placeholder_offset + 16]);
                    if (embedded_size != 0xDEADC0DEDEADC0DE && embedded_size > 0) {
                        info.app_size = embedded_size;
                    }
                }
            }
            
            // Check if binary already has metadata/payload
            if (info.app_size > 0 && data.size() > info.app_size + sizeof(InkPacketMetadata)) {
                // Try to read metadata
                InkPacketMetadata metadata;
                std::memcpy(&metadata, &data[info.app_size], sizeof(metadata));
                
                // Verify it looks like valid metadata
                uint32_t calc_checksum = calculate_crc32(&metadata, sizeof(metadata));
                if (calc_checksum == 0 && metadata.version == INK_PACKET_VERSION) {
                    info.has_existing_payload = true;
                    info.total_size = info.app_size + sizeof(metadata) + metadata.payload_size;
                }
            }
            
            if (!info.has_existing_payload) {
                info.app_size = data.size();
                info.total_size = data.size();
            }
            
            return info;
            
        } catch (const std::exception& e) {
            error = "Analysis failed: " + std::string(e.what());
            return info;
        }
    }
    
private:
    bool patch_size_placeholder(std::vector<uint8_t>& binary_data, size_t app_size,
                                std::string& error) {
        // Find the embedded size variable by looking for guard values
        uint32_t guard_before = InkPacketEmbeddedSize::GUARD_BEFORE;
        uint32_t guard_after = InkPacketEmbeddedSize::GUARD_AFTER;
        
        // Search for pattern: GUARD_BEFORE, 8-byte value, GUARD_AFTER
        for (size_t i = 0; i + 16 <= binary_data.size(); ++i) {
            uint32_t* ptr = reinterpret_cast<uint32_t*>(&binary_data[i]);
            
            if (ptr[0] == guard_before && ptr[3] == guard_after) {
                // Found it! Patch the size
                uint64_t* size_ptr = reinterpret_cast<uint64_t*>(&binary_data[i + 4]);
                *size_ptr = app_size;
                return true;
            }
        }
        
        // Alternative: look for the placeholder pattern followed by size
        const char* pattern = InkPacketSizePlaceholder::PATTERN;
        auto it = std::search(binary_data.begin(), binary_data.end(), pattern, pattern + 16);
        
        if (it != binary_data.end()) {
            size_t offset = std::distance(binary_data.begin(), it) + 16;
            if (offset + 8 <= binary_data.size()) {
                uint64_t* size_ptr = reinterpret_cast<uint64_t*>(&binary_data[offset]);
                *size_ptr = app_size;
                return true;
            }
        }
        
        error = "Could not find size placeholder in binary";
        return false;
    }
    
    std::vector<uint8_t> read_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        return data;
    }
    
    std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data, uint8_t algo) {
        if (algo == 0) { // SHA-256
            std::array<std::byte, 32> hash;
            psyfer::sha256_hasher::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        } else if (algo == 1) { // SHA-512
            std::array<std::byte, 64> hash;
            psyfer::sha512_hasher::hash(
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
    
    std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& hash) {
        // Derive encryption key from hash
        std::array<std::byte, 32> key;
        const char* info = "ink_packet_encryption";
        std::array<std::byte, 32> salt{}; // Empty salt
        
        auto kdf_err = psyfer::hkdf::derive_sha256(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(hash.data()), hash.size()),
            salt,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(info), strlen(info)),
            key
        );
        
        if (kdf_err) {
            return {};
        }
        
        if (config.enc_algo == 0) { // AES-256-GCM
            return encrypt_aes256(key, data);
        } else if (config.enc_algo == 1) { // ChaCha20
            return encrypt_chacha20(key, data);
        }
        
        return {};
    }
    
    std::vector<uint8_t> encrypt_aes256(const std::array<std::byte, 32>& key, const std::vector<uint8_t>& data) {
        constexpr size_t IV_LEN = 16;
        constexpr size_t TAG_LEN = 16;
        
        // Generate random IV
        std::array<std::byte, IV_LEN> iv;
        auto iv_err = psyfer::secure_random::generate(iv);
        if (iv_err) {
            return {};  // Failed to generate IV
        }
        
        // Create output buffer
        std::vector<uint8_t> result(IV_LEN + data.size() + TAG_LEN);
        
        // Copy IV to output
        // Copy IV to output
        for (size_t i = 0; i < IV_LEN; ++i) {
            result[i] = static_cast<uint8_t>(iv[i]);
        }
        
        // Prepare data for encryption
        std::vector<std::byte> encrypt_data(
            reinterpret_cast<const std::byte*>(data.data()),
            reinterpret_cast<const std::byte*>(data.data() + data.size())
        );
        
        // Encrypt data
        psyfer::aes256_gcm cipher;
        std::array<std::byte, TAG_LEN> tag;
        
        auto encrypt_err = cipher.encrypt(
            encrypt_data,
            key,
            iv,
            tag
        );
        
        if (encrypt_err) {
            return {};  // Encryption failed
        }
        
        // Copy encrypted data to result
        for (size_t i = 0; i < encrypt_data.size(); ++i) {
            result[IV_LEN + i] = static_cast<uint8_t>(encrypt_data[i]);
        }
        
        // Append tag
        // Append tag
        for (size_t i = 0; i < TAG_LEN; ++i) {
            result[IV_LEN + data.size() + i] = static_cast<uint8_t>(tag[i]);
        }
        
        return result;
    }
    
    std::vector<uint8_t> encrypt_chacha20(const std::array<std::byte, 32>& key, const std::vector<uint8_t>& data) {
        constexpr size_t NONCE_LEN = 12;
        constexpr size_t TAG_LEN = 16;
        
        // Generate random nonce
        std::array<std::byte, NONCE_LEN> nonce;
        auto nonce_err = psyfer::secure_random::generate(nonce);
        if (nonce_err) {
            return {};  // Failed to generate nonce
        }
        
        // Create output buffer
        std::vector<uint8_t> result(NONCE_LEN + data.size() + TAG_LEN);
        
        // Copy nonce to output
        // Copy nonce to output
        for (size_t i = 0; i < NONCE_LEN; ++i) {
            result[i] = static_cast<uint8_t>(nonce[i]);
        }
        
        // Prepare data for encryption
        std::vector<std::byte> encrypt_data(
            reinterpret_cast<const std::byte*>(data.data()),
            reinterpret_cast<const std::byte*>(data.data() + data.size())
        );
        
        // Encrypt data
        psyfer::chacha20_poly1305 cipher;
        std::array<std::byte, TAG_LEN> tag;
        
        auto encrypt_err = cipher.encrypt(
            encrypt_data,
            key,
            nonce,
            tag
        );
        
        if (encrypt_err) {
            return {};  // Encryption failed
        }
        
        // Copy encrypted data to result
        for (size_t i = 0; i < encrypt_data.size(); ++i) {
            result[NONCE_LEN + i] = static_cast<uint8_t>(encrypt_data[i]);
        }
        
        // Append tag
        // Append tag
        for (size_t i = 0; i < TAG_LEN; ++i) {
            result[NONCE_LEN + data.size() + i] = static_cast<uint8_t>(tag[i]);
        }
        
        return result;
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
    
    PatchConfig config;
};

// Public interface implementation

InkPacketPatcher::InkPacketPatcher(const PatchConfig& config)
    : impl_(std::make_unique<Impl>(config)), config_(config) {}

InkPacketPatcher::~InkPacketPatcher() = default;

bool InkPacketPatcher::patch() {
    return impl_->patch(error_);
}

InkPacketPatcher::BinaryInfo InkPacketPatcher::analyze_binary() {
    return impl_->analyze_binary_internal(error_);
}

} // namespace ink