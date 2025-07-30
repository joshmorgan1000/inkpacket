#include "../include/ink_packet.hpp"
#include <psyfer.hpp>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <array>

namespace ink {

namespace fs = std::filesystem;

class InkPacketBuilder::Impl {
public:
    explicit Impl(const Config& cfg) : config(cfg) {}
    
    bool build(std::string& log, std::string& error) {
        try {
            log.clear();
            
            // Create temp directory for build artifacts
            fs::path temp_dir = fs::temp_directory_path() / ("ink_build_" + std::to_string(rand()));
            fs::create_directories(temp_dir);
            
            log += "Created temp directory: " + temp_dir.string() + "\n";
            
            // Step 1: Build critical components as shared library
            fs::path lib_path = temp_dir / "critical.so";
            if (!build_shared_library(temp_dir, lib_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Step 2: Build main executable
            fs::path exe_path = temp_dir / "main.exe";
            if (!build_main_executable(temp_dir, exe_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Step 3: Package into ink packet
            if (!create_ink_packet(exe_path, lib_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Cleanup
            fs::remove_all(temp_dir);
            log += "Build completed successfully\n";
            return true;
            
        } catch (const std::exception& e) {
            error = "Build failed: " + std::string(e.what());
            return false;
        }
    }
    
private:
    bool build_shared_library(const fs::path& temp_dir, const fs::path& output,
                              std::string& log, std::string& error) {
        std::stringstream cmd;
        cmd << config.compiler << " " << config.cxx_flags;
        cmd << " -shared -fPIC";
        
        // Add critical sources
        for (const auto& src : config.critical_sources) {
            cmd << " " << src;
        }
        
        // Add include directories
        cmd << " -I" << fs::path(config.main_source).parent_path().string();
        
        // Output
        cmd << " -o " << output.string();
        
        log += "Building shared library: " + cmd.str() + "\n";
        
        int result = std::system(cmd.str().c_str());
        if (result != 0) {
            error = "Failed to build shared library";
            return false;
        }
        
        if (config.strip_symbols) {
            std::string strip_cmd = "strip -x " + output.string();
            std::system(strip_cmd.c_str());
        }
        
        return true;
    }
    
    bool build_main_executable(const fs::path& temp_dir, const fs::path& output,
                               std::string& log, std::string& error) {
        // Generate loader stub
        fs::path stub_path = temp_dir / "loader_stub.cpp";
        if (!generate_loader_stub(stub_path, error)) {
            return false;
        }
        
        std::stringstream cmd;
        cmd << config.compiler << " " << config.cxx_flags;
        
        // Add main source and stub
        cmd << " " << config.main_source;
        cmd << " " << stub_path.string();
        
        // Add non-critical sources
        for (const auto& src : config.sources) {
            bool is_critical = false;
            for (const auto& crit : config.critical_sources) {
                if (src == crit) {
                    is_critical = true;
                    break;
                }
            }
            if (!is_critical) {
                cmd << " " << src;
            }
        }
        
        // Add libraries
        for (const auto& lib : config.link_libs) {
            cmd << " -l" << lib;
        }
        
        // Output
        cmd << " -o " << output.string();
        
        log += "Building main executable: " + cmd.str() + "\n";
        
        int result = std::system(cmd.str().c_str());
        if (result != 0) {
            error = "Failed to build main executable";
            return false;
        }
        
        if (config.strip_symbols) {
            std::string strip_cmd = "strip " + output.string();
            std::system(strip_cmd.c_str());
        }
        
        return true;
    }
    
    bool generate_loader_stub(const fs::path& output, std::string& error) {
        std::ofstream stub(output);
        if (!stub) {
            error = "Failed to create loader stub";
            return false;
        }
        
        // Generate code that will load the encrypted library at runtime
        stub << R"(
#include <memory>
#include <stdexcept>

namespace __ink_packet {
    struct LibraryLoader {
        void* handle = nullptr;
        
        LibraryLoader() {
            // This will be replaced with actual loader code
            // For now, just a placeholder
        }
        
        ~LibraryLoader() {
            // Cleanup
        }
        
        template<typename T>
        T get_function(const char* name) {
            // Placeholder - will be implemented properly
            return nullptr;
        }
    };
    
    static std::unique_ptr<LibraryLoader> loader;
    
    void init() {
        if (!loader) {
            loader = std::make_unique<LibraryLoader>();
        }
    }
}

// Initialize before main
__attribute__((constructor))
void __ink_packet_init() {
    __ink_packet::init();
}
)";
        
        return true;
    }
    
    bool create_ink_packet(const fs::path& exe_path, const fs::path& lib_path,
                           std::string& log, std::string& error) {
        // Read executable
        std::vector<uint8_t> exe_data = read_file(exe_path);
        if (exe_data.empty()) {
            error = "Failed to read executable";
            return false;
        }
        
        // Read library
        std::vector<uint8_t> lib_data = read_file(lib_path);
        if (lib_data.empty()) {
            error = "Failed to read library";
            return false;
        }
        
        // Create initial packet structure
        std::vector<uint8_t> packet;
        
        // Reserve space for header
        // Write metadata structure
        InkPacketMetadata metadata = {};
        metadata.version = INK_PACKET_VERSION;
        metadata.hash_algo = config.hash_algo;
        metadata.enc_algo = config.enc_algo;
        metadata.flags = 0;
        
        // Start with executable data
        packet = exe_data;
        
        // Add metadata after executable
        size_t metadata_offset = packet.size();
        packet.resize(packet.size() + sizeof(metadata));
        
        // Calculate hash of executable portion only
        std::vector<uint8_t> exe_hash = calculate_hash(exe_data);
        
        // Encrypt library using hash-derived key
        std::vector<uint8_t> encrypted_lib = encrypt_payload(lib_data, exe_hash);
        
        // Update metadata with payload info
        metadata.payload_size = encrypted_lib.size();
        
        // Append encrypted library
        packet.insert(packet.end(), encrypted_lib.begin(), encrypted_lib.end());
        
        // Calculate metadata checksum
        metadata.checksum = 0;
        metadata.checksum = crc32(reinterpret_cast<uint8_t*>(&metadata), sizeof(metadata));
        
        // Write metadata to packet
        std::memcpy(packet.data() + metadata_offset, &metadata, sizeof(metadata));
        
        // Write final packet
        std::ofstream out(config.output_path, std::ios::binary);
        if (!out) {
            error = "Failed to write output file";
            return false;
        }
        
        out.write(reinterpret_cast<const char*>(packet.data()), packet.size());
        
        // Make executable
#ifndef _WIN32
        fs::permissions(config.output_path, 
                        fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                        fs::perm_options::add);
#endif
        
        log += "Created ink packet: " + config.output_path + "\n";
        log += "  Executable size: " + std::to_string(exe_data.size()) + " bytes\n";
        log += "  Protected library size: " + std::to_string(lib_data.size()) + " bytes\n";
        log += "  Total size: " + std::to_string(packet.size()) + " bytes\n";
        
        return true;
    }
    
    std::vector<uint8_t> read_file(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        return data;
    }
    
    std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data) {
        if (config.hash_algo == 0) { // SHA-256
            std::array<std::byte, 32> hash;
            psyfer::hash::sha256::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        } else if (config.hash_algo == 1) { // SHA-512
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
    
    std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& hash) {
        // Derive encryption key from hash using HKDF
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
        auto iv_err = psyfer::utils::secure_random::generate(iv);
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
        psyfer::crypto::aes256_gcm cipher;
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
        auto nonce_err = psyfer::utils::secure_random::generate(nonce);
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
        psyfer::crypto::chacha20_poly1305 cipher;
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
    
    uint32_t crc32(const uint8_t* data, size_t size) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }
    
    Config config;
};

InkPacketBuilder::InkPacketBuilder(const Config& config) 
    : impl_(std::make_unique<Impl>(config)), config_(config) {}

InkPacketBuilder::~InkPacketBuilder() = default;

bool InkPacketBuilder::build() {
    return impl_->build(log_, error_);
}

}
