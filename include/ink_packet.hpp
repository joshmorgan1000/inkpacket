#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <span>
#include <array>

namespace ink {

/**
 * @brief Self-size placeholder embedded in the application binary
 * 
 * This structure contains a placeholder that gets patched at build time
 * with the actual size of the application binary. The application uses
 * this to know exactly how many bytes to hash.
 */
struct InkPacketSizePlaceholder {
    // Unique pattern for finding in binary (must be 16 bytes)
    static constexpr char PATTERN[16] = {
        'I', 'N', 'K', '_', 'S', 'I', 'Z', 'E',  // INK_SIZE
        '_', 'P', 'L', 'A', 'C', 'E', 'H', 'R'   // _PLACEIR
    };
};

/**
 * @brief Static storage for the application size
 * 
 * This will be patched post-compilation with the actual size.
 * The volatile keyword prevents compiler optimization.
 */
struct InkPacketEmbeddedSize {
    alignas(8) static volatile uint64_t app_size;
    static constexpr uint32_t GUARD_BEFORE = 0xDEADBEEF;
    static constexpr uint32_t GUARD_AFTER = 0xCAFEBABE;
};

/**
 * @brief Version of the ink packet format
 */
constexpr uint16_t INK_PACKET_VERSION = 3; // Version 3: Hash-as-salt system

/**
 * @brief Metadata structure that follows the magic boundary
 * 
 * This structure is placed immediately after the magic bytes and
 * contains information needed to decrypt the payload.
 */
struct InkPacketMetadata {
    uint32_t version;           ///< Format version (should be 3)
    uint32_t payload_size;      ///< Size of encrypted payload
    uint8_t  hash_algo;         ///< Hash algorithm (0=BLAKE3, 1=SHA256)
    uint8_t  enc_algo;          ///< Encryption algorithm (0=AES-GCM, 1=ChaCha20)
    uint16_t flags;             ///< Protection flags
    uint32_t checksum;          ///< CRC32 of this metadata structure
    uint8_t  reserved[48];      ///< Reserved for future use, zero-filled
};
static_assert(sizeof(InkPacketMetadata) == 64, "Metadata must be exactly 64 bytes");

/**
 * @brief Binary layout for hash-as-salt system
 * 
 * Layout:
 * [Application Binary with embedded size] (size determined by embedded value)
 * [Metadata - 64 bytes] 
 * [Encrypted Payload - variable size]
 * 
 * The application:
 * 1. Reads its embedded size value
 * 2. Hashes exactly that many bytes (the application portion) 
 * 3. Uses hash as salt for key derivation
 * 4. Reads metadata and decrypts payload
 */
struct InkPacketLayout {
    // Layout is self-describing via embedded size
};

/**
 * @brief Feature flags for enhanced protection
 */
enum class ProtectionFlags : uint16_t {
    NONE = 0,
    ANTI_DEBUG = 1 << 0,         ///< Enable anti-debugging checks
    MULTI_HASH = 1 << 1,         ///< Multiple hash verification points
    OBFUSCATE = 1 << 2,          ///< Extra obfuscation layers
    TIME_BOMB = 1 << 3,          ///< Enable expiration date
    HARDWARE_LOCK = 1 << 4,      ///< Lock to specific hardware
};

/**
 * @brief Runtime loader for ink packet protected binaries
 * 
 * This class handles the runtime decryption and loading of protected
 * shared libraries from within an ink packet binary.
 */
class InkPacketLoader {
public:
    /**
     * @brief Initialize the loader with the current process binary
     */
    InkPacketLoader();
    
    /**
     * @brief Initialize with explicit binary path
     */
    explicit InkPacketLoader(const std::string& binary_path);
    
    ~InkPacketLoader();
    
    /**
     * @brief Verify the integrity of the ink packet
     * @return true if the packet is valid and untampered
     */
    bool verify() const;
    
    /**
     * @brief Load and decrypt the protected payload
     * @return true if successful
     */
    bool load();
    
    /**
     * @brief Get a symbol from the decrypted library
     * @param symbol_name Name of the symbol to retrieve
     * @return Pointer to the symbol or nullptr if not found
     */
    void* get_symbol(const std::string& symbol_name) const;
    
    /**
     * @brief Template helper to get typed function pointers
     */
    template<typename T>
    T get_function(const std::string& name) const {
        return reinterpret_cast<T>(get_symbol(name));
    }
    
    /**
     * @brief Check if the loader has successfully loaded the payload
     */
    bool is_loaded() const { return loaded_; }
    
    /**
     * @brief Get the last error message
     */
    const std::string& get_error() const { return error_; }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    bool loaded_ = false;
    std::string error_;
};

/**
 * @brief Builder for creating ink packet protected binaries
 * 
 * This class handles the compilation and packaging of source code
 * into self-protecting binaries.
 */
class InkPacketBuilder {
public:
    /**
     * @brief Configuration for building ink packets
     */
    struct Config {
        std::string output_path;           ///< Output binary path
        std::string main_source;           ///< Main application source
        std::vector<std::string> sources;  ///< Additional source files
        std::vector<std::string> critical_sources; ///< Sources to protect
        std::string compiler = "clang++";  ///< Compiler to use
        std::string cxx_flags = "-std=c++20 -O2"; ///< Compiler flags
        std::vector<std::string> link_libs; ///< Libraries to link
        bool strip_symbols = true;         ///< Strip debug symbols
        uint8_t hash_algo = 0;            ///< Hash algorithm (0=BLAKE3)
        uint8_t enc_algo = 0;             ///< Encryption algorithm (0=AES-256-GCM)
    };
    
    explicit InkPacketBuilder(const Config& config);
    ~InkPacketBuilder();
    
    /**
     * @brief Build the ink packet binary
     * @return true if successful
     */
    bool build();
    
    /**
     * @brief Get build log/output
     */
    const std::string& get_log() const { return log_; }
    
    /**
     * @brief Get the last error message
     */
    const std::string& get_error() const { return error_; }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    Config config_;
    std::string log_;
    std::string error_;
};

/**
 * @brief Memory protection utilities
 */
namespace memory {
    /**
     * @brief Lock memory pages to prevent swapping
     * @param addr Memory address
     * @param size Size in bytes
     * @return true if successful
     */
    bool lock_pages(void* addr, size_t size);
    
    /**
     * @brief Unlock previously locked pages
     * @param addr Memory address
     * @param size Size in bytes
     * @return true if successful
     */
    bool unlock_pages(void* addr, size_t size);
    
    /**
     * @brief Mark memory as non-dumpable (won't appear in core dumps)
     * @param addr Memory address
     * @param size Size in bytes
     * @return true if successful
     */
    bool mark_non_dumpable(void* addr, size_t size);
    
    /**
     * @brief Allocate executable memory
     * @param size Size in bytes
     * @return Pointer to allocated memory or nullptr
     */
    void* alloc_executable(size_t size);
    
    /**
     * @brief Free executable memory
     * @param addr Memory address
     * @param size Size in bytes
     */
    void free_executable(void* addr, size_t size);
}

/**
 * @brief Self-verification utilities
 */
namespace verify {
    /**
     * @brief Calculate hash of current binary
     * @param algo Hash algorithm (0=BLAKE3, 1=SHA256)
     * @return Hash as byte vector
     */
    std::vector<uint8_t> hash_self(uint8_t algo = 0);
    
    /**
     * @brief Check if binary has been tampered with
     * @return true if integrity is intact
     */
    bool check_integrity();
    
    /**
     * @brief Perform deep integrity check with anti-debugging
     * @return true if all checks pass
     */
    bool deep_verify();
    
    /**
     * @brief Register a tampering callback
     * @param callback Function to call on tampering detection
     */
    void on_tamper(std::function<void()> callback);
    
    /**
     * @brief Check if debugger is attached
     * @return true if debugger detected
     */
    bool is_debugger_present();
}

/**
 * @brief Post-build patcher for creating hash-salt protected binaries
 */
class InkPacketPatcher {
public:
    struct PatchConfig {
        std::string binary_path;      ///< Path to binary to patch
        std::string payload_path;     ///< Path to payload to embed
        std::string base_key;         ///< Base key for additional entropy
        bool verify_after = true;     ///< Verify after patching
        bool backup_original = true;  ///< Create backup before patching
        uint8_t hash_algo = 0;        ///< Hash algorithm (0=BLAKE3)
        uint8_t enc_algo = 0;         ///< Encryption algorithm (0=AES-GCM)
    };
    
    explicit InkPacketPatcher(const PatchConfig& config);
    ~InkPacketPatcher();
    
    /**
     * @brief Patch the binary with embedded keys and payload
     * @return true if successful
     */
    bool patch();
    
    /**
     * @brief Information about binary structure
     */
    struct BinaryInfo {
        size_t app_size = 0;               ///< Size of application part
        size_t total_size = 0;             ///< Total size after patching
        bool has_existing_payload = false; ///< Already has payload
        size_t size_placeholder_offset = 0; ///< Offset to size placeholder
    };
    BinaryInfo analyze_binary();
    
    /**
     * @brief Get the last error message
     */
    const std::string& get_error() const { return error_; }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    PatchConfig config_;
    std::string error_;
};

}
