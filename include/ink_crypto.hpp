#pragma once

/**
 * @file ink_crypto.hpp
 * @brief Cryptographic utilities for InkPacket using psyfer library
 */

#include <psyfer.hpp>
#include <vector>
#include <string>
#include <span>
#include <array>
#include <memory>
#include <cstdint>

namespace ink {
namespace crypto {

/**
 * @brief Hash algorithms supported
 */
enum class HashAlgorithm : uint8_t {
    BLAKE3 = 0,
    SHA256 = 1
};

/**
 * @brief Encryption algorithms supported
 */
enum class EncryptionAlgorithm : uint8_t {
    AES_256_GCM = 0,
    CHACHA20_POLY1305 = 1
};

/**
 * @brief Result of encryption operation
 */
struct EncryptResult {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 12> nonce;
    std::array<uint8_t, 16> tag;
};

/**
 * @brief Calculate hash of data
 * @param data Data to hash
 * @param algo Hash algorithm to use
 * @return Hash value
 */
inline std::vector<uint8_t> hash(std::span<const uint8_t> data, HashAlgorithm algo = HashAlgorithm::BLAKE3) {
    switch (algo) {
        case HashAlgorithm::BLAKE3: {
            // BLAKE3 not yet in psyfer, use SHA256 for now
            std::array<std::byte, 32> hash;
            psyfer::sha256_hasher::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        }
        case HashAlgorithm::SHA256: {
            std::array<std::byte, 32> hash;
            psyfer::sha256_hasher::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                hash
            );
            return std::vector<uint8_t>(
                reinterpret_cast<const uint8_t*>(hash.data()),
                reinterpret_cast<const uint8_t*>(hash.data() + hash.size())
            );
        }
        default:
            throw std::runtime_error("Unsupported hash algorithm");
    }
}

/**
 * @brief Derive key from password using PBKDF2
 * @param password Password
 * @param salt Salt for key derivation
 * @param key_size Desired key size in bytes
 * @param iterations Number of iterations
 * @return Derived key
 */
inline std::vector<uint8_t> derive_key(
    const std::string& password,
    std::span<const uint8_t> salt,
    size_t key_size = 32,
    size_t iterations = 100000
) {
    // Use HKDF with SHA256
    auto password_bytes = std::vector<uint8_t>(password.begin(), password.end());
    auto ikm = psyfer::sha256(password_bytes);
    
    // Repeat hashing for iterations (simple PBKDF2-like behavior)
    std::vector<uint8_t> key = ikm;
    for (size_t i = 1; i < iterations; ++i) {
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), key.begin(), key.end());
        combined.insert(combined.end(), salt.begin(), salt.end());
        key = psyfer::sha256(combined);
    }
    
    // Use HKDF to expand to desired key size
    return psyfer::hkdf_sha256(key, salt, {}, key_size);
}

/**
 * @brief Encrypt data using specified algorithm
 * @param plaintext Data to encrypt
 * @param key Encryption key
 * @param algo Encryption algorithm
 * @param aad Additional authenticated data (optional)
 * @return Encryption result with ciphertext, nonce, and tag
 */
inline EncryptResult encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    EncryptionAlgorithm algo = EncryptionAlgorithm::AES_256_GCM,
    std::span<const uint8_t> aad = {}
) {
    if (key.size() != 32) {
        throw std::runtime_error("Key must be 32 bytes");
    }

    EncryptResult result;
    
    // Generate random nonce
    result.nonce = psyfer::random_bytes<12>();
    
    switch (algo) {
        case EncryptionAlgorithm::AES_256_GCM: {
            auto [ciphertext, tag] = psyfer::aes256_gcm_encrypt(
                plaintext, 
                std::array<uint8_t, 32>{key.begin(), key.end()},
                result.nonce,
                aad
            );
            result.ciphertext = std::move(ciphertext);
            result.tag = tag;
            break;
        }
        case EncryptionAlgorithm::CHACHA20_POLY1305: {
            auto [ciphertext, tag] = psyfer::chacha20_poly1305_encrypt(
                plaintext,
                std::array<uint8_t, 32>{key.begin(), key.end()},
                result.nonce,
                aad
            );
            result.ciphertext = std::move(ciphertext);
            result.tag = tag;
            break;
        }
        default:
            throw std::runtime_error("Unsupported encryption algorithm");
    }
    
    return result;
}

/**
 * @brief Decrypt data using specified algorithm
 * @param ciphertext Encrypted data
 * @param key Decryption key
 * @param nonce Nonce used for encryption
 * @param tag Authentication tag
 * @param algo Encryption algorithm
 * @param aad Additional authenticated data (optional)
 * @return Decrypted plaintext
 */
inline std::vector<uint8_t> decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> tag,
    EncryptionAlgorithm algo = EncryptionAlgorithm::AES_256_GCM,
    std::span<const uint8_t> aad = {}
) {
    if (key.size() != 32) {
        throw std::runtime_error("Key must be 32 bytes");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("Nonce must be 12 bytes");
    }
    if (tag.size() != 16) {
        throw std::runtime_error("Tag must be 16 bytes");
    }

    switch (algo) {
        case EncryptionAlgorithm::AES_256_GCM: {
            return psyfer::aes256_gcm_decrypt(
                ciphertext,
                std::array<uint8_t, 32>{key.begin(), key.end()},
                std::array<uint8_t, 12>{nonce.begin(), nonce.end()},
                std::array<uint8_t, 16>{tag.begin(), tag.end()},
                aad
            );
        }
        case EncryptionAlgorithm::CHACHA20_POLY1305: {
            return psyfer::chacha20_poly1305_decrypt(
                ciphertext,
                std::array<uint8_t, 32>{key.begin(), key.end()},
                std::array<uint8_t, 12>{nonce.begin(), nonce.end()},
                std::array<uint8_t, 16>{tag.begin(), tag.end()},
                aad
            );
        }
        default:
            throw std::runtime_error("Unsupported encryption algorithm");
    }
}

/**
 * @brief Generate cryptographically secure random bytes
 * @param size Number of bytes to generate
 * @return Random bytes
 */
inline std::vector<uint8_t> random_bytes(size_t size) {
    std::vector<uint8_t> result(size);
    psyfer::secure_random_bytes(result);
    return result;
}

/**
 * @brief Securely clear memory
 * @param data Memory to clear
 */
inline void secure_clear(std::span<uint8_t> data) {
    psyfer::secure_zero_memory(data.data(), data.size());
}

/**
 * @brief RAII wrapper for secure memory
 */
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : data_(size) {}
    
    ~SecureBuffer() {
        secure_clear(data_);
    }
    
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    SecureBuffer(SecureBuffer&& other) noexcept = default;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept = default;
    
    std::span<uint8_t> data() { return data_; }
    std::span<const uint8_t> data() const { return data_; }
    size_t size() const { return data_.size(); }
    
private:
    std::vector<uint8_t> data_;
};

} // namespace crypto
} // namespace ink