#!/bin/bash
#
# Standalone demonstration of inkpacket binary protection
# This script shows how inkpacket works without requiring compilation
#

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          Inkpacket Binary Protection Demo                      ║"
echo "║          Part of the Psyfer Encryption Library                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

# Create temporary directory for demo
DEMO_DIR=$(mktemp -d -t inkpacket_demo_XXXXXX)
trap "rm -rf $DEMO_DIR" EXIT

echo "📁 Creating demo in: $DEMO_DIR"
cd "$DEMO_DIR"

# Create a simple application
echo "📝 Creating sample application..."
cat > main.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This would normally be in the encrypted section
void secret_algorithm(const char* input) {
    printf("[PROTECTED] Processing: %s\n", input);
    printf("[PROTECTED] Result: ");
    for (int i = 0; input[i]; i++) {
        printf("%02x ", (unsigned char)(input[i] ^ 0x42));
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("=== Demo Application ===\n");
    
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    // In a protected binary, this would decrypt and load the protected code
    printf("Decrypting protected section...\n");
    secret_algorithm(argv[1]);
    
    return 0;
}
EOF

# Compile the application
echo "🔨 Compiling application..."
cc -o demo_app main.c

# Show the binary
echo
echo "📊 Original binary:"
ls -la demo_app
ORIGINAL_SIZE=$(stat -f%z demo_app 2>/dev/null || stat -c%s demo_app)
echo "   Size: $ORIGINAL_SIZE bytes"

# Calculate hash of original
echo "   SHA256: $(shasum -a 256 demo_app | cut -d' ' -f1)"

# Create simulated encrypted payload
echo
echo "🔐 Creating encrypted payload..."
cat > payload.bin << 'EOF'
ENCRYPTED_CRITICAL_CODE_SECTION_DEADBEEFCAFEBABE
EOF

# Create metadata structure (64 bytes)
echo "📋 Creating metadata..."
printf '\x03\x00\x00\x00' > metadata.bin  # version = 3
printf '\x30\x00\x00\x00' >> metadata.bin # payload_size = 48
printf '\x00' >> metadata.bin             # hash_algo = SHA256
printf '\x00' >> metadata.bin             # enc_algo = AES-256-GCM
printf '\x00\x00' >> metadata.bin         # flags
printf '\xEF\xBE\xAD\xDE' >> metadata.bin # checksum
# Pad to 64 bytes
dd if=/dev/zero bs=1 count=48 >> metadata.bin 2>/dev/null

# Create protected binary
echo "🛡️  Creating protected binary..."
cp demo_app demo_protected
cat metadata.bin >> demo_protected
cat payload.bin >> demo_protected

# Patch the size into the binary (simulate)
echo "   Patching embedded size: $ORIGINAL_SIZE"

# Show protected binary
echo
echo "📊 Protected binary:"
ls -la demo_protected
PROTECTED_SIZE=$(stat -f%z demo_protected 2>/dev/null || stat -c%s demo_protected)
echo "   Size: $PROTECTED_SIZE bytes (original + metadata + encrypted payload)"
echo "   SHA256: $(shasum -a 256 demo_protected | cut -d' ' -f1)"

# Demo execution
echo
echo "▶️  Running protected binary:"
./demo_protected "Hello World" || true

# Simulate tampering
echo
echo "🔧 Simulating tampering..."
echo "   Modifying one byte at offset 1000..."
# Create tampered copy
cp demo_protected demo_tampered
# Modify a byte
printf '\xFF' | dd of=demo_tampered bs=1 seek=1000 count=1 conv=notrunc 2>/dev/null

echo "   Original hash: $(shasum -a 256 demo_protected | cut -d' ' -f1 | cut -c1-16)..."
echo "   Tampered hash: $(shasum -a 256 demo_tampered | cut -d' ' -f1 | cut -c1-16)..."

echo
echo "▶️  Running tampered binary (should fail in real implementation):"
./demo_tampered "Hello World" 2>&1 || echo "   ❌ Would fail with: Decryption error - integrity check failed"

# Explain the protection
echo
echo "═══════════════════════════════════════════════════════════════"
echo "🔍 How Inkpacket Protection Works:"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "1️⃣  Build Time:"
echo "   • Compile application and critical code separately"
echo "   • Calculate SHA-256 hash of application binary"
echo "   • Derive key from hash using HKDF-SHA256"
echo "   • Encrypt critical code with AES-256-GCM"
echo "   • Append metadata + encrypted payload to binary"
echo "   • Patch original size into binary at known offset"
echo
echo "2️⃣  Runtime Protection:"
echo "   • Application reads embedded size ($ORIGINAL_SIZE bytes)"
echo "   • Hashes first $ORIGINAL_SIZE bytes of itself"
echo "   • Derives decryption key from hash"
echo "   • Decrypts payload using derived key"
echo "   • Loads decrypted code into protected memory"
echo
echo "3️⃣  Tamper Detection:"
echo "   • Any modification changes the binary hash"
echo "   • Wrong hash → wrong key → decryption fails"
echo "   • GCM authentication tag prevents forgery"
echo "   • Application terminates on integrity failure"
echo
echo "4️⃣  Security Features:"
echo "   ✓ Self-verifying binary"
echo "   ✓ Anti-debugging protection"
echo "   ✓ Memory protection (mlock, non-swappable)"
echo "   ✓ Continuous runtime verification"
echo "   ✓ Platform-specific hardening"
echo
echo "═══════════════════════════════════════════════════════════════"
echo "💡 Key Insight: The binary becomes its own 'password'"
echo "═══════════════════════════════════════════════════════════════"