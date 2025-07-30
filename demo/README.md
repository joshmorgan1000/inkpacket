# Inkpacket Demo

This directory contains a standalone demonstration of the inkpacket binary protection system.

## Quick Start

```bash
# Run the standalone demo
bash standalone_demo.sh
```

## What the Demo Shows

The `standalone_demo.sh` script demonstrates:

1. **Binary Structure** - How protected binaries are constructed
2. **Protection Process** - Step-by-step encryption and patching
3. **Runtime Behavior** - How the binary self-decrypts
4. **Tamper Detection** - What happens when the binary is modified

## How It Works

The demo creates a temporary directory and:
- Builds a simple C application
- Simulates the protection process
- Shows how tampering breaks decryption
- Explains the security mechanisms

No compilation of inkpacket itself is required - this is a conceptual demonstration using standard Unix tools.

## Real Implementation

In the actual inkpacket system:
- Uses Psyfer's encryption (AES-256-GCM, ChaCha20-Poly1305)
- Implements platform-specific memory protection
- Includes anti-debugging and runtime verification
- Provides command-line tools (ink-pack, ink-patch)

## Security Features Demonstrated

- **Self-verification**: Binary checks its own integrity
- **Hash-as-key**: Binary content becomes the decryption password
- **Tamper-proof**: Any modification breaks functionality
- **Zero external dependencies**: No network or key storage needed