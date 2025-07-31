#!/bin/bash
# Build script for the InkPacket demo

set -e

echo "=== Building InkPacket Demo ==="
echo

# 1. Build the secret library
echo "📚 Step 1: Building secret library..."
c++ -shared -fPIC -o secret_lib.so secret_lib.cpp
echo "   ✅ Built secret_lib.so"
echo

# 2. Build the main application
echo "🔨 Step 2: Building main application..."
c++ -o protected_app protected_app.cpp -I../include -L.. -linkpacket -ldl -std=c++20
echo "   ✅ Built protected_app"
echo

# 3. Show the current state
echo "📊 Step 3: Current state:"
echo "   - protected_app: $(stat -f%z protected_app 2>/dev/null || stat -c%s protected_app) bytes"
echo "   - secret_lib.so: $(stat -f%z secret_lib.so 2>/dev/null || stat -c%s secret_lib.so) bytes"
echo

# 4. Run unprotected (should fail)
echo "🧪 Step 4: Running unprotected app (should fail):"
./protected_app || true
echo

# 5. Protect the binary
echo "🔐 Step 5: Protecting the binary..."
./example_patcher protected_app secret_lib.so
echo

# 6. Show new size
echo "📊 Step 6: Protected binary:"
echo "   - protected_app: $(stat -f%z protected_app 2>/dev/null || stat -c%s protected_app) bytes"
echo

# 7. Run protected (should work!)
echo "🎯 Step 7: Running protected app (should work!):"
./protected_app
echo

# 8. Demonstrate tampering
echo "💥 Step 8: Demonstrating tamper detection:"
echo "   Creating tampered version..."
cp protected_app protected_app_tampered
# Change one byte
echo -n "X" | dd of=protected_app_tampered bs=1 seek=1000 count=1 conv=notrunc 2>/dev/null
echo "   Running tampered version (should fail):"
./protected_app_tampered || echo "   ✅ Tamper detection works!"
echo

echo "🎉 Demo complete!"