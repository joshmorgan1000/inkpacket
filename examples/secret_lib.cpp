/**
 * @file secret_lib.cpp
 * @brief Secret library that contains protected functionality
 * 
 * This library will be encrypted and embedded in the main application.
 * The message only exists here, not in the main application.
 */

#include <iostream>
#include <string>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

/**
 * @brief Display the secret message that only exists in this library
 */
EXPORT void display_secret_message() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════╗\n";
    std::cout << "║     🔓 SECRET MESSAGE SUCCESSFULLY LOADED! 🔓   ║\n";
    std::cout << "║                                                ║\n";
    std::cout << "║  This message ONLY exists in the encrypted     ║\n";
    std::cout << "║  library. If you're seeing this, it means:    ║\n";
    std::cout << "║                                                ║\n";
    std::cout << "║  ✅ The binary calculated its own hash        ║\n";
    std::cout << "║  ✅ Used the hash to derive the decrypt key   ║\n";
    std::cout << "║  ✅ Successfully decrypted the library        ║\n";
    std::cout << "║  ✅ Loaded it into memory                     ║\n";
    std::cout << "║  ✅ And called this function!                 ║\n";
    std::cout << "║                                                ║\n";
    std::cout << "║  The InkPacket protection is working! 🎉      ║\n";
    std::cout << "╚════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

/**
 * @brief Perform a secret calculation
 */
EXPORT int secret_calculation(int a, int b) {
    // This algorithm only exists in the encrypted library
    return (a * 42) + (b * 7) - 13;
}

/**
 * @brief Get library version
 */
EXPORT const char* get_secret_version() {
    return "InkPacket Protected Library v1.0";
}

}