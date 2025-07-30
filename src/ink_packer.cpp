/**
 * @file ink_packer.cpp
 * @brief Command-line tool for creating ink packet protected binaries
 */

#include "../include/ink_packet.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options] -o output main.cpp\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -o <output>      Output binary path\n";
    std::cout << "  -c <source>      Mark source file as critical (protect in encrypted library)\n";
    std::cout << "  -s <source>      Add additional source file\n";
    std::cout << "  -l <library>     Link with library\n";
    std::cout << "  --compiler <cc>  Compiler to use (default: clang++)\n";
    std::cout << "  --cxxflags <f>   Compiler flags (default: -std=c++20 -O2)\n";
    std::cout << "  --no-strip       Don't strip debug symbols\n";
    std::cout << "  --hash <algo>    Hash algorithm: sha256, sha512 (default: sha256)\n";
    std::cout << "  --enc <algo>     Encryption: aes-gcm, chacha20 (default: aes-gcm)\n";
    std::cout << "  -h, --help       Show this help\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program << " -o protected_app -c crypto.cpp -s utils.cpp main.cpp\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    ink::InkPacketBuilder::Config config;
    std::string main_source;
    
    // Parse command line
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-o" && i + 1 < argc) {
            config.output_path = argv[++i];
        }
        else if (arg == "-c" && i + 1 < argc) {
            config.critical_sources.push_back(argv[++i]);
        }
        else if (arg == "-s" && i + 1 < argc) {
            config.sources.push_back(argv[++i]);
        }
        else if (arg == "-l" && i + 1 < argc) {
            config.link_libs.push_back(argv[++i]);
        }
        else if (arg == "--compiler" && i + 1 < argc) {
            config.compiler = argv[++i];
        }
        else if (arg == "--cxxflags" && i + 1 < argc) {
            config.cxx_flags = argv[++i];
        }
        else if (arg == "--no-strip") {
            config.strip_symbols = false;
        }
        else if (arg == "--hash" && i + 1 < argc) {
            std::string hash = argv[++i];
            if (hash == "sha256") config.hash_algo = 0;
            else if (hash == "sha512") config.hash_algo = 1;
            else {
                std::cerr << "Unknown hash algorithm: " << hash << "\n";
                return 1;
            }
        }
        else if (arg == "--enc" && i + 1 < argc) {
            std::string enc = argv[++i];
            if (enc == "aes-gcm") config.enc_algo = 0;
            else if (enc == "chacha20") config.enc_algo = 1;
            else {
                std::cerr << "Unknown encryption algorithm: " << enc << "\n";
                return 1;
            }
        }
        else if (arg[0] != '-') {
            main_source = arg;
        }
    }
    
    // Validate inputs
    if (config.output_path.empty()) {
        std::cerr << "Error: No output path specified\n";
        return 1;
    }
    
    if (main_source.empty()) {
        std::cerr << "Error: No main source file specified\n";
        return 1;
    }
    
    config.main_source = main_source;
    config.sources.push_back(main_source);
    
    // Build ink packet
    std::cout << "Building ink packet...\n";
    std::cout << "Main source: " << main_source << "\n";
    std::cout << "Critical sources: ";
    for (const auto& src : config.critical_sources) {
        std::cout << src << " ";
    }
    std::cout << "\n";
    
    ink::InkPacketBuilder builder(config);
    
    if (!builder.build()) {
        std::cerr << "Build failed: " << builder.get_error() << "\n";
        std::cerr << "\nBuild log:\n" << builder.get_log() << "\n";
        return 1;
    }
    
    std::cout << "\nBuild log:\n" << builder.get_log() << "\n";
    std::cout << "Successfully created: " << config.output_path << "\n";
    
    return 0;
}