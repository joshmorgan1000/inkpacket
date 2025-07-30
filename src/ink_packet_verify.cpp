/**
 * @file ink_packet_verify.cpp
 * @brief Self-verification and anti-tampering utilities
 */

#include "../include/ink_packet.hpp"
#include <psyfer.hpp>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>

#if defined(_WIN32)
    #include <windows.h>
    #include <tlhelp32.h>
#elif defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <unistd.h>
    #include <mach-o/dyld.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/ptrace.h>
#endif

namespace ink {
namespace verify {

namespace {
    std::atomic<bool> g_tamper_detected{false};
    std::function<void()> g_tamper_callback;
    std::mutex g_callback_mutex;
}

/**
 * @brief Get path to current executable
 */
static std::string get_self_path() {
#if defined(_WIN32)
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, sizeof(path));
    return path;
#elif defined(__APPLE__)
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        return std::filesystem::canonical(path).string();
    }
    return "";
#else
    return std::filesystem::canonical("/proc/self/exe").string();
#endif
}

std::vector<uint8_t> hash_self(uint8_t algo) {
    try {
        std::string self_path = get_self_path();
        if (self_path.empty()) {
            return {};
        }
        
        // Read embedded size
        uint64_t app_size = InkPacketEmbeddedSize::app_size;
        if (app_size == 0xDEADC0DEDEADC0DE) {
            // Not properly patched, hash entire file
            std::ifstream file(self_path, std::ios::binary);
            if (!file) return {};
            
            file.seekg(0, std::ios::end);
            app_size = file.tellg();
            file.seekg(0);
        }
        
        // Read exact amount
        std::ifstream file(self_path, std::ios::binary);
        if (!file) return {};
        
        std::vector<uint8_t> data(app_size);
        file.read(reinterpret_cast<char*>(data.data()), app_size);
        if (!file) return {};
        
        // Calculate hash
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
        
    } catch (...) {
        // Silent failure
    }
    
    return {};
}

bool check_integrity() {
    try {
        // Simple check - just verify we can load
        InkPacketLoader loader;
        return loader.verify();
        
    } catch (...) {
        return false;
    }
}

bool deep_verify() {
    // Check debugger first
    if (is_debugger_present()) {
        g_tamper_detected = true;
        return false;
    }
    
    // Multiple hash verification with timing checks
    auto start = std::chrono::high_resolution_clock::now();
    
    // First hash
    auto hash1 = hash_self(0);
    if (hash1.empty()) {
        g_tamper_detected = true;
        return false;
    }
    
    // Add small delay to throw off timing attacks
    std::this_thread::sleep_for(std::chrono::milliseconds(10 + (rand() % 20)));
    
    // Second hash - should match
    auto hash2 = hash_self(0);
    if (hash2.empty() || hash1 != hash2) {
        g_tamper_detected = true;
        return false;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // If verification was too fast, might be hooked
    if (duration.count() < 5) {
        g_tamper_detected = true;
        return false;
    }
    
    // Full integrity check
    if (!check_integrity()) {
        g_tamper_detected = true;
        return false;
    }
    
    return true;
}

void on_tamper(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(g_callback_mutex);
    g_tamper_callback = callback;
    
    // Start background verification thread if not already running
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        std::thread([]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(30 + (rand() % 30)));
                
                if (!deep_verify()) {
                    std::lock_guard<std::mutex> lock(g_callback_mutex);
                    if (g_tamper_callback) {
                        g_tamper_callback();
                    }
                    break;
                }
            }
        }).detach();
    });
}

bool is_debugger_present() {
#if defined(_WIN32)
    // Windows debugger detection
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // Check for remote debugger
    BOOL remote_dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_dbg);
    if (remote_dbg) {
        return true;
    }
    
    // Check PEB
    bool being_debugged = false;
    __asm {
        mov eax, fs:[30h]
        mov al, byte ptr [eax + 2]
        mov being_debugged, al
    }
    
    return being_debugged;
    
#elif defined(__APPLE__)
    // macOS debugger detection
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    info.kp_proc.p_flag = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    if (sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, nullptr, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    
    return false;
    
#else
    // Linux debugger detection
    static bool checked = false;
    static bool debugger_present = false;
    
    if (!checked) {
        // Try ptrace
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            debugger_present = true;
        } else {
            // We were able to trace ourselves, so no debugger
            ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
        }
        
        // Also check /proc/self/status
        std::ifstream status("/proc/self/status");
        if (status) {
            std::string line;
            while (std::getline(status, line)) {
                if (line.find("TracerPid:") == 0) {
                    int tracer_pid = std::stoi(line.substr(10));
                    if (tracer_pid != 0) {
                        debugger_present = true;
                    }
                    break;
                }
            }
        }
        
        checked = true;
    }
    
    return debugger_present;
#endif
}

} // namespace verify
} // namespace ink