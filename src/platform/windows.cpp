/**
 * @file windows.cpp
 * @brief Windows-specific implementations for ink packet
 */

#include "../../include/ink_packet.hpp"
#include <windows.h>
#include <psapi.h>
#include <winternl.h>

namespace ink {
namespace platform {

/**
 * @brief Get base address of current process
 */
uintptr_t get_base_address() {
    return reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
}

/**
 * @brief Check various Windows debuggers
 */
bool is_debugger_present_extended() {
    // Check for kernel debugger
    SYSTEM_KERNEL_DEBUGGER_INFORMATION kdi;
    NTSTATUS status = NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        &kdi,
        sizeof(kdi),
        nullptr
    );
    
    if (NT_SUCCESS(status) && kdi.KernelDebuggerEnabled) {
        return true;
    }
    
    // Check for debug flags in PEB
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (peb->BeingDebugged) {
        return true;
    }
    
    // Check NtGlobalFlag
    if (peb->NtGlobalFlag & 0x70) {
        return true;
    }
    
    // Check for debug object handle
    HANDLE debug_object = nullptr;
    status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &debug_object,
        sizeof(debug_object),
        nullptr
    );
    
    if (NT_SUCCESS(status) && debug_object != nullptr) {
        return true;
    }
    
    return false;
}

/**
 * @brief Hide from debugger process list
 */
void hide_from_debugger() {
    // Could implement various anti-debugging techniques here
    // For now, just a placeholder
}

/**
 * @brief Check for common analysis tools
 */
bool is_analysis_tool_present() {
    const wchar_t* tools[] = {
        L"ollydbg.exe",
        L"x64dbg.exe",
        L"windbg.exe",
        L"idaq.exe",
        L"idaq64.exe",
        L"apimonitor.exe",
        L"processhacker.exe",
        L"procmon.exe",
        L"wireshark.exe"
    };
    
    DWORD processes[1024], needed;
    if (!EnumProcesses(processes, sizeof(processes), &needed)) {
        return false;
    }
    
    DWORD count = needed / sizeof(DWORD);
    for (DWORD i = 0; i < count; ++i) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                     FALSE, processes[i]);
        if (process) {
            wchar_t name[MAX_PATH];
            if (GetModuleBaseNameW(process, nullptr, name, MAX_PATH)) {
                for (const auto* tool : tools) {
                    if (_wcsicmp(name, tool) == 0) {
                        CloseHandle(process);
                        return true;
                    }
                }
            }
            CloseHandle(process);
        }
    }
    
    return false;
}

} // namespace platform
} // namespace ink