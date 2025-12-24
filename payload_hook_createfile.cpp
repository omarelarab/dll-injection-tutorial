#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>

std::ofstream logFile;

// Original function pointer
typedef HANDLE (WINAPI *CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

CreateFileW_t OriginalCreateFileW = nullptr;

// Storage for hook
uint8_t originalBytes[14];
uintptr_t createFileWAddr = 0;

void Log(const char* msg) {
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

void LogW(const wchar_t* msg) {
    if (logFile.is_open()) {
        // Convert to narrow string for logging
        char buffer[512];
        WideCharToMultiByte(CP_UTF8, 0, msg, -1, buffer, 512, NULL, NULL);
        logFile << buffer << std::endl;
        logFile.flush();
    }
}

// Our hook function
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    Log("=== CreateFileW CALLED ===");
    
    if (lpFileName) {
        Log("Filename:");
        LogW(lpFileName);
    }
    
    logFile << "DesiredAccess: 0x" << std::hex << dwDesiredAccess << std::endl;
    logFile << "ShareMode: 0x" << std::hex << dwShareMode << std::endl;
    logFile << "CreationDisposition: " << std::dec << dwCreationDisposition << std::endl;
    
    // Check if this is a WRITE operation (Save)
    if (dwDesiredAccess & GENERIC_WRITE) {
        Log(">>> THIS IS A WRITE OPERATION (SAVE) <<<");
        MessageBoxW(NULL, lpFileName, L"CreateFileW - WRITE detected!", MB_OK);
    }
    
    Log("=== END ===\n");
    
    // Unhook temporarily to call original
    DWORD oldProtect;
    VirtualProtect((LPVOID)createFileWAddr, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)createFileWAddr, originalBytes, 14);
    VirtualProtect((LPVOID)createFileWAddr, 14, oldProtect, &oldProtect);
    
    // Call original
    HANDLE result = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, 
                                 lpSecurityAttributes, dwCreationDisposition, 
                                 dwFlagsAndAttributes, hTemplateFile);
    
    // Re-hook
    uint8_t jmpPatch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uintptr_t hookAddr = (uintptr_t)&HookedCreateFileW;
    memcpy(&jmpPatch[6], &hookAddr, 8);
    
    VirtualProtect((LPVOID)createFileWAddr, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)createFileWAddr, jmpPatch, 14);
    VirtualProtect((LPVOID)createFileWAddr, 14, oldProtect, &oldProtect);
    
    return result;
}

bool InstallHook() {
    // Get address of CreateFileW from kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        hKernel32 = GetModuleHandleW(L"kernelbase.dll"); // Modern Windows
    }
    
    if (!hKernel32) {
        Log("ERROR: Could not find kernel32/kernelbase");
        return false;
    }
    
    createFileWAddr = (uintptr_t)GetProcAddress(hKernel32, "CreateFileW");
    if (!createFileWAddr) {
        Log("ERROR: Could not find CreateFileW");
        return false;
    }
    
    logFile << "CreateFileW at: 0x" << std::hex << createFileWAddr << std::endl;
    
    // Save original bytes
    DWORD oldProtect;
    VirtualProtect((LPVOID)createFileWAddr, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(originalBytes, (void*)createFileWAddr, 14);
    
    // Write jump patch
    uint8_t jmpPatch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uintptr_t hookAddr = (uintptr_t)&HookedCreateFileW;
    memcpy(&jmpPatch[6], &hookAddr, 8);
    
    memcpy((void*)createFileWAddr, jmpPatch, 14);
    VirtualProtect((LPVOID)createFileWAddr, 14, oldProtect, &oldProtect);
    
    Log("Hook installed on CreateFileW!");
    return true;
}

void SetupHook() {
    logFile.open("C:\\Users\\Public\\createfilew_hook_log.txt");
    Log("CreateFileW Hook Payload Started");
    Log("================================");
    
    if (InstallHook()) {
        MessageBox(NULL, 
            TEXT("CreateFileW hook installed!\n\nNow type something in Notepad and click Save.\nThe file path will be captured."),
            TEXT("Ready"), MB_OK);
    } else {
        MessageBox(NULL, TEXT("Failed to install hook!"), TEXT("Error"), MB_OK);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SetupHook, NULL, 0, NULL);
    }
    return TRUE;
}
