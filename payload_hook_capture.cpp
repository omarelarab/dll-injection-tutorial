#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>

// The offset we discovered
#define TARGET_RVA 0x7eaf0

std::ofstream logFile;

// Storage for original bytes (we need to restore them to call original)
uint8_t originalBytes[14]; // Size of our jump patch
uintptr_t targetAddress = 0;
uintptr_t trampolineAddress = 0;

// Function to log messages
void Log(const char* msg) {
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

void LogHex(const char* label, uintptr_t value) {
    if (logFile.is_open()) {
        logFile << label << ": 0x" << std::hex << std::setw(16) << std::setfill('0') << value << std::endl;
        logFile.flush();
    }
}

// This is our hook function that will capture parameters
// In x64 calling convention:
//   RCX = 1st param
//   RDX = 2nd param
//   R8  = 3rd param
//   R9  = 4th param
//   Stack = 5th+ params
//
// We need to use naked assembly to access registers without compiler interference
// But MSVC x64 doesn't support __naked, so we use a different approach:
// We create a trampoline in assembly that saves registers before calling our C++ logger.

// Since we can't use inline x64 assembly in MSVC, we'll use a different technique:
// We'll create a detour that jumps to our function, which is a normal C++ function
// that takes parameters in the same convention.

// For simplicity, we'll assume the function takes (void* this, void* param1)
// and capture those two registers.

typedef void (*OriginalFunc)(void* rcx, void* rdx, void* r8, void* r9);

// Our hook function - MUST match calling convention
void __fastcall HookFunction(void* rcx, void* rdx, void* r8, void* r9) {
    Log("=== FUNCTION CALLED ===");
    LogHex("RCX (this?)", (uintptr_t)rcx);
    LogHex("RDX (param1?)", (uintptr_t)rdx);
    LogHex("R8  (param2?)", (uintptr_t)r8);
    LogHex("R9  (param3?)", (uintptr_t)r9);
    
    // Try to read some data if rcx looks like a valid pointer
    if (rcx && (uintptr_t)rcx > 0x10000) {
        Log("Attempting to read data at RCX...");
        __try {
            uintptr_t* pData = (uintptr_t*)rcx;
            LogHex("  [RCX+0x00]", pData[0]);
            LogHex("  [RCX+0x08]", pData[1]);
            LogHex("  [RCX+0x10]", pData[2]);
            LogHex("  [RCX+0x18]", pData[3]);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("  (Access violation reading RCX data)");
        }
    }
    
    if (rdx && (uintptr_t)rdx > 0x10000) {
        Log("Attempting to read data at RDX...");
        __try {
            uintptr_t* pData = (uintptr_t*)rdx;
            LogHex("  [RDX+0x00]", pData[0]);
            LogHex("  [RDX+0x08]", pData[1]);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("  (Access violation reading RDX data)");
        }
    }
    
    Log("=== END OF CAPTURE ===\n");
    
    // DO NOT call original - just return (this will break functionality but capture params)
    // If you want to call original, we need a proper trampoline
    MessageBox(NULL, TEXT("Parameters captured! Check log file.\nNotepad may become unstable."), TEXT("Hook"), MB_OK);
}

// Function to install the hook using a simple JMP patch
bool InstallHook() {
    uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);
    targetAddress = baseAddress + TARGET_RVA;
    
    LogHex("Base Address", baseAddress);
    LogHex("Target Address", targetAddress);
    
    // Change memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)targetAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("ERROR: VirtualProtect failed");
        return false;
    }
    
    // Save original bytes
    memcpy(originalBytes, (void*)targetAddress, 14);
    Log("Original bytes saved");
    
    // Write a 14-byte absolute JMP to our hook
    // FF 25 00 00 00 00 [8-byte address]
    // This is: JMP QWORD PTR [RIP+0] ; followed by 8-byte target
    uint8_t jmpPatch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // JMP [RIP+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 8-byte address
    };
    
    uintptr_t hookAddr = (uintptr_t)&HookFunction;
    memcpy(&jmpPatch[6], &hookAddr, 8);
    
    // Write the patch
    memcpy((void*)targetAddress, jmpPatch, 14);
    
    // Restore protection
    VirtualProtect((LPVOID)targetAddress, 14, oldProtect, &oldProtect);
    
    Log("Hook installed successfully!");
    LogHex("Hook function at", hookAddr);
    
    return true;
}

void SetupCapture() {
    logFile.open("C:\\Users\\Public\\param_capture_log.txt");
    Log("Parameter Capture Payload Started");
    Log("=====================================");
    
    if (InstallHook()) {
        MessageBox(NULL, 
            TEXT("Hook installed!\n\nNow click File -> Save in Notepad.\nThe parameters will be captured to:\nC:\\Users\\Public\\param_capture_log.txt"),
            TEXT("Ready"), MB_OK);
    } else {
        MessageBox(NULL, TEXT("Failed to install hook!"), TEXT("Error"), MB_OK);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SetupCapture, NULL, 0, NULL);
    }
    return TRUE;
}
