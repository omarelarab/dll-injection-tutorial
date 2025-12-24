#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

// Helper to enable debug privileges
bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return false; }
    CloseHandle(hToken);
    return true;
}

// Get PID by name
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

// Get Module Base Address
uintptr_t GetModuleBaseAddress(DWORD pid, const std::wstring& moduleName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(moduleName.c_str(), me32.szModule) == 0) {
                    modBaseAddr = (uintptr_t)me32.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    return modBaseAddr;
}

// Convert "48 8B ? ?" string to byte vector (with -1 for wildcards)
std::vector<int> PatternToBytes(const char* pattern) {
    std::vector<int> bytes;
    std::stringstream ss(pattern);
    std::string byteStr;

    while (ss >> byteStr) {
        if (byteStr == "?" || byteStr == "??")
            bytes.push_back(-1); // Wildcard
        else
            bytes.push_back(std::stoi(byteStr, nullptr, 16));
    }
    return bytes;
}

// Scan a buffer for the pattern
uintptr_t ScanBuffer(const std::vector<uint8_t>& buffer, const std::vector<int>& pattern) {
    size_t scanSize = buffer.size() - pattern.size();
    for (size_t i = 0; i < scanSize; ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != -1 && buffer[i + j] != (uint8_t)pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0; // Not found
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: scanner.exe \"<PATTERN>\" [process_name]" << std::endl;
        std::cout << "Example: scanner.exe \"48 8B 05 ? ? ? ?\" notepad.exe" << std::endl;
        return 1;
    }

    const char* patternStr = argv[1];
    std::wstring targetProcess = (argc > 2) ? std::wstring(argv[2], argv[2] + strlen(argv[2])) : L"notepad.exe";

    EnableDebugPrivilege();

    DWORD pid = GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::cerr << "Process not found." << std::endl;
        return 1;
    }

    uintptr_t baseAddr = GetModuleBaseAddress(pid, targetProcess);
    if (baseAddr == 0) {
        std::cerr << "Could not get base address." << std::endl;
        return 1;
    }

    std::cout << "Target PID: " << pid << std::endl;
    std::cout << "Base Address: 0x" << std::hex << baseAddr << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    std::vector<int> pattern = PatternToBytes(patternStr);
    
    // Naive approach: Dump entire main module memory and scan
    // For large apps, scanning chunk by chunk is better, but this is simple for demo.
    // We'll read the first 10MB of the module (usually enough for code sections)
    const size_t SCAN_SIZE = 10 * 1024 * 1024; 
    std::vector<uint8_t> buffer(SCAN_SIZE);
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hProcess, (LPCVOID)baseAddr, buffer.data(), SCAN_SIZE, &bytesRead)) {
        std::cout << "Read " << bytesRead << " bytes. Scanning..." << std::endl;
        
        uintptr_t offset = ScanBuffer(buffer, pattern);
        if (offset != 0) {
            std::cout << "------------------------------------------------" << std::endl;
            std::cout << "PATTERN FOUND!" << std::endl;
            std::cout << "Offset: +0x" << std::hex << offset << std::endl;
            std::cout << "Address: 0x" << std::hex << (baseAddr + offset) << std::endl;
            std::cout << "------------------------------------------------" << std::endl;
        } else {
            std::cout << "Pattern not found in the first 10MB." << std::endl;
        }
    } else {
        std::cerr << "Failed to read memory. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
