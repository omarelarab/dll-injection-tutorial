#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

std::ofstream logFile;

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

// Get Module Base Address AND Size
bool GetModuleInfo(DWORD pid, const std::wstring& moduleName, uintptr_t& baseAddr, size_t& moduleSize) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(moduleName.c_str(), me32.szModule) == 0) {
                    baseAddr = (uintptr_t)me32.modBaseAddr;
                    moduleSize = me32.modBaseSize;
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    return false;
}

// Search buffer for ASCII string (case-insensitive)
uintptr_t FindAsciiString(const std::vector<uint8_t>& buffer, const char* target) {
    size_t len = strlen(target);
    for (size_t i = 0; i < buffer.size() - len; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; ++j) {
            if (tolower(buffer[i + j]) != tolower(target[j])) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return (uintptr_t)-1; // Not found
}

// Search buffer for Wide string
uintptr_t FindWideString(const std::vector<uint8_t>& buffer, const wchar_t* target) {
    size_t lenBytes = wcslen(target) * sizeof(wchar_t);
    const uint8_t* pTarget = (const uint8_t*)target;
    for (size_t i = 0; i < buffer.size() - lenBytes; ++i) {
        bool match = true;
        for (size_t j = 0; j < lenBytes; ++j) {
            if (buffer[i + j] != pTarget[j]) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return (uintptr_t)-1;
}

int main() {
    logFile.open("analyzer_results.txt");
    EnableDebugPrivilege();

    std::wstring targetProcess = L"notepad.exe";
    std::cout << "Analyzer v2: Searching for " << std::string(targetProcess.begin(), targetProcess.end()) << "..." << std::endl;
    logFile << "Analyzer v2 Started" << std::endl;

    DWORD pid = GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::cerr << "Process not found. Make sure Notepad is running." << std::endl;
        logFile << "ERROR: Process not found." << std::endl;
        return 1;
    }

    uintptr_t baseAddr = 0;
    size_t moduleSize = 0;
    if (!GetModuleInfo(pid, targetProcess, baseAddr, moduleSize)) {
        std::cerr << "Could not get module info." << std::endl;
        return 1;
    }

    std::cout << "PID: " << pid << ", Base: 0x" << std::hex << baseAddr << ", Size: 0x" << moduleSize << std::endl;
    logFile << "Base: 0x" << std::hex << baseAddr << ", Size: 0x" << moduleSize << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Read the ENTIRE module into a buffer
    std::vector<uint8_t> moduleBuffer(moduleSize);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddr, moduleBuffer.data(), moduleSize, &bytesRead)) {
        std::cerr << "Failed to read module memory. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "Read " << std::dec << bytesRead << " bytes of module." << std::endl;

    // Candidate strings to search for (static strings likely in .rdata)
    const wchar_t* candidates[] = {
        L"Save",     // Menu item - PRIORITY
        L"SaveFile", // Possible internal name
        L"WriteFile", // API-like name
        L"Untitled", // Default title
        L"Open",     // Menu item
        L"File",     // Menu header
        L"notepad",  // App name
        L".txt"      // Just in case it's static here
    };

    uintptr_t foundStringOffset = (uintptr_t)-1;
    const wchar_t* foundString = nullptr;

    for (int c = 0; c < sizeof(candidates) / sizeof(candidates[0]); ++c) {
        uintptr_t offset = FindWideString(moduleBuffer, candidates[c]);
        if (offset != (uintptr_t)-1) {
            std::cout << "Found static string: " << std::string(candidates[c], candidates[c] + wcslen(candidates[c])) 
                      << " at offset 0x" << std::hex << offset << std::endl;
            logFile << "Found: " << std::string(candidates[c], candidates[c] + wcslen(candidates[c])) 
                    << " at RVA 0x" << std::hex << offset << std::endl;
            foundStringOffset = offset;
            foundString = candidates[c];
            break; // Use the first one found
        }
    }

    if (foundStringOffset == (uintptr_t)-1) {
        std::cout << "No candidate static strings found within module." << std::endl;
        logFile << "No candidate strings found." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    uintptr_t foundStringAbsAddr = baseAddr + foundStringOffset;
    logFile << "Target String Address: 0x" << std::hex << foundStringAbsAddr << std::endl;

    // Scan module's code section for references
    // We'll brute-force scan for any 4-byte relative offset pointing to it.
    std::cout << "Brute-force scanning for relative references to string..." << std::endl;
    logFile << "Scanning for code references..." << std::endl;

    int matchCount = 0;
    for (size_t i = 0; i < bytesRead - 4; ++i) {
        int32_t relOffset = *(int32_t*)&moduleBuffer[i];
        // currentRip after the offset = baseAddr + i + 4
        uintptr_t currentRip = baseAddr + i + 4;
        uintptr_t targetAddr = currentRip + relOffset;

        if (targetAddr == foundStringAbsAddr) {
            matchCount++;
            uint8_t b1 = (i > 0) ? moduleBuffer[i - 1] : 0;
            uint8_t b2 = (i > 1) ? moduleBuffer[i - 2] : 0;
            bool isLea = (b1 == 0x8D); // LEA instruction

            std::cout << "MATCH #" << matchCount << " at RVA 0x" << std::hex << i << std::endl;
            logFile << "!!! MATCH FOUND !!!" << std::endl;
            logFile << "RVA of Rel32: 0x" << std::hex << i << std::endl;
            logFile << "Preceding bytes: " << std::hex << (int)b2 << " " << (int)b1 << std::endl;
            if (isLea) {
                logFile << "Likely a LEA instruction. Function entry might be nearby." << std::endl;
            }
        }
    }

    if (matchCount == 0) {
        std::cout << "No code references found to the string within module." << std::endl;
        logFile << "No code references found." << std::endl;
    } else {
        std::cout << "Total matches: " << std::dec << matchCount << std::endl;
        logFile << "Total matches: " << std::dec << matchCount << std::endl;
    }

    logFile.close();
    CloseHandle(hProcess);
    return 0;
}
