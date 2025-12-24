#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: dumper.exe <RVA_hex>" << std::endl;
        std::cout << "Example: dumper.exe 7f708" << std::endl;
        return 1;
    }

    uintptr_t targetRva = strtoull(argv[1], nullptr, 16);
    std::cout << "Target RVA: 0x" << std::hex << targetRva << std::endl;

    EnableDebugPrivilege();

    std::wstring targetProcess = L"notepad.exe";
    DWORD pid = GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::cerr << "Process not found." << std::endl;
        return 1;
    }

    uintptr_t baseAddr = 0;
    size_t moduleSize = 0;
    if (!GetModuleInfo(pid, targetProcess, baseAddr, moduleSize)) {
        std::cerr << "Could not get module info." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    // Dump 256 bytes before and after the target RVA
    size_t dumpStart = (targetRva > 256) ? (targetRva - 256) : 0;
    size_t dumpSize = 512;
    
    std::vector<uint8_t> buffer(dumpSize);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(baseAddr + dumpStart), buffer.data(), dumpSize, &bytesRead)) {
        std::cerr << "Failed to read memory." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::ofstream dump("code_dump.txt");
    dump << "Code dump around RVA 0x" << std::hex << targetRva << std::endl;
    dump << "Base Address: 0x" << baseAddr << std::endl;
    dump << std::endl;

    // Look for common function prologs going backwards
    // x64 prolog patterns:
    // 48 89 5C 24 xx  = mov [rsp+xx], rbx
    // 48 83 EC xx     = sub rsp, xx
    // 40 53           = push rbx
    // CC              = int 3 (padding between functions)
    // 90              = nop (padding)
    // C3              = ret (end of previous function)

    std::cout << "Searching backwards for function prologs..." << std::endl;
    dump << "Searching backwards for function prologs..." << std::endl;

    size_t offsetInBuffer = targetRva - dumpStart;
    for (int i = (int)offsetInBuffer; i >= 0; --i) {
        uintptr_t currentRva = dumpStart + i;
        uint8_t b0 = buffer[i];
        uint8_t b1 = (i + 1 < (int)bytesRead) ? buffer[i + 1] : 0;
        uint8_t b2 = (i + 2 < (int)bytesRead) ? buffer[i + 2] : 0;
        uint8_t b3 = (i + 3 < (int)bytesRead) ? buffer[i + 3] : 0;

        // Check for common function start patterns
        bool foundProlog = false;

        // Pattern: 48 89 5C 24 (mov [rsp+...], rbx)
        if (b0 == 0x48 && b1 == 0x89 && b2 == 0x5C && b3 == 0x24) {
            dump << "POSSIBLE FUNCTION START (mov [rsp+xx], rbx) at RVA 0x" << std::hex << currentRva << std::endl;
            foundProlog = true;
        }
        // Pattern: 48 83 EC xx (sub rsp, xx)
        if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) {
            dump << "POSSIBLE FUNCTION START (sub rsp, xx) at RVA 0x" << std::hex << currentRva << std::endl;
            foundProlog = true;
        }
        // Pattern: 40 53 (push rbx) - common start for leaf functions
        if (b0 == 0x40 && b1 == 0x53) {
            dump << "POSSIBLE FUNCTION START (push rbx) at RVA 0x" << std::hex << currentRva << std::endl;
            foundProlog = true;
        }
        // Pattern: CC or 90 followed by something else (padding then new function)
        if (i > 0 && (buffer[i-1] == 0xCC || buffer[i-1] == 0x90) && b0 != 0xCC && b0 != 0x90) {
            dump << "POSSIBLE FUNCTION START (after padding) at RVA 0x" << std::hex << currentRva << std::endl;
            foundProlog = true;
        }
        // Pattern: C3 followed by something (ret then new function)
        if (i > 0 && buffer[i-1] == 0xC3) {
            dump << "POSSIBLE FUNCTION START (after ret) at RVA 0x" << std::hex << currentRva << std::endl;
            foundProlog = true;
        }

        if (foundProlog) {
            std::cout << "Candidate function entry at RVA 0x" << std::hex << currentRva << std::endl;
        }
    }

    // Hex dump
    dump << std::endl << "Hex Dump (RVA 0x" << std::hex << dumpStart << " - 0x" << (dumpStart + bytesRead) << "):" << std::endl;
    for (size_t i = 0; i < bytesRead; ++i) {
        if (i % 16 == 0) {
            dump << std::endl << "0x" << std::hex << std::setw(8) << std::setfill('0') << (dumpStart + i) << ": ";
        }
        dump << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
    }
    dump << std::endl;

    dump.close();
    CloseHandle(hProcess);
    std::cout << "Dump written to code_dump.txt" << std::endl;
    return 0;
}
