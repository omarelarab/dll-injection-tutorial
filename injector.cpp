#include <windows.h> // Include Windows API headers for system functions
#include <tlhelp32.h> // Include Tool Help Library for process snapshotting
#include <iostream>   // Include IO stream for console output
#include <string>     // Include string library for string manipulation

// Function to get Process ID by name
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0; // Initialize PID to 0 (default for not found)
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Take a snapshot of all running processes
    if (hSnapshot != INVALID_HANDLE_VALUE) { // Check if the snapshot was successful
        PROCESSENTRY32W pe32; // Structure to hold process entry details
        pe32.dwSize = sizeof(PROCESSENTRY32W); // Set size of the structure (required by API)
        if (Process32FirstW(hSnapshot, &pe32)) { // Retrieve information about the first process
            do {
                if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0) { // Compare process name (case-insensitive)
                    pid = pe32.th32ProcessID; // If matched, store the Process ID
                    break; // Exit the loop
                }
            } while (Process32NextW(hSnapshot, &pe32)); // Continue to the next process in the snapshot
        }
        CloseHandle(hSnapshot); // Close the snapshot handle to free resources
    }
    return pid; // Return the found PID (or 0 if not found)
}

// Enable Debug Privilege to allow accessing system processes
bool EnableDebugPrivilege() {
    HANDLE hToken; // Handle to the process token
    TOKEN_PRIVILEGES tp; // Structure to hold token privileges
    LUID luid; // Locally Unique Identifier for the privilege

    // Open the access token associated with the current process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false; // Return false if unable to open token
    }

    // Lookup the LUID for the "SeDebugPrivilege"
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken); // Close token handle on failure
        return false; // Return false if privilege lookup fails
    }

    tp.PrivilegeCount = 1; // Set the number of privileges to adjust
    tp.Privileges[0].Luid = luid; // Set the privilege LUID
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Enable the privilege

    // Adjust the token privileges to enable Debug privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken); // Close token handle on failure
        return false; // Return false if adjustment fails
    }

    // Check if the privilege was actually assigned (even if function succeeds)
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken); // Close token handle
        return false; // Return false if not all privileges assigned
    }

    CloseHandle(hToken); // Close the token handle
    return true; // Return true indicating success
}

int main(int argc, char* argv[]) { // Main entry point with command line arguments
    if (argc < 2) { // Check if a payload argument was provided
        std::cerr << "Usage: injector.exe <payload.dll>" << std::endl; // Print usage instructions
        return 1; // Exit with error code
    }

    // Attempt to enable debug privilege for higher access rights
    if (EnableDebugPrivilege()) {
        std::cout << "Debug privilege enabled." << std::endl; // Log success
    } else {
        std::cerr << "Failed to enable debug privilege (might be needed)." << std::endl; // Log warning
    }

    const std::wstring targetProcess = L"notepad.exe"; // Target process name to find or launch
    const char* payloadName = argv[1]; // Get payload DLL name from command line
    
    DWORD pid = 0; // Variable to store Process ID
    HANDLE hProcess = NULL; // Variable to store Process Handle

    // 1. Find the process
    pid = GetProcessIdByName(targetProcess); // Check if process is already running
    
    if (pid == 0) { // If process is not running
        std::wcout << L"Process " << targetProcess << L" not found. Launching..." << std::endl; // Log launching status
        
        // Startup information structure for the new process
        STARTUPINFOW si; // Structure for startup info
        PROCESS_INFORMATION pi; // Structure for process info
        ZeroMemory(&si, sizeof(si)); // Zero out the memory for startup info (initialize to 0)
        si.cb = sizeof(si); // Set structure size
        ZeroMemory(&pi, sizeof(pi)); // Zero out the memory for process info

        // Start the child process.
        wchar_t cmdLine[] = L"notepad.exe"; // Command line string (mutable buffer)
        if (!CreateProcessW(NULL,   // No module name (use command line)
            cmdLine,        // Command line being executed
            NULL,           // Process handle not inheritable
            NULL,           // Thread handle not inheritable
            FALSE,          // Set handle inheritance to FALSE
            0,              // No creation flags
            NULL,           // Use parent's environment block
            NULL,           // Use parent's starting directory 
            &si,            // Pointer to STARTUPINFO structure
            &pi)           // Pointer to PROCESS_INFORMATION structure
            )
        {
            std::cerr << "CreateProcess failed (" << GetLastError() << ")." << std::endl; // Log failure reason
            return 1; // Exit with error
        }

        // Wait until child process exits (or initializes)
        WaitForInputIdle(pi.hProcess, 1000); // Wait for process to be idle/ready input
        
        // Close handles immediately. We will look for the process again to find the "real" one
        // in case this was just a shim (common in Win11).
        CloseHandle(pi.hProcess); // Close process handle
        CloseHandle(pi.hThread); // Close thread handle

        // Poll for the process to appear
        int retries = 10; // Number of retry attempts
        while (retries > 0) { // Loop until found or retries exhausted
            Sleep(500); // Wait 500ms between checks
            pid = GetProcessIdByName(targetProcess); // Check for process ID again
            if (pid != 0) break; // If found, exit loop
            retries--; // Decrement retry counter
        }

        if (pid == 0) { // If still not found after retries
            std::cerr << "Timeout waiting for Notepad to start." << std::endl; // Log timeout error
            return 1; // Exit with error
        }
        
    }
    
    std::wcout << L"Found " << targetProcess << L" with PID: " << pid << std::endl; // Log found PID
    // 2. Open the process (Always open fresh to ensure we get the real process)
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // Open process with full access rights

    if (!hProcess) { // Check if open failed
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl; // Log error code
        return 1; // Exit with error
    }

    // 3. Get full path of the DLL
    char dllPath[MAX_PATH]; // Buffer for full DLL path
    if (GetFullPathNameA(payloadName, MAX_PATH, dllPath, NULL) == 0) { // Resolve absolute path
        std::cerr << "Failed to get full path of DLL. Error: " << GetLastError() << std::endl; // Log error
        CloseHandle(hProcess); // Cleanup handle
        return 1; // Exit with error
    }
    std::cout << "Injecting DLL: " << dllPath << std::endl; // Log intended DLL path

    // 4. Allocate memory in target process
    // Allocate space in the remote process memory to store the DLL path string
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) { // Check allocation failure
        std::cerr << "Failed to allocate memory. Error: " << GetLastError() << std::endl; // Log memory error
        CloseHandle(hProcess); // Cleanup handle
        return 1; // Exit
    }

    // 5. Write DLL path to target process
    // Copy the DLL path string into the allocated remote memory
    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write memory. Error: " << GetLastError() << std::endl; // Log write error
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE); // Free allocated memory
        CloseHandle(hProcess); // Cleanup handle
        return 1; // Exit
    }

    // 6. Create remote thread to load the DLL
    // Start a new thread in the remote process that calls LoadLibraryA with the path to our DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemotePath, 0, NULL);
    if (!hThread) { // Check thread creation failure
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl; // Log thread error
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE); // Free memory
        CloseHandle(hProcess); // Cleanup process handle
        return 1; // Exit
    }

    std::cout << "Injection successful!" << std::endl; // Log success

    // Cleanup
    WaitForSingleObject(hThread, INFINITE); // Wait for the injection thread to finish (LoadLibrary to return)
    CloseHandle(hThread); // Close thread handle
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE); // Free the remote memory
    CloseHandle(hProcess); // Close process handle

    return 0; // Return success code
}
