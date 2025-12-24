#include <windows.h>
#include <shlobj.h>  // For SHGetFolderPath
#include <string>

void WriteFileToDesktop() {
    // Get Desktop path
    wchar_t desktopPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        MessageBox(NULL, TEXT("Failed to get Desktop path"), TEXT("Error"), MB_OK);
        return;
    }
    
    // Create full file path
    std::wstring filePath = std::wstring(desktopPath) + L"\\injected_file.txt";
    
    // The content we want to write
    const char* content = "This file was created by DLL injection!\r\n"
                          "The 'Hard Way' succeeded!\r\n"
                          "Parameters captured from Notepad:\r\n"
                          "  DesiredAccess: 0xC0000000 (GENERIC_READ | GENERIC_WRITE)\r\n"
                          "  ShareMode: 0x1 (FILE_SHARE_READ)\r\n"
                          "  CreationDisposition: 4 (OPEN_ALWAYS)\r\n";
    
    // Use the EXACT parameters we captured from Notepad
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        0xC0000000,             // GENERIC_READ | GENERIC_WRITE
        0x1,                    // FILE_SHARE_READ
        NULL,                   // Default security
        4,                      // OPEN_ALWAYS (create if not exists)
        FILE_ATTRIBUTE_NORMAL,  // Normal file
        NULL                    // No template
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        wchar_t msg[256];
        wsprintfW(msg, L"CreateFileW failed!\nError: %d\nPath: %s", error, filePath.c_str());
        MessageBoxW(NULL, msg, L"Error", MB_OK);
        return;
    }
    
    // Write the content
    DWORD bytesWritten;
    BOOL success = WriteFile(hFile, content, (DWORD)strlen(content), &bytesWritten, NULL);
    
    if (!success) {
        MessageBox(NULL, TEXT("WriteFile failed!"), TEXT("Error"), MB_OK);
        CloseHandle(hFile);
        return;
    }
    
    // Close the file (this flushes and saves)
    CloseHandle(hFile);
    
    // Success message
    wchar_t msg[512];
    wsprintfW(msg, L"File created successfully!\n\nPath: %s\nBytes written: %d", filePath.c_str(), bytesWritten);
    MessageBoxW(NULL, msg, L"SUCCESS - Hard Way Complete!", MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WriteFileToDesktop, NULL, 0, NULL);
    }
    return TRUE;
}
