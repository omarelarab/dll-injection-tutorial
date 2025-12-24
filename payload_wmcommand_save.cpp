#include <windows.h>
#include <string.h>
#include <iostream>
#include <fstream>

// Standard Windows Menu Command IDs for Notepad
// These are typically defined in the resource file. Common IDs:
// ID_FILE_NEW    = 1
// ID_FILE_OPEN   = 2
// ID_FILE_SAVE   = 3
// ID_FILE_SAVEAS = 4
// Note: Windows 11 Notepad may use different IDs. We'll try common ones.

#define ID_FILE_SAVE    3
#define ID_FILE_SAVEAS  4

std::ofstream logFile;

void Log(const std::string& msg) {
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId()) {
        if (GetWindow(hwnd, GW_OWNER) == NULL && IsWindowVisible(hwnd)) {
            *(HWND*)lParam = hwnd;
            return FALSE;
        }
    }
    return TRUE;
}

void TriggerSave() {
    logFile.open("C:\\Users\\Public\\wmcommand_save_log.txt");
    Log("WM_COMMAND Save Payload Started");
    
    // Find our main window
    HWND hMain = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hMain);
    
    if (!hMain) {
        Log("ERROR: Could not find main window");
        MessageBox(NULL, TEXT("Main window not found!"), TEXT("Error"), MB_OK);
        return;
    }
    
    char title[256];
    GetWindowTextA(hMain, title, 256);
    Log("Found window: " + std::string(title));
    
    // Try sending WM_COMMAND with the Save ID
    Log("Sending WM_COMMAND with ID_FILE_SAVE (3)");
    LRESULT result = SendMessage(hMain, WM_COMMAND, MAKEWPARAM(ID_FILE_SAVE, 0), 0);
    Log("Result: " + std::to_string(result));
    
    // If that didn't work, try Save As
    Log("Sending WM_COMMAND with ID_FILE_SAVEAS (4)");
    result = SendMessage(hMain, WM_COMMAND, MAKEWPARAM(ID_FILE_SAVEAS, 0), 0);
    Log("Result: " + std::to_string(result));
    
    // Alternative approach: Use accelerator keys
    // This simulates Ctrl+S at the window level
    Log("Sending keyboard accelerator (Ctrl+S via WM_KEYDOWN)");
    
    // Send Ctrl key down
    PostMessage(hMain, WM_KEYDOWN, VK_CONTROL, 0);
    // Send S key
    PostMessage(hMain, WM_KEYDOWN, 'S', 0);
    PostMessage(hMain, WM_KEYUP, 'S', 0);
    // Send Ctrl key up
    PostMessage(hMain, WM_KEYUP, VK_CONTROL, 0);
    
    MessageBox(NULL, TEXT("WM_COMMAND sent! Check log for details."), TEXT("Done"), MB_OK);
    
    logFile.close();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TriggerSave, NULL, 0, NULL);
    }
    return TRUE;
}
