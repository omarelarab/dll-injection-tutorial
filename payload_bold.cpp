#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <richedit.h>

// Define necessary RichEdit constants if not already defined
#ifndef CFM_BOLD
#define CFM_BOLD 0x00000001
#endif
#ifndef CFE_BOLD
#define CFE_BOLD 0x00000001
#endif
#ifndef SCF_ALL
#define SCF_ALL 0x0004
#endif

std::ofstream logFile;

void Log(const std::string& msg) {
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

// Function to set font to Bold for standard Edit control
void SetBoldStandard(HWND hwnd) {
    Log("Attempting to set Bold on Standard Edit: " + std::to_string((unsigned long long)hwnd));
    HFONT hFont = (HFONT)SendMessage(hwnd, WM_GETFONT, 0, 0);
    LOGFONT lf;
    if (hFont) {
        GetObject(hFont, sizeof(LOGFONT), &lf);
    } else {
        SystemParametersInfo(SPI_GETICONTITLELOGFONT, sizeof(LOGFONT), &lf, 0);
    }
    lf.lfWeight = FW_BOLD;
    HFONT hNewFont = CreateFontIndirect(&lf);
    SendMessage(hwnd, WM_SETFONT, (WPARAM)hNewFont, MAKELPARAM(TRUE, 0));
    Log("Standard Edit Bold Set");
}

// Function to set font to Bold for RichEdit control (Win 11)
void SetBoldRichEdit(HWND hwnd) {
    Log("Attempting to set Bold on RichEdit: " + std::to_string((unsigned long long)hwnd));
    CHARFORMAT2 cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_BOLD;
    cf.dwEffects = CFE_BOLD;
    SendMessage(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    Log("RichEdit Bold Set message sent");
}

// Callback for EnumChildWindows
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char className[256];
    GetClassNameA(hwnd, className, 256);
    Log("Found Child Window: " + std::string(className));
    
    // Check for various Edit classes
    if (strstr(className, "RichEdit") != NULL || strstr(className, "Edit") != NULL) {
        Log("Target Match! Class: " + std::string(className));
        
        // Try both methods just in case? Or distinguish.
        // Windows 11 Notepad uses RichEditD2DPT
        if (strstr(className, "RichEdit") != NULL) {
            SetBoldRichEdit(hwnd);
        } else {
             SetBoldStandard(hwnd);
        }
        
        *(BOOL*)lParam = TRUE;
        // Don't stop enumerating, apply to ALL edit controls we find (e.g. tabs!)
        // return FALSE; 
    }
    return TRUE; 
}

// Callback to find the main window of this process
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId()) {
        if (GetWindow(hwnd, GW_OWNER) == NULL && IsWindowVisible(hwnd)) {
            *(HWND*)lParam = hwnd;
            return FALSE; // Stop enumerating
        }
    }
    return TRUE;
}

// Function to apply the payload
void ApplyBoldPayload() {
    // Open log file safely
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string logPath = std::string(tempPath) + "notepad_payload_log.txt";
    logFile.open(logPath);

    Log("Payload Thread Started");
    
    // DEBUG: Show message box to confirm injection logic is running
    // MessageBox(NULL, TEXT("Payload Injected! Checking log..."), TEXT("Debug"), MB_OK);

    HWND hMain = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hMain);

    if (hMain) {
        char title[256];
        GetWindowTextA(hMain, title, 256);
        Log("Found Main Window: " + std::string(title));

        BOOL found = FALSE;
        EnumChildWindows(hMain, EnumChildProc, (LPARAM)&found);
        
        if (found) {
            Log("Bold Styling Applied to at least one control.");
            MessageBox(NULL, TEXT("Bold Applied! check Notepad."), TEXT("Success"), MB_OK);
        } else {
            Log("No suitable Edit control found in children.");
            MessageBox(NULL, TEXT("Failed to find edit control. Check log in Temp."), TEXT("Failure"), MB_OK);
        }
    } else {
        Log("Main Window not found via EnumWindows.");
        MessageBox(NULL, TEXT("Main Window not found!"), TEXT("Failure"), MB_OK);
    }
    
    logFile.close();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyBoldPayload, NULL, 0, NULL);
        break;
    }
    return TRUE;
}
