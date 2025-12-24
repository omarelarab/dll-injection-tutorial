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
#ifndef SCF_DEFAULT
#define SCF_DEFAULT 0x0000
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
    Log("Setting Bold on Standard Edit");
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
}

// Function to set font to Bold for RichEdit control (Win 11)
void SetBoldRichEdit(HWND hwnd) {
    Log("Setting Bold on RichEdit (Unicode)");
    
    // Use Unicode structure
    CHARFORMAT2W cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_BOLD;
    cf.dwEffects = CFE_BOLD;
    
    // Apply to ALL text
    LRESULT resultAll = SendMessageW(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    Log("EM_SETCHARFORMAT (ALL) Result: " + std::to_string(resultAll));

    // Apply to DEFAULT (future text)
    LRESULT resultDef = SendMessageW(hwnd, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
    Log("EM_SETCHARFORMAT (DEFAULT) Result: " + std::to_string(resultDef));
}

// Callback for EnumChildWindows
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char className[256];
    GetClassNameA(hwnd, className, 256);
    Log("Found Child Window: " + std::string(className));
    
    if (strstr(className, "RichEdit") != NULL || strstr(className, "Edit") != NULL) {
        Log("Target Match! Class: " + std::string(className));
        
        if (strstr(className, "RichEdit") != NULL) {
            SetBoldRichEdit(hwnd);
        } else {
             SetBoldStandard(hwnd);
        }
        
        *(BOOL*)lParam = TRUE;
    }
    return TRUE; 
}

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

void ApplyBoldPayload() {
    logFile.open("C:\\Users\\Public\\notepad_payload_log.txt");
    Log("Payload v3 Started");
    
    HWND hMain = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hMain);

    if (hMain) {
        char title[256];
        GetWindowTextA(hMain, title, 256);
        Log("Found Main Window: " + std::string(title));

        BOOL found = FALSE;
        EnumChildWindows(hMain, EnumChildProc, (LPARAM)&found);
        
        if (found) {
            MessageBox(NULL, TEXT("Bold Applied (v3)!"), TEXT("Success"), MB_OK);
        } else {
            MessageBox(NULL, TEXT("No Edit Control Found!"), TEXT("Failure"), MB_OK);
        }
    } else {
        MessageBox(NULL, TEXT("Main Window Missing!"), TEXT("Failure"), MB_OK);
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
