#include <windows.h> // Include the core Windows API header for windowing and process functions
#include <iostream>  // Include the standard C++ I/O library
#include <string.h>  // Include the C string manipulation library for strcmp

// Global variable to store the address of the original window procedure for the subclassed control
WNDPROC g_OriginalWndProc = NULL;

// The replacement window procedure that will intercept messages sent to the Notepad edit control
LRESULT CALLBACK NewWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    // Check if the incoming message is a character input (WM_CHAR)
    if (uMsg == WM_CHAR) {
        // Cast the wParam (which contains the character code) to a TCHAR
        TCHAR ch = (TCHAR)wParam;

        // Determine if the character is an alphabetical letter (a-z or A-Z)
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            // Increment the character value by 1 to perform a simple Caesar cipher shift
            ch++;

            // Check if the shifted character went past 'z' and wrap it back to 'a'
            if (ch == 'z' + 1) ch = 'a';
            // Check if the shifted character went past 'Z' and wrap it back to 'A'
            if (ch == 'Z' + 1) ch = 'A';

            // Pass the modified character to the original window procedure to be processed/displayed
            return CallWindowProc(g_OriginalWndProc, hwnd, uMsg, (WPARAM)ch, lParam);
        }
    }

    // For all other messages, pass them through to the original window procedure unchanged
    return CallWindowProc(g_OriginalWndProc, hwnd, uMsg, wParam, lParam);
}

// Callback function invoked by EnumChildWindows for every child window found
BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    char className[256]; // Buffer to hold the class name string
    GetClassNameA(hwnd, className, 256); // Retrieve the class name of the current child window handle
    
    // Compare the class name against known Notepad edit control class names (Win11 and Legacy)
    if (strcmp(className, "RichEditD2DPT") == 0 || strcmp(className, "Edit") == 0) {
        HWND* phEdit = (HWND*)lParam; // Cast the user-defined parameter back to an HWND pointer
        *phEdit = hwnd;               // Store the handle of the found edit control
        return FALSE;                 // Return FALSE to stop the enumeration process
    }
    return TRUE; // Return TRUE to continue searching through other child windows
}

// Function responsible for finding the target window and applying the subclassing hook
void InstallHook() {
    // Get the unique Process ID of the process this DLL is currently running inside
    DWORD currentPid = GetCurrentProcessId();
    
    HWND hMain = NULL; // Variable to store the handle of the main Notepad window
    HWND hEdit = NULL; // Variable to store the handle of the internal text editing control

    // Start searching for top-level windows from the top of the Z-order
    HWND hTemp = GetTopWindow(NULL);
    while (hTemp) {
        DWORD pid;
        // Get the PID of the process that owns the current window handle
        GetWindowThreadProcessId(hTemp, &pid);
        // Check if this window belongs to our current Notepad process
        if (pid == currentPid) {
            char className[256];
            GetClassNameA(hTemp, className, 256); // Get the class name of the window
            // Verify if the window class is "Notepad"
            if (strcmp(className, "Notepad") == 0) {
                hMain = hTemp; // Found the main window
                break;         // Stop searching top-level windows
            }
        }
        // Move to the next window in the system's window list
        hTemp = GetNextWindow(hTemp, GW_HWNDNEXT);
    }

    // If the main Notepad window was found, look for its child edit control
    if (hMain) {
        // Enumerate all child windows of hMain and use EnumChildProc to find the edit control
        EnumChildWindows(hMain, EnumChildProc, (LPARAM)&hEdit);
    }

    // If the edit control was successfully located
    if (hEdit) {
        // Use SetWindowLongPtr to replace the window's procedure with NewWndProc and save the old one
        g_OriginalWndProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)NewWndProc);
        MessageBox(NULL, TEXT("Hook Installed!"), TEXT("Payload"), MB_OK);
    } else {
        MessageBox(NULL, TEXT("Could not find Edit control!"), TEXT("Error"), MB_OK);
    }
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Create a thread to do the hooking so we don't block the loader
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InstallHook, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
