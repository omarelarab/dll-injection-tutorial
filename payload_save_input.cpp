#include <windows.h>
#include <iostream>

void SendCtrlS() {
    // 1. INPUT Structure for Key Down (Ctrl)
    INPUT inputs[4] = {};
    ZeroMemory(inputs, sizeof(inputs));

    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_CONTROL;

    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = 'S';

    inputs[2].type = INPUT_KEYBOARD;
    inputs[2].ki.wVk = 'S';
    inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;

    inputs[3].type = INPUT_KEYBOARD;
    inputs[3].ki.wVk = VK_CONTROL;
    inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

    // Send the Input
    SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT));
}

void TypeString(const char* str) {
    // Basic implementation to type ASCII characters
    for (int i = 0; str[i] != '\0'; ++i) {
        char c = str[i];
        SHORT vk = VkKeyScanA(c);
        
        INPUT input[2] = {};
        input[0].type = INPUT_KEYBOARD;
        input[0].ki.wVk = LOBYTE(vk);
        
        // Handle Shift if needed (e.g. colon, uppercase)
        bool shift = (HIBYTE(vk) & 1);
        
        if (shift) {
            INPUT shiftIn = {};
            shiftIn.type = INPUT_KEYBOARD;
            shiftIn.ki.wVk = VK_SHIFT;
            SendInput(1, &shiftIn, sizeof(INPUT));
        }

        SendInput(1, &input[0], sizeof(INPUT)); // Down

        input[1] = input[0];
        input[1].ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &input[1], sizeof(INPUT)); // Up

        if (shift) {
            INPUT shiftOut = {};
            shiftOut.type = INPUT_KEYBOARD;
            shiftOut.ki.wVk = VK_SHIFT;
            shiftOut.ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(1, &shiftOut, sizeof(INPUT));
        }
    }
}

void SavePayload() {
    Sleep(1000); // Wait for injection to settle
    MessageBox(NULL, TEXT("Payload Injected! Attempting to Save..."), TEXT("Save Payload"), MB_OK);
    
    // 1. Set Focus (Optional, but good practice if logic allows)
    // 2. Send Ctrl + S
    SendCtrlS();
    
    // 3. Wait for "Save As" Dialog
    Sleep(1000);
    
    // 4. Type Filename (Desktop path usually requires typing absolute path or navigating)
    // We will try typing a generic name, assuming default is Documents or Desktop
    
    // Get Desktop Path?
    // For simplicity, let's type a name in the current default folder
    TypeString("hacked_file.txt");
    
    Sleep(500);
    
    // 5. Press Enter to Save
    INPUT enter[2] = {};
    enter[0].type = INPUT_KEYBOARD;
    enter[0].ki.wVk = VK_RETURN;
    enter[1] = enter[0];
    enter[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, enter, sizeof(INPUT));

    MessageBox(NULL, TEXT("Save command sent!"), TEXT("Success"), MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SavePayload, NULL, 0, NULL);
    }
    return TRUE;
}
