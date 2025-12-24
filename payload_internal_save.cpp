#include <windows.h>
#include <iostream>

// =============================================================
// STEP 1: DEFINE THE FUNCTION SIGNATURE
// You must know exactly what the internal function looks like.
// For "SaveFile" in many apps, it might be void, or take a bool.
// This is an EXAMPLE signature. Reverse engineering is required to verify.
// =============================================================
typedef void (__fastcall *SaveFileFunc)(bool); 
// Note: __fastcall is common for internal C++ functions (ecx = this pointer).
// If it's a global function, it might be __stdcall or __cdecl.

// =============================================================
// STEP 2: PUT YOUR OFFSET HERE
// The analyzer found a function at RVA 0x7eaf0 that references
// the "Save" string. This is likely part of the save handling logic.
// NOTE: The exact calling convention and arguments are UNKNOWN.
//       This is a risky call - it may crash or do unexpected things.
// =============================================================
uintptr_t OFFSET_SAVE_FUNCTION = 0x7eaf0; // Discovered via analyzer 

void CallInternalSave() {
    // 1. Get Base Address of Notepad
    uintptr_t baseAddress = (uintptr_t)GetModuleHandle(NULL);
    
    // 2. Calculate the Real Address
    uintptr_t functionAddress = baseAddress + OFFSET_SAVE_FUNCTION;

    char msg[256];
    sprintf_s(msg, "Calling Internal Function at:\nBase: 0x%p\nOffset: 0x%p\nTarget: 0x%p", 
        (void*)baseAddress, (void*)OFFSET_SAVE_FUNCTION, (void*)functionAddress);
    MessageBox(NULL, TEXT(msg), TEXT("Debug"), MB_OK);

    // 3. Cast the address to a function pointer
    SaveFileFunc InternalSave = (SaveFileFunc)functionAddress;

    // 4. CALL IT!
    // TRY-CATCH to prevent crashing if the offset is wrong
    __try {
        // Passing 'false' (assuming argument is 'SaveAs')
        InternalSave(false); 
        MessageBox(NULL, TEXT("Function Called Successfully!"), TEXT("Success"), MB_OK);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MessageBox(NULL, TEXT("CRASH! The function call failed.\nWrong Offset or Signature?"), TEXT("Error"), MB_OK);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Run in a thread to keep DllMain fast
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallInternalSave, NULL, 0, NULL);
    }
    return TRUE;
}
