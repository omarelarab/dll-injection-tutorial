# DLL Injection Tutorial: From Zero to Hero
## A Complete Beginner's Guide to Windows Process Manipulation

**Author**: Created with AI Assistance  
**Date**: December 2024  
**Target Audience**: Beginners with basic C++ knowledge  
**Platform**: Windows 10/11 (64-bit)

---

# Table of Contents

1. [Introduction: What is DLL Injection?](#chapter-1-introduction-what-is-dll-injection)
2. [Setting Up Your Environment](#chapter-2-setting-up-your-environment)
3. [Part 1: The Injector - Getting Into Another Process](#chapter-3-the-injector)
4. [Part 2: Simple Payloads - Doing Things Inside the Process](#chapter-4-simple-payloads)
5. [Part 3: Window Subclassing - Intercepting Messages](#chapter-5-window-subclassing)
6. [Part 4: Memory Scanning - Finding Hidden Functions](#chapter-6-memory-scanning)
7. [Part 5: Inline Hooking - Intercepting Function Calls](#chapter-7-inline-hooking)
8. [Part 6: API Hooking - The Ultimate Power](#chapter-8-api-hooking)
9. [Part 7: Putting It All Together](#chapter-9-putting-it-all-together)
10. [Conclusion and Next Steps](#chapter-10-conclusion)

---

# Chapter 1: Introduction - What is DLL Injection?

## What You Will Learn

DLL Injection is a technique used to run your own code inside another program's memory space. Think of it like this:

- **Normal Program**: Your code runs in its own "house" (process)
- **DLL Injection**: Your code moves into someone else's "house" and can access everything there

## Why Would You Want This?

| Use Case | Example |
|----------|---------|
| **Game Modding** | Adding new features to games |
| **Debugging** | Monitoring what a program does |
| **Security Research** | Understanding malware behavior |
| **Accessibility** | Adding features to closed-source software |
| **Automation** | Controlling programs without UI automation |

## The Components We'll Build

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   INJECTOR.EXE  │────▶│   NOTEPAD.EXE   │◀────│   PAYLOAD.DLL   │
│  (Our Launcher) │     │ (Target Process)│     │  (Our Code)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │   1. Find Process     │                       │
        │   2. Allocate Memory  │                       │
        │   3. Write DLL Path   │                       │
        │   4. Create Thread    │                       │
        │                       │                       │
        └───────────────────────┴───────────────────────┘
```

## Key Concepts for Beginners

### What is a Process?
A **process** is a running program. When you open Notepad, Windows creates a "process" for it. Each process has:
- Its own memory space (other processes can't normally access it)
- A Process ID (PID) - a unique number to identify it
- One or more threads (paths of execution)

### What is a DLL?
A **DLL** (Dynamic Link Library) is a file containing code that can be loaded into a process. Unlike an EXE, a DLL can't run on its own - it needs to be loaded by another program.

### What is a Handle?
A **handle** is like a ticket or key that Windows gives you to access system resources. When you open a process, file, or window, Windows gives you a handle to use for future operations.

---

# Chapter 2: Setting Up Your Environment

## Prerequisites

1. **Windows 10 or 11** (64-bit)
2. **Visual Studio 2022** (Community Edition is free)
3. **Basic C++ knowledge** (variables, functions, pointers)

## Creating the Project

```
📁 NotepadInject/
├── 📄 injector.cpp       (The launcher that injects DLLs)
├── 📄 payload_shift.cpp  (Payload: Shifts typed characters)
├── 📄 payload_bold.cpp   (Payload: Makes text bold)
├── 📄 scanner.cpp        (Tool: Finds memory patterns)
├── 📄 analyzer.cpp       (Tool: Analyzes process memory)
├── 📄 dumper.cpp         (Tool: Dumps code for analysis)
└── 📄 payload_*.cpp      (Various other payloads)
```

## Compiling Commands

Open **Developer Command Prompt for VS 2022** and use:

```batch
:: For an EXE (like injector)
cl.exe /EHsc injector.cpp user32.lib advapi32.lib

:: For a DLL (like payloads)
cl.exe /LD payload_shift.cpp user32.lib gdi32.lib
```

---

# Chapter 3: The Injector - Getting Into Another Process

## How Injection Works (Step by Step)

### Step 1: Find the Target Process

Before we can inject, we need to find Notepad. Windows provides the **Tool Help Library** for this:

```cpp
#include <tlhelp32.h>  // Tool Help Library

DWORD GetProcessIdByName(const std::wstring& processName) {
    // Take a "snapshot" of all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);  // REQUIRED: Set the structure size
    
    // Loop through all processes
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Compare names (case-insensitive)
            if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0) {
                return pe32.th32ProcessID;  // Found it!
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    return 0;  // Not found
}
```

**Key Concept**: `CreateToolhelp32Snapshot` creates a "photograph" of the current state of all processes. We then iterate through this snapshot to find our target.

### Step 2: Open the Process

Once we have the PID, we need to open a "handle" to the process:

```cpp
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,  // We want full access
    FALSE,               // Don't inherit this handle to child processes
    pid                  // The Process ID we found
);
```

**Why might this fail?**
- The process doesn't exist
- We don't have permission (need Administrator for some processes)
- Anti-virus software blocking us

### Step 3: Allocate Memory in the Target

Now comes the clever part. We need to write the path of our DLL into Notepad's memory. But we can't just write anywhere - we need to ask Windows to give us some space:

```cpp
// "strlen(dllPath) + 1" includes the null terminator
LPVOID pRemotePath = VirtualAllocEx(
    hProcess,                   // Which process
    NULL,                       // Let Windows choose the address
    strlen(dllPath) + 1,        // How many bytes we need
    MEM_COMMIT,                 // Actually allocate the memory
    PAGE_READWRITE              // We need to read and write to it
);
```

**Think of it like this**: You're asking Notepad "Hey, can I have a small piece of paper to write on inside your house?"

### Step 4: Write the DLL Path

Now we write our DLL's path into that allocated memory:

```cpp
WriteProcessMemory(
    hProcess,               // Target process
    pRemotePath,            // Where to write (the memory we just allocated)
    dllPath,                // What to write (our DLL's path as a string)
    strlen(dllPath) + 1,    // How many bytes
    NULL                    // We don't need to know how many bytes were written
);
```

### Step 5: The Magic - Create a Remote Thread

Here's where the magic happens. Windows has a function called `LoadLibraryA` that loads a DLL. We're going to create a new thread in Notepad that calls this function with our DLL path:

```cpp
HANDLE hThread = CreateRemoteThread(
    hProcess,                           // Target process
    NULL,                               // Default security
    0,                                  // Default stack size
    (LPTHREAD_START_ROUTINE)LoadLibraryA,  // Function to call
    pRemotePath,                        // Argument to that function (our DLL path)
    0,                                  // Start immediately
    NULL                                // We don't need the thread ID
);
```

**What happens**:
1. Windows creates a new thread inside Notepad
2. That thread runs `LoadLibraryA("C:\\path\\to\\our\\payload.dll")`
3. Windows loads our DLL into Notepad's memory
4. Our DLL's `DllMain` function is called!

---

# Chapter 4: Simple Payloads - Doing Things Inside the Process

## The DllMain Entry Point

Every DLL has an entry point called `DllMain`. This is automatically called when the DLL is loaded:

```cpp
BOOL APIENTRY DllMain(
    HMODULE hModule,           // Handle to our DLL
    DWORD  ul_reason_for_call, // WHY we're being called
    LPVOID lpReserved          // Reserved (don't use)
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:   // DLL is being loaded
        // Start our payload code here!
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MyPayload, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:    // New thread created in process
    case DLL_THREAD_DETACH:    // Thread exiting
    case DLL_PROCESS_DETACH:   // DLL is being unloaded
        break;
    }
    return TRUE;
}
```

**Important**: Don't do heavy work directly in `DllMain`! Windows holds a lock while calling it. Create a new thread instead.

## Payload Example: Making Text Bold

Our `payload_bold.cpp` demonstrates finding UI controls and modifying their appearance:

```cpp
void ApplyBoldPayload() {
    // 1. Find the main Notepad window
    HWND hMain = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hMain);
    
    // 2. Find the edit control inside
    HWND hEdit = NULL;
    EnumChildWindows(hMain, EnumChildProc, (LPARAM)&hEdit);
    
    // 3. Get current font, modify it to bold
    HFONT hFont = (HFONT)SendMessage(hEdit, WM_GETFONT, 0, 0);
    LOGFONT lf;
    GetObject(hFont, sizeof(LOGFONT), &lf);
    lf.lfWeight = FW_BOLD;  // Make it bold!
    
    // 4. Create new font and apply
    HFONT hNewFont = CreateFontIndirect(&lf);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hNewFont, TRUE);
}
```

---

# Chapter 5: Window Subclassing - Intercepting Messages

## What is Subclassing?

Every window in Windows has a **Window Procedure** (WndProc) - a function that handles all messages sent to that window. Subclassing means replacing that function with our own.

```
BEFORE SUBCLASSING:
┌──────────────────────────────────────────────────────┐
│  Keyboard Press → Windows → Notepad's WndProc       │
└──────────────────────────────────────────────────────┘

AFTER SUBCLASSING:
┌──────────────────────────────────────────────────────┐
│  Keyboard Press → Windows → OUR WndProc → Original  │
│                              (intercept!)            │
└──────────────────────────────────────────────────────┘
```

## The Character Shift Payload

Our `payload_shift.cpp` intercepts keystrokes and shifts them:

```cpp
// Our replacement window procedure
LRESULT CALLBACK NewWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_CHAR) {  // Character typed!
        TCHAR ch = (TCHAR)wParam;
        
        // Shift alphabetic characters
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            ch++;  // 'a' becomes 'b', 'b' becomes 'c', etc.
            
            // Handle wrap-around
            if (ch == 'z' + 1) ch = 'a';
            if (ch == 'Z' + 1) ch = 'A';
            
            // Pass modified character to original
            return CallWindowProc(g_OriginalWndProc, hwnd, uMsg, (WPARAM)ch, lParam);
        }
    }
    
    // For all other messages, call the original
    return CallWindowProc(g_OriginalWndProc, hwnd, uMsg, wParam, lParam);
}

// Install the hook
void InstallHook() {
    HWND hEdit = /* find the edit control */;
    
    // Replace the window procedure - returns the OLD one
    g_OriginalWndProc = (WNDPROC)SetWindowLongPtr(
        hEdit, 
        GWLP_WNDPROC, 
        (LONG_PTR)NewWndProc
    );
}
```

**Key Points**:
- `SetWindowLongPtr` with `GWLP_WNDPROC` replaces the window procedure
- It returns the OLD procedure, which we save
- We MUST call the original for messages we don't handle
- Otherwise, the window would stop working!

---

# Chapter 6: Memory Scanning - Finding Hidden Functions

## The Challenge

When we wanted to call Notepad's internal "Save" function, we faced a problem:
- The function isn't exported (we can't just call it by name)
- The address changes every time the program runs (ASLR)

## Solution: Signature Scanning

We look for a **pattern** of bytes that is unique to the function we want. This pattern stays the same even when the address changes.

### How Our Analyzer Works

```cpp
// 1. Read the module into memory
std::vector<uint8_t> moduleBuffer(moduleSize);
ReadProcessMemory(hProcess, (LPCVOID)baseAddr, moduleBuffer.data(), moduleSize, &bytesRead);

// 2. Search for a known string (like "Save")
uintptr_t stringOffset = FindWideString(moduleBuffer, L"Save");

// 3. Search for code that REFERENCES this string
// In x64, this looks like: LEA register, [RIP + offset]
for (size_t i = 0; i < bytesRead - 4; ++i) {
    int32_t relOffset = *(int32_t*)&moduleBuffer[i];
    uintptr_t targetAddr = (baseAddr + i + 4) + relOffset;
    
    if (targetAddr == stringAbsAddr) {
        // Found code that references our string!
        std::cout << "Match at RVA: 0x" << std::hex << i << std::endl;
    }
}
```

### What is RIP-Relative Addressing?

In 64-bit Windows, code often accesses data using **RIP-relative addressing**:

```
Address of string = Address of next instruction + Relative offset

Example:
  Instruction at 0x7f708: LEA rdx, [RIP + 0x16c4c4]
  Next instruction at:    0x7f70F
  String is at:          0x7f70F + 0x16c4c4 = 0x1EBBD0
```

This is why we scan for 4-byte values that, when added to their position, equal our target.

---

# Chapter 7: Inline Hooking - Intercepting Function Calls

## What is Inline Hooking?

Inline hooking overwrites the first few bytes of a function with a JMP instruction that redirects to our code:

```
BEFORE:
┌─────────────────────────────────────┐
│ TargetFunction:                     │
│   mov [rsp+18h], rbx   ← Original   │
│   mov [rsp+20h], rsi      bytes     │
│   push rbp                          │
│   ...rest of function...            │
└─────────────────────────────────────┘

AFTER:
┌─────────────────────────────────────┐
│ TargetFunction:                     │
│   jmp HookFunction     ← Our JMP    │
│   <garbage bytes>      ← Overwritten│
│   push rbp                          │
│   ...rest of function...            │
└─────────────────────────────────────┘
```

## The Hook Implementation

```cpp
bool InstallHook() {
    uintptr_t targetAddress = baseAddress + TARGET_RVA;
    
    // 1. Make the memory writable
    DWORD oldProtect;
    VirtualProtect((LPVOID)targetAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 2. Save original bytes (so we can call the original later)
    memcpy(originalBytes, (void*)targetAddress, 14);
    
    // 3. Create the jump patch (14 bytes for x64)
    // FF 25 00 00 00 00 = JMP [RIP+0]
    // Followed by 8-byte absolute address
    uint8_t jmpPatch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // JMP [RIP+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address
    };
    
    uintptr_t hookAddr = (uintptr_t)&HookFunction;
    memcpy(&jmpPatch[6], &hookAddr, 8);  // Copy our function's address
    
    // 4. Write the patch
    memcpy((void*)targetAddress, jmpPatch, 14);
    
    // 5. Restore original protection
    VirtualProtect((LPVOID)targetAddress, 14, oldProtect, &oldProtect);
    
    return true;
}
```

## Our Parameter Capture Hook

We used this technique to capture the parameters of an unknown function:

```cpp
void __fastcall HookFunction(void* rcx, void* rdx, void* r8, void* r9) {
    Log("=== FUNCTION CALLED ===");
    LogHex("RCX (this?)", (uintptr_t)rcx);
    LogHex("RDX (param1?)", (uintptr_t)rdx);
    LogHex("R8  (param2?)", (uintptr_t)r8);
    LogHex("R9  (param3?)", (uintptr_t)r9);
    
    // Try to read data at the pointers...
}
```

This allowed us to discover that the function we found was actually a **UI text display function**, not the Save handler!

---

# Chapter 8: API Hooking - The Ultimate Power

## Why Hook Windows APIs?

When we couldn't find Notepad's internal Save function, we realized:
- **Every program** must eventually call Windows APIs to do real work
- To save a file, ANY program must call `CreateFileW` and `WriteFile`
- We can hook these APIs to see EXACTLY what Notepad does!

## Hooking CreateFileW

```cpp
// Our hook function - same signature as the original
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    // LOG EVERYTHING!
    Log("CreateFileW called!");
    LogW(lpFileName);  // This shows us the file path!
    
    if (dwDesiredAccess & GENERIC_WRITE) {
        Log(">>> THIS IS A WRITE/SAVE OPERATION <<<");
    }
    
    // Call the original function
    // (We temporarily unhook, call, then re-hook)
    return OriginalCreateFileW(...);
}

// Install the hook
void InstallApiHook() {
    // Get the API's address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    createFileWAddr = (uintptr_t)GetProcAddress(hKernel32, "CreateFileW");
    
    // Hook it using the same inline hooking technique
    // ... (same as before)
}
```

## What We Discovered

When we clicked Save in Notepad, our hook captured:

```
Filename: C:\Users\Omar\Desktop\asassa.txt
DesiredAccess: 0xC0000000 (GENERIC_READ | GENERIC_WRITE)
ShareMode: 0x1 (FILE_SHARE_READ)
CreationDisposition: 4 (OPEN_ALWAYS)
>>> THIS IS A WRITE OPERATION (SAVE) <<<
```

**These are the EXACT parameters Notepad uses to save files!**

---

# Chapter 9: Putting It All Together

## The Final Payload

Armed with the exact parameters, we created a payload that writes files directly:

```cpp
void WriteFileToDesktop() {
    // Get Desktop path
    wchar_t desktopPath[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    
    std::wstring filePath = std::wstring(desktopPath) + L"\\injected_file.txt";
    
    // Use the EXACT parameters we captured from Notepad!
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        0xC0000000,        // GENERIC_READ | GENERIC_WRITE
        0x1,               // FILE_SHARE_READ  
        NULL,
        4,                 // OPEN_ALWAYS
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    // Write content
    const char* content = "Created by DLL injection!";
    WriteFile(hFile, content, strlen(content), &bytesWritten, NULL);
    
    CloseHandle(hFile);  // Save complete!
}
```

## Summary of All Tools We Created

| File | Purpose |
|------|---------|
| `injector.cpp` | Launches Notepad and injects DLLs |
| `payload_shift.cpp` | Subclasses window to shift typed characters |
| `payload_bold.cpp` | Modifies font to bold |
| `scanner.cpp` | Scans memory for byte patterns |
| `analyzer.cpp` | Finds string references in code |
| `dumper.cpp` | Dumps code around a specific address |
| `payload_hook_capture.cpp` | Hooks internal function to capture params |
| `payload_hook_createfile.cpp` | Hooks CreateFileW API |
| `payload_write_file.cpp` | Final payload that writes files |

---

# Chapter 10: Conclusion and Next Steps

## What You Learned

1. **DLL Injection Basics**: How to inject code into other processes
2. **Windows Internals**: Processes, handles, memory protection
3. **Window Subclassing**: Intercepting UI messages
4. **Memory Scanning**: Finding functions by pattern matching
5. **Inline Hooking**: Redirecting function calls
6. **API Hooking**: Intercepting Windows system calls
7. **Reverse Engineering**: Analyzing unknown code/parameters

## The Journey We Took

```
Start: "I want to call Notepad's Save function"
    ↓
Attempt 1: Find function by string reference
    ↓
Problem: Function signature unknown → CRASH!
    ↓
Attempt 2: Hook function to capture parameters
    ↓
Discovery: It was a UI function, not Save!
    ↓
Attempt 3: Hook Windows API (CreateFileW)
    ↓
SUCCESS: Captured exact save parameters!
    ↓
Final: Created payload using those parameters
```

## Ethical Considerations

⚠️ **WARNING**: The techniques in this tutorial are powerful. Use them responsibly:

- ✅ Learning and education
- ✅ Debugging your own software
- ✅ Security research (with permission)
- ✅ Game modding (check terms of service)
- ❌ Cheating in online games
- ❌ Bypassing DRM or copy protection
- ❌ Creating malware
- ❌ Accessing systems without permission

## Next Steps for Learning

1. **Learn x86/x64 Assembly**: Understanding assembly makes reverse engineering much easier
2. **Use Real Debuggers**: Try x64dbg or WinDbg for interactive debugging
3. **Study PE Format**: Learn how Windows executables are structured
4. **Explore Anti-Debug Techniques**: Understand how software protects itself
5. **Read Windows Internals**: The book by Mark Russinovich is excellent

## Final Thoughts

What started as "make Notepad's text bold" evolved into a deep dive into Windows internals, reverse engineering, and process manipulation. We:

- Built an injector from scratch
- Created multiple payloads with different techniques
- Wrote memory scanning tools
- Implemented inline hooks
- Hooked Windows APIs
- Discovered unknown function parameters
- Successfully wrote files using captured parameters

The "Hard Way" taught us that reverse engineering is often about persistence and creative problem-solving. When one approach fails, there's usually another path to explore!

---

**Happy Hacking (Ethically)!** 🎉
