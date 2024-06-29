#pragma once

#ifndef SYS_TAMPERING_H
#define SYS_TAMPERING_H

#include <windows.h>

#define DEBUG
//\
#define DELAY

// ==========================================================================================================================

#define MAX_ENTRIES		600

// ==========================================================================================================================

typedef struct _SYSCALL_ENTRY {

	UINT32		u32Hash;
	ULONG_PTR	uAddress;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _SYSCALL_ENTRY_LIST {

	DWORD			dwEntriesCount;
	SYSCALL_ENTRY	Entries[MAX_ENTRIES];

} SYSCALL_ENTRY_LIST, * PSYSCALL_ENTRY_LIST;

// ==========================================================================================================================

BOOL InitializeTamperedSyscall	(IN ULONG_PTR uCalledSyscallAddress, IN UINT32 uCRC32FunctionHash, IN ULONG_PTR uParm1, IN ULONG_PTR uParm2, IN ULONG_PTR uParm3, IN ULONG_PTR uParm4);

// ==========================================================================================================================

BOOL InitHardwareBreakpointHooking	();
BOOL HaltHardwareBreakpointHooking	();

// ==========================================================================================================================

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile

typedef NTSTATUS(NTAPI* fnNtQueryDirectoryFile)(
	ULONG_PTR		uParm1,
	ULONG_PTR		uParm2,
	ULONG_PTR		uParm3,
	ULONG_PTR		uParm4,
	ULONG_PTR		uParm5,
	ULONG_PTR		uParm6,
	ULONG_PTR		uParm7,
	ULONG_PTR		uParm8,
	ULONG_PTR		uParm9,
	ULONG_PTR		uParmA,
	ULONG_PTR		uParmB		// One can add more fake parameters here if the original syscall required > 11 parms
);

// ==========================================================================================================================

/*
	TAMPER_SYSCALL:
		* Calls the "InitializeTamperedSyscall" function.
		* Calls the decoy syscall, "NtQuerySecurityObject". When "NtQuerySecurityObject" is executed, its SSN will be replaced with u32SyscallHash's SSN (that is the ssn of the real syscall to be executed).
		  Therefore the kernel will invoke the function of hash "u32SyscallHash". 
		* First 4 parameters of "NtQuerySecurityObject" are NULL, these are replaced by the VEH when triggered.
*/
#define TAMPER_SYSCALL(u32SyscallHash, uParm1, uParm2, uParm3, uParm4, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)					\
	if (1){																																		\
																																				\
		NTSTATUS					STATUS					= 0x00;																				\
		fnNtQueryDirectoryFile		pNtQuerySecurityObject	= NULL;																				\
																																				\
		if (!(pNtQuerySecurityObject = (fnNtQueryDirectoryFile)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQuerySecurityObject")))	\
			return -1;																															\
																																				\
		if (!InitializeTamperedSyscall(pNtQuerySecurityObject, u32SyscallHash, uParm1, uParm2, uParm3, uParm4))									\
			return -1;																															\
																																				\
		if ((STATUS = pNtQuerySecurityObject(NULL, NULL, NULL, NULL, uParm5, uParm6, uParm7, uParm8, uParm9, uParmA, uParmB)) != 0x00) {		\
			printf("[!] 0x%0.8X Failed With Error: 0x%0.8X \n", u32SyscallHash, STATUS);														\
			return -1;																															\
		}																																		\
	}

// ==========================================================================================================================

#endif // !SYS_TAMPERING_H
