#pragma once

#include <windows.h>

// ==========================================================================================================================

typedef struct _TAMPERED_SYSCALL {

	ULONG_PTR	uParm1;
	ULONG_PTR	uParm2;
	ULONG_PTR	uParm3;
	ULONG_PTR	uParm4;
	DWORD		dwSyscallNmbr;

}TAMPERED_SYSCALL, * PTAMPERED_SYSCALL;

// ==========================================================================================================================

BOOL InitHardwareBreakpointHooking();
BOOL HaltHardwareBreakpointHooking();

VOID PassParameters				(IN ULONG_PTR uParm1, IN ULONG_PTR uParm2, IN ULONG_PTR uParm3, IN ULONG_PTR uParm4, IN DWORD dwSyscallNmbr);
BOOL InstallHardwareBPHook		(IN DWORD dwThreadID, IN ULONG_PTR uTargetFuncAddress);

// ==========================================================================================================================

