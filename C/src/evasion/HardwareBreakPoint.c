#include <windows.h>
#include <stdio.h>

#include "HardwareBreakPoint.h"
#include "SyscallTampering.h"

// ==========================================================================================================================

CRITICAL_SECTION	g_CriticalSection		= { 0 };
TAMPERED_SYSCALL	g_TamperedSyscall		= { 0 };
PVOID				g_VehHandler			= NULL;

// ==========================================================================================================================

/*
	Initialize the g_TamperedSyscall global variable with the right parameters. 
	The element "dwSyscallNmbr" in the "TAMPERED_SYSCALL" structure represents the original SSN of the real syscall to execute.
*/
VOID PassParameters(IN ULONG_PTR uParm1, IN ULONG_PTR uParm2, IN ULONG_PTR uParm3, IN ULONG_PTR uParm4, IN DWORD dwSyscallNmbr) {

	EnterCriticalSection(&g_CriticalSection);

	g_TamperedSyscall.uParm1			= uParm1;
	g_TamperedSyscall.uParm2			= uParm2;
	g_TamperedSyscall.uParm3			= uParm3;
	g_TamperedSyscall.uParm4			= uParm4;
	g_TamperedSyscall.dwSyscallNmbr		= dwSyscallNmbr;

	LeaveCriticalSection(&g_CriticalSection);
}

// ==========================================================================================================================

unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
	unsigned long long mask				= (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register	= (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
	return NewDr7Register;
}

// ==========================================================================================================================


LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo) {
	
	BOOL	bResolved	= FALSE;

	if (pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		goto _EXIT_ROUTINE;

	if (pExceptionInfo->ExceptionRecord->ExceptionAddress != pExceptionInfo->ContextRecord->Dr0)
		goto _EXIT_ROUTINE;

#ifdef DEBUG
	//printf("[i] Address Of Exception: 0x%p [ TID: %d ]\n", pExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
	//printf("[i] Decoy SSN: %d\n", (DWORD)pExceptionInfo->ContextRecord->Rax);
	//printf("[i] Real SSN: %d\n", (DWORD)g_TamperedSyscall.dwSyscallNmbr);
#endif 

	EnterCriticalSection(&g_CriticalSection);

	// Replace Decoy SSN
	pExceptionInfo->ContextRecord->Rax = (DWORD64)g_TamperedSyscall.dwSyscallNmbr;
	// Replace Decoy parms
	pExceptionInfo->ContextRecord->R10 = (DWORD64)g_TamperedSyscall.uParm1;
	pExceptionInfo->ContextRecord->Rdx = (DWORD64)g_TamperedSyscall.uParm2;
	pExceptionInfo->ContextRecord->R8 = (DWORD64)g_TamperedSyscall.uParm3;
	pExceptionInfo->ContextRecord->R9 = (DWORD64)g_TamperedSyscall.uParm4;
	// Remove breakpoint
	pExceptionInfo->ContextRecord->Dr0 = 0ull;

	LeaveCriticalSection(&g_CriticalSection);

#ifdef DEBUG
	//printf("[*] Executing Real Syscall Stub ...\n");
#endif 

	bResolved = TRUE;

_EXIT_ROUTINE:
	return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}

// ==========================================================================================================================

BOOL InitHardwareBreakpointHooking() {

	if (g_VehHandler)
		return TRUE;

	InitializeCriticalSection(&g_CriticalSection);

	if (!(g_VehHandler = AddVectoredExceptionHandler(0x01, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine))) {
#ifdef DEBUG
		printf("[!] AddVectoredExceptionHandler Failed With Error: %d \n", GetLastError());
#endif
		return FALSE;
	}

	return TRUE;
}

BOOL HaltHardwareBreakpointHooking() {

	DeleteCriticalSection(&g_CriticalSection);

	if (g_VehHandler) {

		if (RemoveVectoredExceptionHandler(g_VehHandler) == 0x00) {
#ifdef DEBUG
			printf("[!] AddVectoredExceptionHandler Failed With Error: %d \n", GetLastError());
#endif
			return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

// ==========================================================================================================================


BOOL InstallHardwareBPHook(IN DWORD dwThreadID, IN ULONG_PTR uTargetFuncAddress) {

	CONTEXT		Context		= { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE		hThread		= NULL;
	BOOL		bResult		= FALSE;

#ifdef DEBUG
	//printf("[i] Installing BP At: 0x%p [ TID: %d ]\n", uTargetFuncAddress, dwThreadID);
#endif

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {
#ifdef DEBUG
		printf("[!] OpenThread Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	if (!GetThreadContext(hThread, &Context)) {
#ifdef DEBUG
		printf("[!] GetThreadContext Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	Context.Dr0 = uTargetFuncAddress;
	Context.Dr6 = 0x00;
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x10, 0x02, 0x00);
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x12, 0x02, 0x00);
	Context.Dr7 = SetDr7Bits(Context.Dr7, 0x00, 0x01, 0x01);

	if (!SetThreadContext(hThread, &Context)) {
#ifdef DEBUG
		printf("[!] SetThreadContext Failed With Error: %d \n", GetLastError());
#endif
		goto _END_OF_FUNC;
	}

	bResult = TRUE;

_END_OF_FUNC:
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}

// ==========================================================================================================================
