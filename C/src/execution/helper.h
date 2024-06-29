#pragma once
#include <windows.h>

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