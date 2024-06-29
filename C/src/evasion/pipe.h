#pragma once

#include <windows.h>
#include <stdio.h>


BOOL CreateNamedPipeClientW(IN LPCWSTR szPipeName, IN PBYTE pData, IN DWORD dwDataLength) {

    BOOL    bResult         = FALSE;
    HANDLE  hPipe           = INVALID_HANDLE_VALUE;
    DWORD   dwWritten       = 0x00;

    if ((hPipe = CreateFileW(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileW Failed With Error: %d \n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hPipe, pData, dwDataLength, &dwWritten, NULL) || dwDataLength != dwWritten) {
        printf("[!] WriteFile Failed With Error: %d \n", GetLastError());
        printf("[i] Wrote %d Of %d Bytes \n", dwWritten, dwDataLength);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
    return bResult;
}