/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2017, CardContact Systems GmbH, Minden, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of CardContact Systems GmbH nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CardContact Systems GmbH BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file    sc-hsm-minidriver-test.c
 * @author  Andreas Schwier
 * @brief   Test framework for the CSP minidriver implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

static int testscompleted = 0;
static int testsfailed = 0;

#ifndef _WIN32

#include <unistd.h>
#include <dlfcn.h>
#define LIB_HANDLE void*
#define P11LIBNAME "/usr/local/lib/libsc-hsm-pkcs11.so"

#else

#include <windows.h>
#include <malloc.h>
#define LIB_HANDLE HMODULE
#define P11LIBNAME "sc-hsm-pkcs11.dll"

#define dlopen(fn, flag) LoadLibrary(fn)
#define dlclose(h) FreeLibrary(h)
#define dlsym(h, n) GetProcAddress(h, n)
#define pthread_t HANDLE
#define pthread_create(t, a, f, p) (*t = CreateThread(0, 0, f, p, 0, 0), *t ? 0 : GetLastError())
#define pthread_join(t, s) WaitForSingleObject(t, INFINITE)
#define pthread_exit(r) ExitThread(0)
#define pthread_attr_t int
#define pthread_attr_init(a)
#define pthread_attr_setdetachstate(a, f)
#define pthread_attr_destroy(a)

char* dlerror()
{
	char* msg = "UNKNOWN";
	DWORD le = GetLastError();
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, le, 0, (char*)&msg, 0, 0);
	return msg;
}

size_t getline(char** pp, size_t* pl, FILE* f)
{
	char buf[256];
	buf[0] = 0;
	fgets(buf, sizeof(buf), f);
	*pl = strlen(buf) + 1;
	if (*pp)
		free(*pp);
	*pp = (char*)malloc(*pl);
	if (*pp == 0) {
		printf("malloc(%d) failed.", *pl);
		exit(1);
	}
	memcpy(*pp, buf, *pl);
	return *pl - 1;
}

void usleep(unsigned int usec) 
{ 
    HANDLE timer; 
    LARGE_INTEGER ft; 
  
    ft.QuadPart = -(10 * (__int64)usec); 
  
    timer = CreateWaitableTimer(NULL, TRUE, NULL); 
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
    WaitForSingleObject(timer, INFINITE); 
    CloseHandle(timer); 
}

#endif /* _WIN32 */

#include <cardmod.h>



static char *verdict(int condition) {
	testscompleted++;

	if (condition) {
		return "Passed";
	} else {
		testsfailed++;
		return "Failed";
	}
}



LPVOID WINAPI CSP_ALLOC(__in SIZE_T Size) {
	return calloc(1, Size);
}


LPVOID WINAPI CSP_REALLOC(__in LPVOID Address, __in SIZE_T Size) {
	return realloc(Address, Size);
}


void WINAPI CSP_FREE(__in LPVOID Address) {
	free(Address);
}


int main(int argc, char *argv[])

{
	LIB_HANDLE dlhandle;
	PFN_CARD_ACQUIRE_CONTEXT pcac;
	CARD_FREE_SPACE_INFO cardFreeSpaceInfo;
	CARD_CAPABILITIES cardCapabilities;
	CARD_DATA cardData;
	CARD_KEY_SIZES keySizes;
	CARD_FILE_INFO fileInfo;
	CONTAINER_INFO containerInfo;
	PIN_INFO pinInfo;
	DWORD cch = 0;
	LPTSTR readers = NULL;
	LPSTR filenames;
	PBYTE pb;
	DWORD dwActiveProtocol, readernamelen, state, protocol, atrlen;
	unsigned char atr[36], cardid[16];
	DWORD dwrc,dwlen,dwparam;
	BOOL flag;

	dlhandle = dlopen("sc-hsm-minidriver.dll", RTLD_NOW);

	if (!dlhandle) {
		printf("dlopen failed with %s\n", dlerror());
		exit(1);
	}

	pcac = (PFN_CARD_ACQUIRE_CONTEXT)dlsym(dlhandle, "CardAcquireContext");

	memset(&cardData, 0, sizeof(cardData));
	cardData.dwVersion = 7;
	cardData.pwszCardName = L"TestCard";
	cardData.hScard = 1;

	cardData.pfnCspAlloc = CSP_ALLOC;
	cardData.pfnCspReAlloc = CSP_REALLOC;
	cardData.pfnCspFree = CSP_FREE;

	if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &cardData.hSCardCtx) != SCARD_S_SUCCESS) {
		printf("SCardEstablishContext() failed\n");
		exit(1);
	}

	if (SCardListReaders(cardData.hSCardCtx, NULL, NULL, &cch) != SCARD_S_SUCCESS) {
		printf("SCardListReaders() failed\n");
		exit(1);
	}

	readers = calloc(cch, 1);

	if (SCardListReaders(cardData.hSCardCtx, NULL, readers, &cch) != SCARD_S_SUCCESS) {
		printf("SCardListReaders() failed\n");
		exit(1);
	}

	// readers = readers + strlen(readers) + 1;
	if (SCardConnect(cardData.hSCardCtx, readers, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &cardData.hScard, &dwActiveProtocol) != SCARD_S_SUCCESS) {
		printf("SCardConnect() failed\n");
		exit(1);
	}

	readernamelen = 0;
	atrlen = sizeof(atr);

	if (SCardStatus(cardData.hScard, NULL, &readernamelen, &state, &protocol, atr, &atrlen) != SCARD_S_SUCCESS) {
		printf("SCardStatus() failed\n");
		exit(1);
	}

	cardData.pbAtr = atr;
	cardData.cbAtr = atrlen;

	printf("Calling CardAcquireContext()");
	dwrc = (*pcac)(&cardData, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryFreeSpace()");
	cardFreeSpaceInfo.dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryFreeSpace)(&cardData, 0, &cardFreeSpaceInfo);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_FREE_SPACE)");
	cardFreeSpaceInfo.dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_FREE_SPACE, (PBYTE)&cardFreeSpaceInfo, sizeof(cardFreeSpaceInfo), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryCapabilities()");
	cardCapabilities.dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryCapabilities)(&cardData, &cardCapabilities);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_CAPABILITIES)");
	cardCapabilities.dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_CAPABILITIES, (PBYTE)&cardCapabilities, sizeof(cardCapabilities), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardQueryKeySizes()");
	keySizes.dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardQueryKeySizes)(&cardData, AT_SIGNATURE, 0, &keySizes);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_KEYSIZES)");
	keySizes.dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_KEYSIZES, (PBYTE)&keySizes, sizeof(keySizes), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_READ_ONLY)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_READ_ONLY, (PBYTE)&flag, sizeof(flag), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && flag));

	printf("Calling CardGetProperty(CP_CARD_CACHE_MODE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_CACHE_MODE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == CP_CACHE_MODE_NO_CACHE)));

	printf("Calling CardGetProperty(CP_SUPPORTS_WIN_X509_ENROLLMENT)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_SUPPORTS_WIN_X509_ENROLLMENT, (PBYTE)&flag, sizeof(flag), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && !flag));

	printf("Calling CardGetProperty(CP_CARD_GUID)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_GUID, (PBYTE)&cardid, sizeof(cardid), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_SERIAL_NO)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_SERIAL_NO, (PBYTE)&cardid, sizeof(cardid), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_PIN_INFO)");
	pinInfo.dwVersion = PIN_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_PIN_INFO, (PBYTE)&pinInfo, sizeof(pinInfo), &dwlen, ROLE_USER);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));
	
	printf("Calling CardGetProperty(CP_CARD_LIST_PINS)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_LIST_PINS, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == CREATE_PIN_SET(ROLE_USER))));

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardGetProperty(CP_CARD_PIN_STRENGTH_VERIFY)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_PIN_STRENGTH_VERIFY, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == CARD_PIN_STRENGTH_PLAINTEXT)));

	printf("Calling CardGetProperty(CP_KEY_IMPORT_SUPPORT)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_KEY_IMPORT_SUPPORT, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardReadFile(cardid)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, szCARD_IDENTIFIER_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 16)));

	printf("Calling CardReadFile(cardcf)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, szCACHE_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 6)));

	printf("Calling CardReadFile(cardapps)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, NULL, "cardapps", 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen == 8)));

	printf("Calling CardReadFile(mscp/cmapfile)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardGetFileInfo(mscp/cmapfile)");
	fileInfo.dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetFileInfo)(&cardData, szBASE_CSP_DIR, szCONTAINER_MAP_FILE, &fileInfo);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardReadFile(mscp/kxc00)");
	dwrc = (*cardData.pfnCardReadFile)(&cardData, szBASE_CSP_DIR, szUSER_KEYEXCHANGE_CERT_PREFIX "00", 0, &pb, &dwlen);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardEnumFiles(root)");
	dwrc = (*cardData.pfnCardEnumFiles)(&cardData, NULL, &filenames, &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwlen > 0)));

	printf("Calling CardGetContainerInfo(0)");
	containerInfo.dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	dwrc = (*cardData.pfnCardGetContainerInfo)(&cardData, 0, 0, &containerInfo);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardAuthenticatePin(wszCARD_USER_USER)");
	dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, "648219", 6, &dwparam);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 3)));

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 2)));

	printf("Calling CardAuthenticatePin(wszCARD_USER_USER) - Wrong PIN");
	dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, "123456", 6, &dwparam);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_W_WRONG_CHV) && (dwparam == 2)));

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardAuthenticatePin(wszCARD_USER_USER)");
	dwrc = (*cardData.pfnCardAuthenticatePin)(&cardData, wszCARD_USER_USER, "648219", 6, &dwparam);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 3)));

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 2)));

	printf("Calling CardDeAuthenticate(wszCARD_USER_USER)");
	dwrc = (*cardData.pfnCardDeauthenticate)(&cardData, wszCARD_USER_USER, 0);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	printf("Calling CardGetProperty(CP_CARD_AUTHENTICATED_STATE)");
	dwrc = (*cardData.pfnCardGetProperty)(&cardData, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&dwparam, sizeof(dwparam), &dwlen, 0);
	printf(" - %x : %s\n", dwrc, verdict((dwrc == SCARD_S_SUCCESS) && (dwparam == 0)));

	printf("Calling CardDeleteContext()");
	dwrc = (*cardData.pfnCardDeleteContext)(&cardData);
	printf(" - %x : %s\n", dwrc, verdict(dwrc == SCARD_S_SUCCESS));

	SCardReleaseContext(cardData.hSCardCtx);

	printf("Unit test finished.\n");
	printf("%d tests performed.\n", testscompleted);
	printf("%d tests failed.\n", testsfailed);

	exit(testsfailed ? 1 : 0);
}
