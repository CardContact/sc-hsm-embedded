/**
 * SmartCard-HSM Ultra-Light Library
 *
 * Copyright (c) 2013, CardContact Systems GmbH, Minden, Germany
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
 * @file sc-hsm-ultralite-test.c
 * @author Christoph Brunhuber
 */

#include <memory.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <ctccid/ctapi.h>
#include "utils.h"
#include "sc-hsm-ultralite.h"

#ifdef _WIN32
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#include <windows.h>
#ifndef usleep
#define usleep(us) Sleep((us) / 1000)
#endif
#else
/* Windows GetTickCount() returns ms since startup.
 * This function returns ms since the Epoch.
 * Since we're doing a delta it's OK
 */
long GetTickCount()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
#endif

uint8 TestHash[] = {
	0x81, 0x1c, 0x98, 0xb8, 0x3b, 0x8a, 0x56, 0xdf, 0x9e, 0x34, 0xe6, 0x8b, 0x41, 0xf4, 0x27, 0xd6,
	0x9e, 0xfe, 0x7f, 0x52, 0x74, 0x61, 0xb1, 0x39, 0x8a, 0x1c, 0x74, 0xa0, 0xd5, 0xa7, 0x00, 0xd2
};
int TestHashLen = sizeof(TestHash);

int DumpAllFiles(const char *pin)
{
	uint8 list[2 * 128];
	uint16 sw1sw2;
	int rc, i;
	rc = SC_Open(pin);
	if (rc < 0)
		return rc;

	/* - SmartCard-HSM: ENUMERATE OBJECTS */
	rc = SC_ProcessAPDU(
		0, 0x00,0x58,0x00,0x00,
		0, 0,
		list, sizeof(list),
		&sw1sw2);
	if (rc < 0) {
		SC_Close();
		return rc;
	}
	/* save dir and all files */
	SaveToFile("dir.hsm", list, rc);
	for (i = 0; i < rc; i += 2) {
		uint8 buf[0x10000], *p;
		char name[10];
		int rc, off;
		uint16 fid = list[i] << 8 | list[i + 1];
		if (list[i] == 0xcc) /* never readable */
			continue;
		for (p = buf, off = 0; off < sizeof(buf); p += rc) {
			int l = sizeof(buf) - off;
			if (l > MAX_OUT_IN)
				l = MAX_OUT_IN;
			rc = SC_ReadFile(fid, off, p, l);
			if (rc < 0)
				break;
			off += rc;
			if (rc < l)
				break;
		}
		if (rc >= 0) {
			sprintf(name, "%04X.asn", fid);
			printf("write '%s'\n", name);
			SaveToFile(name, buf, off);
		}
	}
	SC_Close();
	return 0;
}

int ResetPin(const char *pin, const char *sopin)
{
	uint16 sw1sw2;
	int rc, len;
	uint8 sopin_pin[8 + 16];
	if (sopin == 0) {
		memcpy(sopin_pin, "\x35\x37\x36\x32\x31\x38\x38\x30", 8);
	} else {
		int i;
		if (strlen(sopin) != 16) {
			printf("SO_PIN must have 16 hex-digits");
			return ERR_INVALID;
		}
		for (i = 0; i < 8; i++) {
			int hi = sopin[2 * i + 0];
			int lo = sopin[2 * i + 1];
#define HEX(ch) (\
			'0' <= ch && ch <= '9' \
			? ch - '0' \
			: 'A' <= ch && ch <= 'F' \
				? 10 + ch - 'A' \
				: 'a' <= ch && ch <= 'f' \
					? 10 - ch - 'a' \
					: -1)
			int b = HEX(hi) << 4 | HEX(lo);
#undef HEX
			if (b < 0) {
				printf("SO_PIN must have 16 hex-digits");
				return ERR_INVALID;
			}
			sopin_pin[i] = b;
		}
	}
	len = strlen(pin);
	if (!(6 <= len && len <= 16)) {
		printf("PIN must have 6 - 16 chars");
		return ERR_INVALID;
	}
	memcpy(sopin_pin + 8, pin, len); /* no 0 terminator */
	rc = SC_Open(0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: RESET RETRY COUNTER */
	rc = SC_ProcessAPDU(
		0, 0x00,0x2C,0x00,0x81,
		sopin_pin, 8 + len,
		0, 0,
		&sw1sw2);
	if (rc < 0) {
		SC_Close();
		return rc;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	if (!(2 <= argc && argc <= 5)) {
		printf("\
usage: %s pin label [count [wait-in-milliseconds]] (signs a test hash)\n\
   or: %s pin (writes all token elementary files to disk)\n\
   or: %s --reset-pin pin [so-pin] (so-pin defaults to '3537363231383830')\n",
			argv[0], argv[0], argv[0]);
		return 1;
	}
#if defined(_WIN32) && defined(_DEBUG)
	atexit((void(*)(void))_CrtDumpMemoryLeaks);
#endif
	if (argc >= 3) {
		if (strcmp(argv[1], "--reset-pin") == 0) {
			ResetPin(argv[2], argc == 3 ? NULL : argv[3]);
		} else {
			int rc;
			const uint8 *pCms = 0;
			int count = argc >= 4 ? atoi(argv[3]) : 1;
			int wait = argc >= 5 ? atoi(argv[4]) : 10000;
			for (i = 0; i < count; i++) {
				long start, end;
				if (i > 0 && count > 1) {
					printf("wait %d milliseconds for next signature\n", wait);
					usleep(wait * 1000);
				}
				start = GetTickCount();
				rc = sign_hash(argv[1], argv[2], TestHash, TestHashLen, &pCms);
				end = GetTickCount();
				printf("sign_hash returns: %d, time used: %ld ms\n", rc, end - start);
				if (rc > 0) {
					char name[64];
					sprintf(name, "test-%s.p7s", argv[2]);
					SaveToFile(name, pCms, rc);
				}
			}
			release_template();
		}
	} else {
		DumpAllFiles(argv[1]);
	}
	return 0;
}
