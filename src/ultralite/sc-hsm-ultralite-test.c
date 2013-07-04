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

#ifdef WIN32
#ifdef DEBUG
#include <crtdbg.h>
#endif
#endif

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <ctccid/ctapi.h>
#include "utils.h"
#include "sc-hsm-ultralite.h"

#ifndef WIN32
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

extern int SC_Open(const char *pin);
extern int SC_ReadFile(int ctn, uint16 fid, int off, uint8 *data, int dataLen);

uint8 TestHash[] = {
	0x81, 0x1c, 0x98, 0xb8, 0x3b, 0x8a, 0x56, 0xdf, 0x9e, 0x34, 0xe6, 0x8b, 0x41, 0xf4, 0x27, 0xd6,
	0x9e, 0xfe, 0x7f, 0x52, 0x74, 0x61, 0xb1, 0x39, 0x8a, 0x1c, 0x74, 0xa0, 0xd5, 0xa7, 0x00, 0xd2
};
int TestHashLen = sizeof(TestHash);

int DumpAllFiles(const char *pin)
{
	uint8 List[2 * 128];
	uint16 SW1SW2;
	int ctn, rc, i;
	ctn = SC_Open(pin);
	if (ctn < 0)
		return ctn;

	/* - SmartCard-HSM: ENUMERATE OBJECTS */
	rc = ProcessAPDU(ctn, 0, 0x00,0x58,0x00,0x00,
					 0, NULL,
					 sizeof(List), List, &SW1SW2);
	if (rc < 0) {
		CT_close(ctn);
		return rc;
	}
	/* save dir and all files */
	SaveToFile("dir.hsm", List, rc);
	for (i = 0; i < rc; i += 2) {
		uint8 buf[0x10000], *p;
		char name[10];
		int rc, off;
		uint16 fid = List[i] << 8 | List[i + 1];
		if (List[i] == 0xcc) /* never readable */
			continue;
		for (p = buf, off = 0; off < sizeof(buf); p += rc) {
			int l = sizeof(buf) - off;
			if (l > MAX_OUT_IN)
				l = MAX_OUT_IN;
			rc = SC_ReadFile(ctn, fid, off, p, l);
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
	CT_close(ctn);
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	if (!(2 <= argc && argc <= 5)) {
		printf("\
    usage: %s pin label [count [wait-in-milliseconds]] (signs a test hash)\n\
       or: %s pin (writes all token elementary files to disk)\n",
			argv[0], argv[0]);
		return 1;
	}
	if (argc >= 3) {
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
	} else {
		DumpAllFiles(argv[1]);
	}
#if defined(WIN32) && defined(DEBUG)
	_CrtDumpMemoryLeaks();
#endif
	return 0;
}
