/**
 * RAMoverHTTP Test Client
 *
 * Copyright (c) 2015, CardContact Systems GmbH, Minden, Germany
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
 * @file ram-client.c
 * @author Andreas Schwier
 * @brief Remote application management over HTTP client
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#include <ramoverhttp/ramoverhttp.h>

#ifdef _WIN32
#define alloca _alloca
#endif

static int optListReaders = 0;
static char *optReader = NULL;
static char *optURL = NULL;
static char *optPin = NULL;
static int optVerbose = 0;


struct localContext {
	LPSTR reader;
	SCARDCONTEXT scardContext;
	SCARDHANDLE card;
};



char *pcsc_error_to_string(const LONG error) {
	static char strError[75];

	switch (error) {
		case SCARD_S_SUCCESS:
			(void) strncpy(strError, "Command successful.", sizeof(strError));
			break;
		case SCARD_F_INTERNAL_ERROR:
			(void) strncpy(strError, "Internal error.", sizeof(strError));
			break;
		case SCARD_E_CANCELLED:
			(void) strncpy(strError, "Command cancelled.", sizeof(strError));
			break;
		case SCARD_E_INVALID_HANDLE:
			(void) strncpy(strError, "Invalid handle.", sizeof(strError));
			break;
		case SCARD_E_INVALID_PARAMETER:
			(void) strncpy(strError, "Invalid parameter given.", sizeof(strError));
			break;
		case SCARD_E_INVALID_TARGET:
			(void) strncpy(strError, "Invalid target given.", sizeof(strError));
			break;
		case SCARD_E_NO_MEMORY:
			(void) strncpy(strError, "Not enough memory.", sizeof(strError));
			break;
		case SCARD_F_WAITED_TOO_LONG:
			(void) strncpy(strError, "Waited too long.", sizeof(strError));
			break;
		case SCARD_E_INSUFFICIENT_BUFFER:
			(void) strncpy(strError, "Insufficient buffer.", sizeof(strError));
			break;
		case SCARD_E_UNKNOWN_READER:
			(void) strncpy(strError, "Unknown reader specified.", sizeof(strError));
			break;
		case SCARD_E_TIMEOUT:
			(void) strncpy(strError, "Command timeout.", sizeof(strError));
			break;
		case SCARD_E_SHARING_VIOLATION:
			(void) strncpy(strError, "Sharing violation.", sizeof(strError));
			break;
		case SCARD_E_NO_SMARTCARD:
			(void) strncpy(strError, "No smart card inserted.", sizeof(strError));
			break;
		case SCARD_E_UNKNOWN_CARD:
			(void) strncpy(strError, "Unknown card.", sizeof(strError));
			break;
		case SCARD_E_CANT_DISPOSE:
			(void) strncpy(strError, "Cannot dispose handle.", sizeof(strError));
			break;
		case SCARD_E_PROTO_MISMATCH:
			(void) strncpy(strError, "Card protocol mismatch.", sizeof(strError));
			break;
		case SCARD_E_NOT_READY:
			(void) strncpy(strError, "Subsystem not ready.", sizeof(strError));
			break;
		case SCARD_E_INVALID_VALUE:
			(void) strncpy(strError, "Invalid value given.", sizeof(strError));
			break;
		case SCARD_E_SYSTEM_CANCELLED:
			(void) strncpy(strError, "System cancelled.", sizeof(strError));
			break;
		case SCARD_F_COMM_ERROR:
			(void) strncpy(strError, "RPC transport error.", sizeof(strError));
			break;
		case SCARD_F_UNKNOWN_ERROR:
			(void) strncpy(strError, "Unknown error.", sizeof(strError));
			break;
		case SCARD_E_INVALID_ATR:
			(void) strncpy(strError, "Invalid ATR.", sizeof(strError));
			break;
		case SCARD_E_NOT_TRANSACTED:
			(void) strncpy(strError, "Transaction failed.", sizeof(strError));
			break;
		case SCARD_E_READER_UNAVAILABLE:
			(void) strncpy(strError, "Reader is unavailable.", sizeof(strError));
			break;
		case SCARD_E_PCI_TOO_SMALL:
			(void) strncpy(strError, "PCI struct too small.", sizeof(strError));
			break;
		case SCARD_E_READER_UNSUPPORTED:
			(void) strncpy(strError, "Reader is unsupported.", sizeof(strError));
			break;
		case SCARD_E_DUPLICATE_READER:
			(void) strncpy(strError, "Reader already exists.", sizeof(strError));
			break;
		case SCARD_E_CARD_UNSUPPORTED:
			(void) strncpy(strError, "Card is unsupported.", sizeof(strError));
			break;
		case SCARD_E_NO_SERVICE:
			(void) strncpy(strError, "Service not available.", sizeof(strError));
			break;
		case SCARD_E_SERVICE_STOPPED:
			(void) strncpy(strError, "Service was stopped.", sizeof(strError));
			break;
		case SCARD_E_NO_READERS_AVAILABLE:
			(void) strncpy(strError, "Cannot find a smart card reader.", sizeof(strError));
			break;
		case SCARD_W_UNSUPPORTED_CARD:
			(void) strncpy(strError, "Card is not supported.", sizeof(strError));
			break;
		case SCARD_W_UNRESPONSIVE_CARD:
			(void) strncpy(strError, "Card is unresponsive.", sizeof(strError));
			break;
		case SCARD_W_UNPOWERED_CARD:
			(void) strncpy(strError, "Card is unpowered.", sizeof(strError));
			break;
		case SCARD_W_RESET_CARD:
			(void) strncpy(strError, "Card was reset.", sizeof(strError));
			break;
		case SCARD_W_REMOVED_CARD:
			(void) strncpy(strError, "Card was removed.", sizeof(strError));
			break;
		case SCARD_E_UNSUPPORTED_FEATURE:
			(void) strncpy(strError, "Feature not supported.", sizeof(strError));
			break;
	};

	/* add a null byte */
	strError[sizeof(strError) - 1] = '\0';

	return strError;
}



void usage()
{
	puts("ram-client [option] <URL>\n");
	puts("  -r, --reader         Select reader name");
	puts("  -l, --list-readers   List available card readers");
	puts("  -v, --verbose        Tell us what you do");
}



void decodeArgs(int argc, char **argv)
{
	argv++;
	argc--;

	while (argc--) {
		if (!strcmp(*argv, "--reader") || !strcmp(*argv, "-r")) {
			if (argc < 0) {
				printf("Argument for --reader missing\n");
				exit(1);
			}
			argv++;
			optReader = *argv;
			argc--;
		} else if (!strcmp(*argv, "--pin") || !strcmp(*argv, "-p")) {
			if (argc < 0) {
				printf("Argument for --pin missing\n");
				exit(1);
			}
			argv++;
			optPin = *argv;
			if (strlen(optPin) > 16) {
				printf("PIN length must not exceed 16 digits\n");
				exit(1);
			}
			argc--;
		} else if (!strcmp(*argv, "--list-readers") || !strcmp(*argv, "-l")) {
			optListReaders = 1;
		} else if (!strcmp(*argv, "--verbose") || !strcmp(*argv, "-v")) {
			optVerbose = 1;
		} else if (**argv == '-') {
			printf("Unknown argument %s\n", *argv);
			usage();
			exit(1);
		} else {
			optURL = *argv;
		}
		argv++;
	}
}



#define bcddigit(x) ((x) >= 10 ? 'A' - 10 + (x) : '0' + (x))



static void decodeBCDString(unsigned char *Inbuff, int len, char *Outbuff) {
	while (len--) {
		*Outbuff++ = bcddigit(*Inbuff >> 4);
		*Outbuff++ = bcddigit(*Inbuff & 15);
		Inbuff++;
	}
	*Outbuff++ = '\0';
}



static void dumpCAPDU(unsigned char *capdu, size_t len) {
	char *msg = alloca(len * 2 + 10);

	if (msg == NULL)
		return;

	strcpy(msg, "C: ");
	decodeBCDString(capdu, len, msg + strlen(msg));
	puts(msg);
}



static void dumpRAPDU(unsigned char *rapdu, size_t len) {
	char *msg = alloca(len * 2 + 10);

	if (msg == NULL)
		return;

	strcpy(msg, "R: ");
	decodeBCDString(rapdu, len, msg + strlen(msg));
	puts(msg);
	fflush(stdout);
}



static void dumpATR(unsigned char *atr, size_t len) {
	char *msg = alloca(len * 2 + 10);

	if (msg == NULL)
		return;

	strcpy(msg, "ATR: ");
	decodeBCDString(atr, len, msg + strlen(msg));
	puts(msg);
	fflush(stdout);
}



static int sendApdu(struct ramContext *ctx, unsigned char *capdu, size_t clen, unsigned char *rapdu, size_t *rlen) {
	struct localContext *lctx = (struct localContext *)ramGetUserObject(ctx);
	LONG scrc;
	DWORD lenr;

	if (optVerbose)
		dumpCAPDU(capdu, clen);

	lenr = *rlen;

	scrc = SCardTransmit(lctx->card, SCARD_PCI_T1, capdu, clen, NULL, rapdu, &lenr);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Error during card communication (%s)\n", pcsc_error_to_string(scrc));
		ramForceClose(ctx, pcsc_error_to_string(scrc));
		return RAME_CARD_ERROR;
	} else {
		if (optVerbose)
			dumpRAPDU(rapdu, lenr);
	}

	*rlen = lenr;

	return 0;
}



static int notify(struct ramContext *ctx, int msgid, char *msg) {
	printf("(%d) %s\n", msgid, msg);
	fflush(stdout);
	return 0;
}



static int reset(struct ramContext *ctx, unsigned char *atr, size_t *alen) {
	struct localContext *lctx = (struct localContext *)ramGetUserObject(ctx);
	DWORD dwActiveProtocol,atrlen, readernamelen, state, protocol;
	LONG scrc;

	SCardDisconnect(lctx->card, SCARD_UNPOWER_CARD);
	scrc = SCardConnect(lctx->scardContext, lctx->reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &lctx->card, &dwActiveProtocol);

	if (scrc != SCARD_S_SUCCESS) {
		ramForceClose(ctx, pcsc_error_to_string(scrc));
		return RAME_CARD_ERROR;
	}

	atrlen = *alen;
	SCardStatus(lctx->card, NULL, &readernamelen, &state, &protocol, atr, &atrlen);
	*alen = atrlen;

	if (optVerbose)
		dumpATR(atr, atrlen);

	return 0;
}



static unsigned char select_apdu[] = { 0x00, 0xA4, 0x04, 0x0C, 0x0B, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01 };

static void verifyPIN(SCARDHANDLE card) {
	LONG scrc;
	DWORD lenr;
	unsigned char capdu[32];
	unsigned char rapdu[16];

	lenr = sizeof(rapdu);
	scrc = SCardTransmit(card, SCARD_PCI_T1, select_apdu, sizeof(select_apdu), NULL, rapdu, &lenr);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Error during card communication (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	if ((lenr != 2) || (rapdu[0] != 0x90) || (rapdu[1] != 0x00)) {
		printf("Not a SmartCard-HSM. Skipping PIN verification.\n");
		return;
	}

	capdu[0] = 0x00;
	capdu[1] = 0x20;
	capdu[2] = 0x00;
	capdu[3] = 0x81;
	capdu[4] = strlen(optPin);
	memcpy(capdu + 5, optPin, capdu[4]);

	lenr = sizeof(rapdu);
	scrc = SCardTransmit(card, SCARD_PCI_T1, capdu, capdu[4] + 5, NULL, rapdu, &lenr);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Error during card communication (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	if ((lenr != 2) || (rapdu[0] != 0x90) || (rapdu[1] != 0x00)) {
		printf("PIN verification failed with SW1/SW2 = %02X%02X.\n", rapdu[0], rapdu[1]);
		exit(1);
	}
}



int main(int argc, char **argv)
{
	struct ramContext *ctx;
	struct localContext lctx;
	DWORD cch = 0;
	DWORD dwActiveProtocol;
	LPTSTR readers = NULL;
	LPTSTR p;
	DWORD atrlen, readernamelen, state, protocol;
	unsigned char atr[36];
	LONG scrc;
	int rc;

	decodeArgs(argc, argv);

	scrc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &lctx.scardContext);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Could not establish context to PC/SC manager (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	scrc = SCardListReaders(lctx.scardContext, NULL, NULL, &cch);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Could not list readers (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	readers = calloc(cch, 1);

	scrc = SCardListReaders(lctx.scardContext, NULL, readers, &cch);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Could not list readers (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	if (!optReader)
		optReader = readers;

	p = readers;
	while (*p != '\0') {
		if (optListReaders)
			printf("%s\n", p);

		if (!strncmp(optReader, p, strlen(optReader)))
			optReader = p;

		p += strlen(p) + 1;
	}

	lctx.reader = optReader;

	scrc = SCardConnect(lctx.scardContext, lctx.reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &lctx.card, &dwActiveProtocol);

	if (scrc) {
		printf("Could not connect to card (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	readernamelen = 0;
	atrlen = sizeof(atr);
	scrc = SCardStatus(lctx.card, NULL, &readernamelen, &state, &protocol, atr, &atrlen);

	if (scrc != SCARD_S_SUCCESS) {
		printf("Could not query card status (%s)\n", pcsc_error_to_string(scrc));
		exit(1);
	}

	if (optPin != NULL) {
		verifyPIN(lctx.card);
	}

	if (optURL != NULL) {
		ramNewContext(&ctx);
		ramSetSendApduHandler(ctx, sendApdu);
		ramSetNotifyHandler(ctx, notify);
		ramSetResetHandler(ctx, reset);
		ramSetUserObject(ctx, (void *)&lctx);
		ramSetURL(ctx, optURL);
		ramSetATR(ctx, atr, atrlen);
		rc = ramConnect(ctx);
		ramFreeContext(&ctx);
	} else {
		printf("No URL defined\n");
		rc = 0;
	}

	SCardDisconnect(lctx.card, SCARD_UNPOWER_CARD);
	SCardReleaseContext(lctx.scardContext);

	switch(rc) {
	case RAME_OK:
		printf("Completed\n");
		break;
	case RAME_OUT_OF_MEMORY:
		printf("Out of memory error\n");
		break;
	case RAME_INVALID_TLV:
		printf("Invalid TLV encoding in request from server\n");
		break;
	case RAME_INVALID_REQ:
		printf("Server request invalid. Is the server URL a valid RAMOverHTTP end-point ?\n");
		break;
	case RAME_CARD_ERROR:
		printf("Card communication error\n");
		break;
	case RAME_HOST_NOT_FOUND:
		printf("Host not found\n");
		break;
	case RAME_INVALID_URL:
		printf("URL is invalid or not found on server\n");
		break;
	case RAME_CONNECT_FAILED:
		printf("Connection to host failed\n");
		break;
	case RAME_CURL_ERROR:
		printf("Networking error\n");
		break;
	case RAME_NO_CONNECT:
		printf("Server did not initiate connection to card. See server log for details\n");
		break;
	case RAME_SERVER_ABORT:
		printf("Server aborted connection to card. See server log for details\n");
		break;
	case RAME_HTTP_CODE:
		printf("Server send unexpected HTTP code\n");
		break;
	default:
		printf("Error %d\n", rc);
		break;
	}

	exit(rc == 0 ? 0 : 1);
}

