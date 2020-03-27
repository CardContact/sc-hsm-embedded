/**
 * Key generator with CT-API for boot level integration
 *
 * Copyright (c) 2020, CardContact Systems GmbH, Minden, Germany
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
 * @file key-generator.c
 * @author Andreas Schwier
 * @brief Key generator with CT-API for boot level integration
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctccid/ctapi.h>

#include "sc-hsm-cardservice.h"

static unsigned char requesticc[] = {0x20,0x12,0x00,0x01,0x00};

// Generated as PKCS#15 Secret Key Description structure in pinmgnt.js
static unsigned char skd_dskkey[] = { 0xA8,0x2F,0x30,0x13,0x0C,0x11,0x44,0x69,0x73,0x6B,0x45,0x6E,0x63,0x72,0x79,0x70,0x74,0x69,0x6F,0x6E,0x4B,0x65,0x79,0x30,0x08,0x04,0x01,0x01,0x03,0x03,0x07,0xC0,0x10,0xA0,0x06,0x30,0x04,0x02,0x02,0x00,0x80,0xA1,0x06,0x30,0x04,0x30,0x02,0x04,0x00 };

static unsigned char algo_dskkey[] = { 0x91,0x01,0x99 };


static int optInit = 0;
static char *optPin = NULL;
static char *optTransportPin = NULL;
static char *optSOPin = "57621880";
static char *optLabel = "Disk1";
static char *optPairingSecret = NULL;



/*
 * Dump the memory pointed to by <mem>
 *
 */
static void dump(unsigned char *mem, int len)
{
	while(len--) {
		printf("%02x", *mem);
		mem++;
	}

	printf("\n");
}



/*
 * Request card
 *
 */
static int requestICC(int ctn)
{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(requesticc), (unsigned char *) &requesticc, &lr, Brsp);

#ifdef DEBUG
	printf("ATR: ");
	dump(Brsp, lr);
#endif

	if((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		fprintf(stderr, "No card present or card reset error\n");
		return -1;
	}

	return 0;
}



/**
 * Initialize SmartCard-HSM
 *
 * @param ctn the card terminal number
 * @return < 0 for error or 0
 */
static int initialize(int ctn)
{
	char tpin[16];
	char sopin[16];
	int rc;

	if (optTransportPin == NULL) {
		printf("Enter transport PIN: ");

		if (fgets(tpin, sizeof(tpin), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			return -1;
		}

		tpin[strlen(tpin) - 1] = 0;
	} else {
		strcpy(tpin, optTransportPin);
	}

	rc = initializeDevice(ctn, (unsigned char *)optSOPin, strlen(optSOPin), (unsigned char *)tpin, strlen(tpin));

	return rc;
}



/**
 * Produce a key value by derivation from the master key
 *
 * @param ctn the card terminal number
 * @return < 0 for error or 0
 */
static int produceKey(int ctn)
{
	int rc;
	unsigned char diskkey[32];

	rc = deriveKey(ctn, 1, optLabel, strlen(optLabel), diskkey, sizeof(diskkey));

	if (rc < 0) {
		return rc;
	}

	dump(diskkey, sizeof(diskkey));
	memset(diskkey, 0, sizeof(diskkey));

	return 0;
}



/**
 * Report the status of the PIN
 *
 * @param sw the SW1/SW2 status word returned by the VERIFY or CHANGE REFERENCE DATA command
 */
static void reportPinStatus(int sw) {
	switch(sw) {
	case 0x6700:
		printf("Wrong PIN length. Pairing secret missing ?\n");
		break;
	case 0x6983:
		printf("PIN blocked\n");
		break;
	case 0x6984:
		printf("PIN in transport state\n");
		break;
	default:
		if ((sw & 0x63C0) == 0x63C0) {
			int rc = sw & 0xF;

			if (rc > 1) {
				printf("PIN wrong, %d tries remaining\n", rc);
			} else {
				printf("PIN wrong, one try remaining\n", rc);
			}
		}
	}
}



/**
 * Install token is the process of changing the transport PIN and creating the master secret
 *
 * @param ctn the card terminal number
 * @return < 0 for error or 0
 */
static int install(int ctn)
{
	char tpin[16];
	char npin[16];
	unsigned char newcode[16];
	int ofs, rc;

	if (optTransportPin == NULL) {
		printf("Enter transport PIN: ");

		if (fgets(tpin, sizeof(tpin), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			return -1;
		}

		tpin[strlen(tpin) - 1] = 0;
	} else {
		strcpy(tpin, optTransportPin);
	}

	if (optPin == NULL) {
		printf("Enter new User PIN : ");

		if (fgets(npin, sizeof(npin), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			return -1;
		}

		npin[strlen(npin) - 1] = 0;
	} else {
		strcpy(npin, optPin);
	}

	ofs = 0;
	if (optPairingSecret != NULL) {
		int len = strlen(optPairingSecret);

		if (len + strlen(npin) > 16) {
			fprintf(stderr, "PIN too long\n");
			return -1;
		}

		memcpy(newcode, optPairingSecret, len);
		ofs = len;
	}

	memcpy(newcode + ofs, (unsigned char *)npin, strlen(npin));
	ofs += strlen(npin);

	rc = changePIN(ctn, (unsigned char *)tpin, strlen(tpin), newcode, ofs);

	memset(tpin, 0, sizeof(tpin));
	memset(npin, 0, sizeof(npin));
	memset(newcode, 0, sizeof(newcode));

	if (rc < 0) {
		return rc;
	}

	if (rc != 0x9000) {
		reportPinStatus(rc);
		return -1;
	}

	rc = generateSymmetricKey(ctn, 1, algo_dskkey, sizeof(algo_dskkey));

	if (rc < 0) {
		return rc;
	}

	rc = writeKeyDescription(ctn, 1, skd_dskkey, sizeof(skd_dskkey));

	return rc;
}



/**
 * Perform user authentication, potentially including the pairing secret
 *
 * @param ctn the card terminal number
 * @return < 0 for error or 0
 */
static int authenticateUser(int ctn)
{
	int rc, ofs;
	char pin[16];
	unsigned char code[16];

	if (optPin == NULL) {
		printf("Enter User PIN: ");

		if (fgets(pin, sizeof(pin), stdin) == NULL) {
			fprintf(stderr, "Input aborted\n");
			return -1;
		}
		pin[strlen(pin) - 1] = 0;
	} else {
		strcpy(pin, optPin);
	}

	ofs = 0;
	if (optPairingSecret != NULL) {
		int len = strlen(optPairingSecret);
		memcpy(code, optPairingSecret, len);
		ofs = len;
	}

	memcpy(code + ofs, (unsigned char *)pin, strlen(pin));
	ofs += strlen(pin);

	rc = verifyPIN(ctn, code, ofs);

	memset(pin, 0, sizeof(pin));
	memset(code, 0, sizeof(code));

	if (rc != 0x9000) {
		reportPinStatus(rc);
		return -1;
	}

	return 0;
}



/**
 * Decode command line arguments
 *
 */
void decodeArgs(int argc, char **argv)
{
	argv++;
	argc--;

	while (argc--) {
		if (!strcmp(*argv, "--pin")) {
			if (argc < 0) {
				fprintf(stderr, "Argument for --pin missing\n");
				exit(1);
			}
			argv++;
			if (strlen(*argv) > 16) {
				fprintf(stderr, "Argument for --pin too long\n");
				exit(1);
			}
			optPin = *argv;
			argc--;
		} else if (!strcmp(*argv, "--transportpin")) {
			if (argc < 0) {
				fprintf(stderr, "Argument for --transportpin missing\n");
				exit(1);
			}
			argv++;
			if (strlen(*argv) > 16) {
				fprintf(stderr, "Argument for --transportpin too long\n");
				exit(1);
			}
			optTransportPin = *argv;
			argc--;
		} else if (!strcmp(*argv, "--sopin")) {
			if (argc < 0) {
				fprintf(stderr, "Argument for --sopin missing\n");
				exit(1);
			}
			argv++;
			if (strlen(*argv) != 8) {
				fprintf(stderr, "Argument for --sopin must be 8 character long\n");
				exit(1);
			}
			optSOPin = *argv;
			argc--;
		} else if (!strcmp(*argv, "--label")) {
			if (argc < 0) {
				fprintf(stderr, "Argument for --label missing\n");
				exit(1);
			}
			argv++;
			if (strlen(*argv) > 32) {
				fprintf(stderr, "Argument for --label too long\n");
				exit(1);
			}
			optLabel = *argv;
			argc--;
		} else if (!strcmp(*argv, "--pairingsecret")) {
			if (argc < 0) {
				fprintf(stderr, "Argument for --pairingsecret missing\n");
				exit(1);
			}
			argv++;
			if (strlen(*argv) > 16) {
				fprintf(stderr, "Argument for --pairingsecret too long\n");
				exit(1);
			}
			optPairingSecret = *argv;
			argc--;
		} else if (!strcmp(*argv, "--init")) {
			optInit = 1;
		} else {
			fprintf(stderr, "Invalid argument %s\n\n", *argv);

			fprintf(stderr, "Usage: key-generator <options>\n\n");
			fprintf(stderr, "\t--init\t\t\tInitialize SmartCard-HSM\n");
			fprintf(stderr, "\t--pin <value>\t\tSet PIN from command line (Prompted otherwise)\n");
			fprintf(stderr, "\t--transportpin <value>\tSet Transport-PIN from command line (Prompted otherwise)\n");
			fprintf(stderr, "\t--sopin <value>\t\tSet Security-Officer PIN from command line (Using default SO-PIN)\n");
			fprintf(stderr, "\t--label <value>\t\tSet label for key derivation (Using default Disk1)\n");
			fprintf(stderr, "\t--pairingsecret <value>\tDefine a local pairing secret (None)\n\n");
			exit(1);
		}
		argv++;
	}
}



int main(int argc, char **argv)
{
	unsigned int i;
	unsigned short lr;
	int rc, ctn;
	unsigned char readers[4096],*po;

	decodeArgs(argc, argv);

	lr = sizeof(readers);
	CT_list(readers, &lr, 0);

	if (lr <= 0) {
		fprintf(stderr, "No token found.\n");
		exit(1);
	}

	po = readers;
	unsigned short port = *po << 8 | *(po + 1);
	po += 2;

#ifdef DEBUG
	printf("Using token %04x : %s\n", port, po);
#endif

	ctn = 0;

	rc = CT_init(ctn, port);
	requestICC(ctn);

	rc = queryPIN(ctn);

	if (rc != 0x9000) {
		selectHSM(ctn);
		rc = queryPIN(ctn);
	}

	if (optInit) {
		initialize(ctn);
	} else {
		if (rc == 0x6984) {
			install(ctn);
		} else {
			authenticateUser(ctn);
		}
		produceKey(ctn);
	}

	CT_close(ctn);
}
