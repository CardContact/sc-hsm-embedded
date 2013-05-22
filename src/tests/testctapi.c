/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |'**> <**'|  Copyright (c) 1999-2006. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       CT-API Tests
 *
 * Author :         Andreas Schwier
 *
 * Last modified:   2006-02-20
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctccid/ctapi.h>


unsigned char requesticc[5] = {0x20,0x12,0x00,0x01,0x00};
unsigned char getstatus[5] = {0x20,0x13,0x00,0x46,0x00};
unsigned char ejecticc[6] = {0x20,0x15,0x00,0x04,0x00, 5};



int freq[] = { 143, 35, 71, 17, 196, 49, 98, 24, 122, 30, 61, 15 ,0};
int curr[] = { 25, 50, 100, 200 };
char *prot[] = { "T=0",
				 "T=1",
			   };
char *sprot[] = { "SDAP", "3WBP", "2WBP" };





void DecodeATR(unsigned char *atr)

{
	unsigned char td;
	int i;

	if ((*atr == 0x3B) || (*atr == 0x3F)) {
		if (*atr == 0x3B) {
			printf("TS  : %02X  Direct logic\n", *atr);
		} else {
			printf("TS  : %02X  Inverse logic\n", *atr);
		}

		atr++;
		printf("TO  : %02X  K    = %4d byte [historical characters]\n", *atr,
			   *atr & 0x0F);
		td = *atr;
		atr++;

		if (td & 0x10) {
			printf("TA1 : %02X  FI   = %4d      [clock rate conversion factor]\n",
				   *atr, (*atr & 0xF0) >> 4);
			printf("          DI   = %4d      [bit rate conversion factor]\n",
				   *atr & 0x0F);
			atr++;
		}

		if (td & 0x20) {
			printf("TB1 : %02X  pa   = %4d %%    [programming voltage accurancy]\n",
				   *atr, *atr & 0x80 ? 2 : 4);
			printf("          I    = %4d mA   [maximum current]\n",
				   curr[(*atr & 0x60) >> 5]);
			printf("          P    = %4d V    [programming voltage]\n",
				   *atr & 0x0F);
			atr++;
		}

		if (td & 0x40) {
			printf("TC1 : %02X  N    = %4d etu  [extra guardtime]\n",
				   *atr, *atr);
			atr++;
		}

		i = 2;

		while (td & 0x80) {
			printf("TD%d : %02X  T    =  %s      [protocol type]\n",
				   i-1, *atr, prot[*atr & 0x01]);

			td = *atr;
			atr++;

			if ((i > 2) && (td & 0x0F) == 1) {
				if (td & 0x10) {
					printf("TA%d : %02X  IFSC = %4d      [information field size]\n",
						   i, *atr, *atr ? *atr : 256);
					atr++;
				}

				if (td & 0x20) {
					printf("TB%d : %02X  CWT  =%5d etu  [character waiting time]\n",
						   i, *atr, (1 << (*atr &0x0F)) + 11);
					printf("          BWT  =%5d etu  [block waiting time]\n",
						   (1 << (*atr >> 4)) / 10 + 11);
					atr++;
				}

				if (td & 0x40) {
					printf("TC%d : %02X  EDC  = %s     [error detection code]\n",
						   i, *atr, *atr & 1 ? "CRC" : "LRC");
					atr++;
				}
			} else {
				if (td & 0x10) {
					printf("TA%d : %02X  BS   = %4d      [block size]\n",
						   i, *atr, *atr ? *atr : 256);
					atr++;
				}

				if (td & 0x20) {
					printf("TB%d : %02X  P2   = %4.1f Volt [programming voltage]\n",
						   i, *atr, (double)*atr / 10.0);
					atr++;
				}

				if (td & 0x40) {
					printf("TC%d : %02X  W    = %4d      [waiting time adjustment factor]\n",
						   i, *atr, *atr);
					atr++;
				}
			}

			i++;
		}
	} else if ((*atr & 0xCF) == 0x82) {
		i = (*atr & 0xF0) >> 4;
		printf("H1  : %02X  S = %d, %s\n", *atr, i, sprot[i - 8]);

		atr++;
		i = 64 << ((*atr & 0x78) >> 3);

		if (i == 64) {
			i = 0;
		}

		printf("H2  : %02X  Units = %d\n", *atr, i);
		printf("          Unit Size = %d bits\n", 1 << (*atr & 0x07));

		atr++;
		printf("H3  : %02X  Category = %s\n", *atr, *atr == 0x10 ? "Synchronous card" : "Unknown");

		atr++;

		if (*atr & 0x80) {
			printf("H4  : %02X  Dir Reference = %d\n", *atr, *atr & 0x7F);
		} else {
			printf("H4  : %02X\n", *atr);
		}
	}
}



/*
 * MyDump the memory pointed to by <mem>
 *
 */

static void MyDump(unsigned char *mem, int len)
{
	if (len >= 16)
		printf("\n");

	while(len--) {
		printf("%02x ", *mem);
		mem++;
	}

	printf("\n");
}



/*
* Process an ISO 7816 APDU with the underlying terminal hardware.
*
* CLA : Class byte of instruction
* INS : Instruction byte
* P1 : Parameter P1
* P2 : Parameter P2
* OutLen : Length of outgoing data (Lc)
* OutData : Outgoing data or NULL if none
* InLen : Length of incoming data (Le)
* InData : Input buffer for incoming data
* InSize : buffer size
* SW1SW2 : Address of short integer to receive SW1SW2
*
* Returns : < 0 Error > 0 Bytes read
*/
static int ProcessAPDU(int ctn, int todad,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)
{
	int rv, rc, r, retry;
	unsigned short lenr;
	unsigned char dad, sad;
	unsigned char scr[MAX_APDULEN], *po;

	/* Reset status word */
	*SW1SW2 = 0x0000;

	retry = 2;

	while (retry--) {
		scr[0] = CLA;
		scr[1] = INS;
		scr[2] = P1;
		scr[3] = P2;
		po = scr + 4;
		rv = 0;

		if (OutData && OutLen) {
			if ((OutLen <= 255) && (InLen <= 255)) {
				*po++ = (unsigned char)OutLen;
			} else {
				*po++ = 0;
				*po++ = (unsigned char)(OutLen >> 8);
				*po++ = (unsigned char)(OutLen & 0xFF);
			}

			memcpy(po, OutData, OutLen);
			po += OutLen;
		}

		if (InData && InSize) {
			if ((InLen <= 255) && (OutLen <= 255)) {
				*po++ = (unsigned char)InLen;
			} else {
				if (InLen >= 65556) {
					InLen = 0;
				}

				if (!OutData) {
					*po++ = 0;
				}

				*po++ = (unsigned char)(InLen >> 8);
				*po++ = (unsigned char)(InLen & 0xFF);
			}
		}

		sad = HOST;
		dad = todad;
		lenr = sizeof(scr);

		rc = CT_data(ctn, &dad, &sad, po - scr, scr, &lenr, scr);

		if (rc < 0) {
			return rc;
		}

		if (scr[lenr - 2] == 0x6C) {
			InLen = scr[lenr - 1];
			continue;
		}

		rv = lenr - 2;

		if (rv > InSize) {
			rv = InSize;
		}

		if (InData) {
			memcpy(InData, scr, rv);
		}

		if ((scr[lenr - 2] == 0x9F) || (scr[lenr - 2] == 0x61))
			if (InData && InSize) { /* Get Response */
				r = ProcessAPDU(ctn, todad,
						(unsigned char)((CLA == 0xE0) || (CLA == 0x80) ?
								0x00 : CLA), 0xC0, 0, 0,
								0, NULL,
								scr[1], InData + rv, InSize - rv, SW1SW2);

				if (r < 0) {
					return(r);
				}

				rv += r;
			} else {
				*SW1SW2 = 0x9000;
			}
		else {
			*SW1SW2 = (scr[lenr - 2] << 8) + scr[lenr - 1];
		}

		break;
	}

	return(rv);
}



/*
 * Test the REQUEST ICC command
 *
 */

int TestRequestICC(int ctn)

{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);

	printf("- REQUEST ICC for ctn=%d ------------------\n", ctn);

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(requesticc), (unsigned char *) &requesticc, &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	if((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		printf("No card present or error !! \n");
		return -1;
	}

	DecodeATR(Brsp);

	return Brsp[lr - 1] == 0x00 ? 1 : 2;  /* Memory or processor card ? */
}



/*
 * Test the STATUS command
 *
 */

int TestStatus(int ctn)

{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	printf("- STATUS CT (46) for ctn=%d ------------------\n", ctn);

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);
	rc = CT_data((unsigned short)ctn, &dad, &sad, 4, (unsigned char *) "\x20\x13\x00\x46", &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	printf("- STATUS CT (80) for ctn=%d ------------------\n", ctn);

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);
	rc = CT_data((unsigned short)ctn, &dad, &sad, 4, (unsigned char *) "\x20\x13\x00\x80", &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	printf("- STATUS CT (81) for ctn=%d ------------------\n", ctn);

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);
	rc = CT_data((unsigned short)ctn, &dad, &sad, 4, (unsigned char *) "\x20\x13\x00\x81", &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	printf("- STATUS ICC for ctn=%d ------------------\n", ctn);

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);
	rc = CT_data((unsigned short)ctn, &dad, &sad, 4, (unsigned char *) "\x20\x13\x01\x80", &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	return(0);
}



/*
 * Test microprocessor cards (SmartCard-HSM)
 *
 */
int TestProcessorCard(int ctn)

{
	unsigned char Brsp[4096];
	unsigned short SW1SW2;
	int rc;

	printf("\n- SmartCard-HSM: SELECT APPLET for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0xA4,0x04,0x04,
					 11, (unsigned char*)"\xE8\x2B\x06\x01\x04\x01\x81\xC3\x1F\x02\x01",
					 0, Brsp, sizeof(Brsp), &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	if (rc >= 0) {
		MyDump(Brsp, rc);
	}

	printf("\n- SmartCard-HSM: VERIFY STATUS for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0x20,0x00,0x81,
					 0, NULL,
					 0, NULL, 0, &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	printf("\n- SmartCard-HSM: GET CHALLENGE for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0x84,0x00,0x00,
					 0, NULL,
					 8, Brsp, sizeof(Brsp), &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	if (rc >= 0) {
		MyDump(Brsp, rc);
	}

	printf("\n- SmartCard-HSM: VERIFY PIN for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0x20,0x00,0x81,
					 6, (unsigned char *)"648219",
					 0, NULL, 0, &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	printf("\n- SmartCard-HSM: READ EF_DevAut for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0xB1,0x2F,0x02,
					 4, (unsigned char*)"\x54\x02\x00\x00",
					 65536, Brsp, sizeof(Brsp), &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	if (rc >= 0) {
		MyDump(Brsp, rc);
	}

	printf("\n- SmartCard-HSM: UPDATE EF for ctn=%d ------------------\n\n", ctn);

	Brsp[0] = 0x54;
	Brsp[1] = 0x02;
	Brsp[2] = 0x00;
	Brsp[3] = 0x00;
	Brsp[4] = 0x53;
	Brsp[5] = 0x82;
	Brsp[6] = 0x01;
	Brsp[7] = 0x00;

	rc = ProcessAPDU(ctn, 0, 0x00,0xD7,0xEF,0x01,
					 264, Brsp,
					 0, NULL, 0, &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	printf("\n- SmartCard-HSM: GAKP(RSA) for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x00,0x46,0x01,0x00,
					 63, (unsigned char*)"\x5F\x29\x01\x00\x42\x0E\x44\x45\x43\x41\x30\x30\x30\x30\x31\x30\x30\x30\x30\x31\x7F\x49\x15\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02\x82\x03\x01\x00\x01\x02\x02\x08\x00\x5F\x20\x10\x55\x54\x54\x45\x53\x54\x4B\x45\x59\x30\x31\x30\x30\x30\x30\x30",
					 65536, Brsp, sizeof(Brsp), &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	if (rc >= 0) {
		MyDump(Brsp, rc);
	}

	printf("\n- SmartCard-HSM: SIGN for ctn=%d ------------------\n\n", ctn);

	rc = ProcessAPDU(ctn, 0, 0x80,0x68,0x01,0xA0,
					 11, (unsigned char*)"Hello World",
					 0, Brsp, sizeof(Brsp), &SW1SW2);

	printf("rc=%d, SW1SW2=%04X: ", rc, SW1SW2);

	if (rc >= 0) {
		MyDump(Brsp, rc);
	}

	return 0;
}



/*
 * Test EJECT ICC command
 *
 */

int TestEjectICC(int ctn)

{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);

	printf("- EJECT ICC for cnt=%d ------------------\n", ctn);

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(ejecticc), (unsigned char *) &ejecticc, &lr, Brsp);

	printf("\nrc = %d - Print rsp: %d\n", rc, lr);

	MyDump(Brsp, lr);

	if((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		printf("No card present or error !! \n");
		return 0;
	}

	return 0;
}



#define MAXPORT 2

/*
 * cnts stores the status for the card reader
 * -1 no card reader connected
 *  0 card reader connected, no card
 *  1 card reader connected, memory card in
 *  2 card reader connected, microprocessor card in
 *
 */

int main(int argc, char **argv)

{
	unsigned int i;
	int ctns[MAXPORT],rc;

	for (i = 0; i < MAXPORT; i++) {
		ctns[i] = -1;
	}

	for (i = 0; i < MAXPORT; i++) {
		rc = CT_init((unsigned short) i, (unsigned short) i);

		if (rc < 0) {
			printf("\nNo reader found at port %d, rc=%i\n", i, rc);
		} else {
			ctns[i] = 0;
		}
	}

	for (i = 0; i < MAXPORT; i++) {
		if (ctns[i] >= 0) {
			if ((rc = TestStatus(i)) < 0) {
				ctns[i] = -1;
			} else {
				ctns[i] = rc;
			}
		}
	}

	for (i = 0; i < MAXPORT; i++) {
		if (ctns[i] >= 0) {
			if ((rc = TestRequestICC(i)) < 0) {
				ctns[i] = -1;
			} else {
				ctns[i] = rc;
			}
		}
	}

	for (i = 0; i < MAXPORT; i++) {
		if (ctns[i] >= 0) {
			if ((rc = TestProcessorCard(i)) < 0) {
				ctns[i] = -1;
			} else {
				ctns[i] = rc;
			}
		}
	}

	for (i = 0; i < MAXPORT; i++) {
		if (ctns[i] >= 1) {
			TestEjectICC(i);
			ctns[i] = 0;
		}
	}

	for (i = 0; i < MAXPORT; i++) {
		if (ctns[i] >= 0) {
			CT_close((unsigned short)i);
		}
	}

	return 0;
}
