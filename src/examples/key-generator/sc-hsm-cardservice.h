/**
 * Mini card service for key generator
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
 * @file sc-hsm-cardservice.h
 * @author Andreas Schwier
 * @brief Minimal card service for key generator
 */

void setDebugLevel(int level);

int processAPDU(int ctn, int todad,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2);

int selectHSM(int ctn);
int initializeDevice(int ctn, unsigned char *sopin, int sopinlen, unsigned char *pin, int pinlen);
int queryPIN(int ctn);
int verifyPIN(int ctn, unsigned char *pin, int pinlen);
int changePIN(int ctn, unsigned char *oldpin, int oldpinlen, unsigned char *newpin, int newpinlen);
int generateSymmetricKey(int ctn, unsigned char id, unsigned char *algo, int algolen);
int writeKeyDescription(int ctn, unsigned char id, unsigned char *desc, int desclen);
int deriveKey(int ctn, unsigned char id, unsigned char *label, int labellen, unsigned char *keybuff, int keybufflen);
