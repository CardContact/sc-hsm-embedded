/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2026, CardContact Systems GmbH, Minden, Germany
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
 * @file    keydomain.c
 * @author  Andreas Schwier
 * @brief   Functions for key domain management
 */

#include <common/debug.h>
#include <common/asn1.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/keydomain.h>

#include <pkcs11/token-sc-hsm.h>



static int createKeyDomainObject(int idx, unsigned char *label, int labellen, struct p11Object_t **pObject)
{
	struct p11Object_t *p11o;
	CK_OBJECT_CLASS class = CKO_SC_HSM_KEY_DOMAIN;
	unsigned char id = (unsigned char)idx;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_ID, &id, 1 },
			{ CKA_LABEL, NULL, 0 }
	};

	int len;

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	len = 0;
	addAttribute(p11o, &template[len++]);
	addAttribute(p11o, &template[len++]);

	if (label != NULL) {
		template[len].pValue = label;
		template[len].ulValueLen = labellen;
		addAttribute(p11o, &template[len++]);
	}

	*pObject = p11o;

	FUNC_RETURNS(CKR_OK);
}



static int updateKeyDomainObject(struct p11Object_t *pObject, unsigned char *kdstatus, int kdstatuslen)
{
	CK_ATTRIBUTE template;
	unsigned char zero = 0;
	int rc;

	for (int i = 2; i < 10; i++)
		zero |= kdstatus[i];

	if (zero) {
		template.type = CKA_SC_HSM_KEK_KCV;
		template.pValue = kdstatus + 2;
		template.ulValueLen = 8;

		rc = updateAttribute(pObject, &template);
		if (rc != CKR_OK)
			return rc;
	}

	if (kdstatuslen == 10) {	// DKEK Key Domain
		template.type = CKA_SC_HSM_SHARE_STATUS;
		template.pValue = kdstatus;
		template.ulValueLen = 2;

		rc = updateAttribute(pObject, &template);
		if (rc != CKR_OK)
			return rc;
	} else {			// XKEK Key Domain
		template.type = CKA_SC_HSM_KEY_DOMAIN_UID;
		template.pValue = kdstatus + 10;
		template.ulValueLen = kdstatuslen - 10;

		rc = updateAttribute(pObject, &template);
		if (rc != CKR_OK)
			return rc;
	}
	FUNC_RETURNS(CKR_OK);
}



int enumerateKeyDomains(struct p11Token_t *token)
{
	struct p11Slot_t *slot = token->slot;
	unsigned char kdinfo[64];
	unsigned char kddesc[256];
	unsigned char *label;
	struct p11Object_t *p11KeyDomain;
	int rc,kdinfolen,labellen;
	unsigned short SW1SW2;

	FUNC_CALLED();

	for (int i = 0; i < 256; i++) {
		rc = transmitAPDU(slot, 0x80, 0x52, 0x00, (unsigned char)i,
				0, NULL,
				65536, kdinfo, sizeof(kdinfo), &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(rc, "transmitAPDU failed");
		}

		if (SW1SW2 == 0x6A86 || SW1SW2 == 0x6D00) {
			break;
		}

		if (SW1SW2 == 0x6A88) {
			continue;
		}

		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(-1, "Token did not enumerate objects");
		}

		if (rc < 10) {
			FUNC_FAILS(-1, "Key domain info too short");
		}

		kdinfolen = rc;
		label = NULL;
		labellen = 0;

		rc = sc_hsm_readEF(slot, (KD_PREFIX << 8) | i, kddesc, sizeof(kddesc));
		if (rc > 0 && asn1Validate(kddesc, rc) == 0) {
			label = asn1Find(kddesc, (unsigned char *)"\x30\x30\x0C", 3);
			if (label != NULL) {
				asn1Tag(&label);
				labellen = asn1Length(&label);
			}
		}

		rc = createKeyDomainObject(i, label, labellen, &p11KeyDomain);

		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Could not create key domain object");
		}

		rc = updateKeyDomainObject(p11KeyDomain, kdinfo, kdinfolen);

		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Could not update key domain object");
		}

		addObject(token, p11KeyDomain, TRUE);
	}

	FUNC_RETURNS(CKR_OK);
}

