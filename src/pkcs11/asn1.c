/**
 * SmartCard-HSM PKCS#11 Module
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
 * @file    asn1.c
 * @author  Andreas Schwier
 * @brief   Encoding and decoding for TLV structures
 */

#include <string.h>
#include <assert.h>

#include <pkcs11/asn1.h>
#include "bytebuffer.h"



/**
 * Decode the tag from an ASN.1 object and update the reference pointer
 *
 * Decode the tag value from the ASN.1 coded data object referenced by the parameter
 * Ref. One and two byte tag values are supported. See asn1Length() function call for
 * an example.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  length field.
 *
 * @return          The function returns the tag value for the ASN.1 data object.
 */
unsigned int asn1Tag(unsigned char **Ref)
{
	unsigned int rc;

	rc = *(*Ref)++;

	if ((rc & 0x01F) == 0x1F) {
		do	{
			rc = (rc << 8) + *(*Ref)++;
		} while (rc & 0x80);
	}

	return rc;
}



/**
 * Decode the length from an ASN.1 object and update the reference pointer.
 *
 * Decode the length value from the ASN.1 coded data object referenced by the pa-
 * rameter Ref. One, two and three byte length values are supported. A prior call of
 * asn1Tag() should have moved the pointer Ref to the length field of the TLV object.
 *
 * Note: Usually asn1Tag() and asn1Length() are used directly after another, even if the
 * length information is not of interest. But this is the only safe way to get to the data field,
 * because the tag and length fields may have a variable size.
 *
 * @param Ref       Address of the pointer variable which points to the length field
 *                  of the TLV structure. It gets updated by the function to point to
 *                  the value field.
 *
 * @return          The function returns the length value for the ASN.1 data object.
 *
 * Example: Decode an ASN.1 data object.
 *
 * \code
 * unsigned char ASN1[] = { 0x5F,0x10,0x02,0x20,0x30 };     // Tag=5F10, Length=2
 * unsigned char *po;
 * int  len;
 *
 * po = ASN1;
 * prnPrintf("Tag = %x\n", asn1Tag(&po));
 *
 * len = asn1Length(&po);
 * prnPrintf("Length = %d\n", len);
 *
 * prnPrintf("Value =");
 * while(len--)
 *     prnPrintf(" %02X", *po++);
 * \endcode
 */
int asn1Length(unsigned char **Ref)
{
	int l,c;

	l = *(*Ref)++;

	if (l & 0x80) {
		c = l & 0x7F;
		if (c == 0) {
			return -1;
		}
		l = 0;
		while(c--) {
			l = (l << 8) | *(*Ref)++;
		}
	}

	return l;
}



/**
 * Construct the ASN.1 tag at referenced memory position.
 *
 * Store the tag according to ASN.1 BER-TLV rules in the message buffer. The function
 * decides whether one or two byte storage is required.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  length field.
 * @param Tag       Tag that shall be stored at position Ref.
 *
 */
void asn1StoreTag(unsigned char **Ref, unsigned short Tag)
{
	if ((Tag & 0x1F00) == 0x1F00)
		*(*Ref)++ = Tag >> 8;
	*(*Ref)++ = Tag & 0xFF;
}



/**
 * Construct the ASN.1 length field at referenced memory position.
 *
 * Store the length according to ASN.1 BER-TLV rules in the message buffer. The func-
 * tion decides whether one, two or three byte of storage is required.
 *
 * @param Ref       Address of the pointer variable which points to the tag field of
 *                  the TLV structure. It gets updated by the function to point to the
 *                  value field.
 * @param Length    Value to be stored in the length field.
 */
void asn1StoreLength(unsigned char **Ref, int Length)
{
	if (Length >= 256) {
		*(*Ref)++ = 0x82;
		*(*Ref)++ = (unsigned char)(Length >> 8);
		*(*Ref)++ = (unsigned char)(Length & 0xFF);
	} else if (Length >= 128) {
		*(*Ref)++ = 0x81;
		*(*Ref)++ = (unsigned char)Length;
	} else
		*(*Ref)++ = (unsigned char)Length;
}



/**
 * Encapsulate the provided message in an ASN.1 TLV structure.
 *
 * This function combines the both functions asn1StoreTag() and asn1StoreLength() and
 * encapsulates the message provided in Msg with an ASN.1 TLV structure.
 *
 * WARNING: Tag and length field will be added to the beginning of the message. Please
 * make sure, that sufficient space is available in the message buffer (maximum 5 addi-
 * tional bytes).
 *
 * @param Tag       The tag that shall be given to the message
 * @param Msg       Pointer to the message buffer which contains the message to
 *                  be encapsulated. The tag and length fields will be added at the
 *                  beginning of this buffer.
 * @param MsgLen    Length of the given message in the Msg buffer
 * @return          The function will return the total number of bytes in the message
 *                  buffer. It is of cause now larger than MsgLen.
 */
int asn1Encap(unsigned short Tag, unsigned char *Msg, int MsgLen)
{
	unsigned char tmpbuf[6], *po;
	int len;

	po = tmpbuf;
	asn1StoreTag(&po, Tag);
	asn1StoreLength(&po, MsgLen);
	len = po - tmpbuf;

	memmove(Msg + len, Msg, MsgLen);
	memmove(Msg, tmpbuf, len);

	return MsgLen + len;
}



/**
 * Append the provided byte string with the given tag
 *
 * @param buf       The byte buffer to which the new TLV object will be appended
 * @param tag       The tag that shall be given to the message
 * @param val       The byte string that becomes the value of the new object
 * @return          The function will return the total number of bytes in the message
 *                  buffer of -1 in case of an overflow.
 */
int asn1Append(bytebuffer buf, unsigned short tag, const bytestring val)
{
	unsigned char tmpbuf[6], *po;
	struct bytestring_s bs = { tmpbuf, 0 };

	po = tmpbuf;
	asn1StoreTag(&po, tag);
	asn1StoreLength(&po, val->len);
	bs.len = po - tmpbuf;
	bbAppend(buf, &bs);
	return bbAppend(buf, val);
}



/**
 * Append the provided byte string with the given tag
 *
 * @param buf       The byte buffer to which the new TLV object will be appended
 * @param tag       The tag that shall be given to the message
 * @param val       The byte string that becomes the value of the new object
 * @return          The function will return the total number of bytes in the message
 *                  buffer of -1 in case of an overflow.
 */
int asn1AppendBytes(bytebuffer buf, unsigned short tag, unsigned char *val, size_t len)
{
	unsigned char tmpbuf[6], *po;
	struct bytestring_s bs = { tmpbuf, 0 };

	po = tmpbuf;
	asn1StoreTag(&po, tag);
	asn1StoreLength(&po, len);
	bs.len = po - tmpbuf;
	bbAppend(buf, &bs);
	bs.val = val;
	bs.len = len;
	return bbAppend(buf, &bs);
}



/**
 * Encapsulate content in the buffer starting at offset with a tag and length
 *
 * @param tag       The tag that shall be given to the message
 * @param buf       The byte buffer containing the prepared message that becomes the
 *                  value of the newly created object
 * @param offset    The offset in the buffer at which to start the wrapping
 * @return          The function will return the total number of bytes in the message
 *                  buffer of -1 in case of an overflow.
 */
int asn1EncapBuffer(unsigned short tag, bytebuffer buf, size_t offset)
{
	unsigned char tmpbuf[6], *po;
	struct bytestring_s bs = { tmpbuf, 0 };

	po = tmpbuf;
	asn1StoreTag(&po, tag);
	asn1StoreLength(&po, buf->len - offset);
	bs.len = po - tmpbuf;

	return bbInsert(buf, offset, &bs);
}



/**
 * Find the TLV object within a TLV structure
 *
 * Scan through the TLV structure an find the object referenced by the path argument.
 * The path argument is a concatenation of tag value which, starting with the outermost
 * tag, describes the full path to the object. The level parameter denotes the number of
 * tags in the path, aka the nested level within the structure.
 *
 * @param data      The TLV data structure
 * @param path      Path to the desired object (List of tags)
 * @param level     Number of tags in the path
 * @return          Pointer to the object or NULL
 *
 * Example:
 * \code
 * asn1Find("\x6F\x04\x40\x02\x12\x34", "\x6F\40", 2);
 * \endcode
 */
unsigned char *asn1Find(unsigned char *data, unsigned char *path, int level)
{
	int d, p, l, datalen;
	unsigned char *obj;

	obj = data;
	d = asn1Tag(&data);
	p = asn1Tag(&path);

	if (d != p)
		return NULL;

	level--;

	while (level) {
		data = obj;
		asn1Tag(&data);
		datalen = asn1Length(&data);
		p = asn1Tag(&path);

		do	{
			obj = data;
			d = asn1Tag(&data);
			l = asn1Length(&data);
			data += l;
			datalen -= data - obj;
		} while ((datalen > 0) && (p != d));

		if ((datalen <= 0) && (p != d))
			return NULL;

		level--;
	}

	return obj;
}



/**
 * Decode the next TLV object
 *
 * Decode the tag and length of the next TLV object and set the value pointer
 * accordingly. The pointer and remaining buffer length is updated by this call.
 *
 * @param ref       Pointer to pointer to first byte of next tag
 * @param reflen    Pointer to variable containing the remaining buffer length
 * @param tag       Pointer to variable updated with the tag value
 * @param length    Pointer to variable updated with the length value
 * @param value     Pointer to a pointer updated with the value field
 * @return          true if further object has been decoded
 */
int asn1Next(unsigned char **ref, int *reflen, int *tag, int *length, unsigned char **value)
{
	unsigned char *base;

	if (*reflen == 0) {
		return 0;
	}
	base = *ref;
	*tag = asn1Tag(ref);
	*length = asn1Length(ref);

	if ((*reflen == -1) && (*tag == 0)) {
		return 0;
	}

	*value = *ref;
	*ref += *length;
	*reflen -= *ref - base;

	return 1;
}



/**
 * Validate a TLV structure, traversing into nested objects recursively
 *
 * @param data the first tag byte
 * @param length the maximum length on the buffer
 * @return 0 if valid, offset with error otherwise
 */
int asn1Validate(unsigned char *data, size_t length)
{
	int ofs;
	int l, rc, tag, tl;
	unsigned char *po;

	if (length < 2) {		// Object must have at least two bytes
		return 1;
	}

	ofs = 0;				// Decode tag
	if ((*(data + ofs) & 0x1F) == 0x1F) {
		do	{				// Decode multi-byte tag
			ofs++;
			if ((ofs >= length) || (ofs > 4)) {
				return ofs;
			}
		} while (*(data + ofs) & 0x80);
	}
	ofs++;

	if (ofs >= length) {	// Length missing
		return ofs;
	}

	l = *(data + ofs);
	ofs++;

	if (l & 0x80) {			// Multi-byte length
		int c = l & 0x7F;
		if (c > 3) {		// No more than 3 byte in length indicator
			return ofs - 1;
		}
		if (c > 0) {		// Finite length
			l = 0;
		} else {			// Undetermined length
			l = -1;
		}
		while (c--) {
			if (ofs >= length) {
				return ofs;
			}
			l = (l << 8) | *(data + ofs);
			ofs++;
		}
	}

	if (ofs + l > length) {
		return length;
	}

	if (l == 0) {
		return 0;
	}

	if (*data & 0x20) {				// Traverse into constructed object
		while(1) {					// Process list of contained TLV objects
			po = data + ofs;

			rc = asn1Validate(po, l);
			if (rc != 0) {
				return ofs + rc;
			}

			tag = asn1Tag(&po);
			tl = asn1Length(&po);
			tl += po - (data + ofs);

			ofs += tl;

			if (l == -1) {
				if ((tag == 0) && (tl == 0)) {
					break;
				}
			} else {
				l -= tl;
				if (l <= 0) {
					break;
				}
			}
		}
	}
	return 0;
}



/**
 * Decode a field of up to 32 bit flags into a long value
 *
 * Flags are stored left aligned, that is the first bit is stored in the MSB of flags
 *
 * @param data the value field
 * @param length the length of the value field
 * @param flags pointer to variable receiving the flags
 */
void asn1DecodeFlags(unsigned char *data, size_t length, unsigned long *flags)
{
	int c = 4;

	*flags = 0;
	while ((c-- > 0) && (length > 0)) {
		*flags |= *data << (c << 3);
		data++;
		length--;
	}
}



/**
 * Encode a field of up to 32 bit flags
 *
 * Flags are stored left aligned, that is the MSB of flags is the first bit stored
 *
 * @param flags the flags
 * @param data the value field
 * @param length the length of the value field
 */
void asn1EncodeFlags(unsigned long flags, unsigned char *data, size_t length)
{
	int c = 4;

	while ((c-- > 0) && (length > 0)) {
		*data = (flags >> (c << 3)) & 0xFF;
		data++;
		length--;
	}
}



/**
 * Decode integer from value field encoded MSB first
 *
 * @param data the value field
 * @param length the length of the value field
 * @param value pointer to variable receiving the value
 */
int asn1DecodeInteger(unsigned char *data, size_t length, int *value)
{
	int c = sizeof(int);

	*value = 0;
	while ((c-- > 0) && (length > 0)) {
		*value = (*value << 8) | *data;
		data++;
		length--;
	}
	if (length > 0) {
		return -1;
	}
	return 0;
}



int asn1EncodeInteger(int value, unsigned char *data, size_t length)
{
	int c, i;
	unsigned char p;

	// Determine number of bytes required to store signed integer
	for (c = sizeof(int); c > 0; c--) {
		p = (value >> ((c - 1) << 3)) & 0xFF;
		if ((p != 0) && (p != 0xFF)) {
			break;
		}
	}

	// Need at least one byte
	if (c == 0) {
		c++;
	}

	// Need additional byte if first bit is set on positive integer
	if ((value > 0) && (p & 0x80)) {
		c++;
	}

	if (c > length) {
		c = length;
	}

	i = c;
	while (i-- > 0) {
		*data++ = (value >> (i << 3)) & 0xFF;
	}

	return c;
}



/**
 * Internal selftest
 */
void testASN1()
{
	unsigned char t1[] = { 0x04, 0x00 };
	unsigned char t2[] = { 0x1F, 0x80 };
	unsigned char t3[] = { 0x1F, 0x80, 0x80, 0x80 };
	unsigned char t4[] = { 0x1F, 0x80, 0x80, 0x00 };
	unsigned char t5[] = { 0x1F, 0x80, 0x80, 0x00, 0x80 };
	unsigned char t6[] = { 0x1F, 0x80, 0x80, 0x00, 0x84 };
	unsigned char t7[] = { 0x1F, 0x80, 0x80, 0x00, 0x81 };
	unsigned char t8[] = { 0x04, 0x01, 0x00 };
	unsigned char t9[] = { 0x04, 0x81, 0x01, 0x00 };
	unsigned char t10[] = { 0x04, 0x82, 0x01 };
	unsigned char t11[] = { 0x04, 0x81, 0x01 };
	unsigned char t12[] = { 0x04, 0x02, 0x01 };
	unsigned char t13[] = { 0x24, 0x03, 0x01, 0x01, 0x01 };
	unsigned char t14[] = { 0x24, 0x00 };
	unsigned char t15[] = { 0x24, 0x01, 0x01 };
	unsigned char t16[] = { 0x24, 0x02, 0x01, 0x01 };
	unsigned char t17[] = { 0x24, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01 };

	assert(asn1Validate(t1, 0) == 1);
	assert(asn1Validate(t1, 1) == 1);
	assert(asn1Validate(t1, sizeof(t1)) == 0);
	assert(asn1Validate(t2, sizeof(t2)) == 2);
	assert(asn1Validate(t3, sizeof(t3)) == 4);
	assert(asn1Validate(t4, sizeof(t4)) == 4);
	assert(asn1Validate(t5, sizeof(t5)) == 0);
	assert(asn1Validate(t6, sizeof(t6)) == 4);
	assert(asn1Validate(t7, sizeof(t7)) == 5);
	assert(asn1Validate(t8, sizeof(t8)) == 0);
	assert(asn1Validate(t9, sizeof(t9)) == 0);
	assert(asn1Validate(t10, sizeof(t10)) == 3);
	assert(asn1Validate(t11, sizeof(t11)) == 3);
	assert(asn1Validate(t12, sizeof(t12)) == 3);
	assert(asn1Validate(t13, sizeof(t13)) == 0);
	assert(asn1Validate(t14, sizeof(t14)) == 0);
	assert(asn1Validate(t15, sizeof(t15)) == 3);
	assert(asn1Validate(t16, sizeof(t16)) == 4);
	assert(asn1Validate(t17, sizeof(t17)) == 0);
}
