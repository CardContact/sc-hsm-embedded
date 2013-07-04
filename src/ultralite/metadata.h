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
 * @file metadata.c
 * @author Keith Morgan
 */
#ifndef _METADATA_H_
#define _METADATA_H_

#include <stdio.h>

#define METADATA_TYPE 0xABCD /*!< Signature metadata file file type (stored in the file header) */
#define METADATA_VER 100 /*!< Signature metadata file file version (stored in the file header) */

/**
 * Structure for saving the latest hashed content
 * length of a signature to disk. This allows quick
 * retrieval of a file's associated signature
 * without scanning against a regular expression.
 */
typedef struct
{
	int type;
	int ver;
	unsigned int hashed_content_len;
} metadata_t;

/**
 * Write a binary metadata file to disk at the specified path
 * @a path.  The content of the metadata file is exactly one
 * ::metadata_t struct which contains the length of the
 * hashed content covered by the associated signature file.
 * @see ::metadata_t
 * @retval 0 Success.
 * @retval R_EACCES File couldn't be opened for writing.
 * @retval R_EIO I/O error.
 */
int write_metadata(const char* path, unsigned int hashed_content_len)
{
	int n;
	FILE* fp;
	metadata_t md;

	/* Initialize the metadata_t struct with the specified values */
	md.type = METADATA_TYPE;
	md.ver = METADATA_VER;
	md.hashed_content_len = hashed_content_len;

	/* Write the metadata_t struct to the specified path */
	fp = fopen(path, "wb");
	if (!fp)
		return 1;
	n = fwrite(&md, sizeof(metadata_t), 1, fp);
	fclose(fp);
	if (n != 1) /* exactly only one struct metadata_t written */
		return 1;

	return 0;
}

/**
 * Read a binary metadata file from disk at the specified path
 * @a path.  The content of the metadata file is exactly one
 * ::metadata_t struct which contains the length of the
 * hashed content covered by the associated signature file.
 * The data read from disk are put in the ::metadata_t struct
 * @a md which must be allocated by the caller.
 * @see ::metadata_t
 * @return 0 Success.
 * @retval R_EACCES File couldn't be opened for reading.
 * @retval R_EIO I/O error.
 * @return R_EINVAL The type or version of the metadata
 * file read from disk are not compatible with current
 * implementation.
 */
int read_metadata(const char* path, metadata_t* md)
{
	int n;
	FILE* fp;

	/* Read the metadata_t struct from the specified path */
	fp = fopen(path, "rb");
	if (!fp)
		return 1;
	n = fread(md, sizeof(metadata_t), 1, fp);
	fclose(fp);
	if (n != 1) /* exactly only one struct metadata_t read */
		return 1;

	/* Verify the struct read from disk is the correct type & version */
	if (md->type != METADATA_TYPE || md->ver != METADATA_VER) {
		printf("'%s' metadata file has type/ver: %d/%d, but expected: %d/%d",
			path, md->type, md->ver, METADATA_TYPE, METADATA_VER);
		return 1;
	}

	return 0;
}

#endif /* _METADATA_H_ */
