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
 * @file sc-hsm-ultralite-sample.c
 * @author Keith Morgan, Christoph Brunhuber
 */

#ifdef _WIN32
#ifdef DEBUG
#include <crtdbg.h>
#endif
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include "ext-win/dirent.h"
#define snprintf _snprintf
#else
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#define MAX_PATH PATH_MAX
#endif

#include <ctccid/ctapi.h>
#include "utils.h"
#include "sc-hsm-ultralite.h"
#include "metadata.h"

extern int SC_Open(const char *pin);
extern int SC_ReadFile(int ctn, uint16 fid, int off, uint8 *data, int dataLen);

unsigned int sign_file(const char* pin, const char* label, const char* path, const char* md_path)
{
	int n, rc;
	sha256_context ctx;
	const uint8 *pCms = 0;
	unsigned char buf[4096], hash[32];
	char new_sig_path[MAX_PATH];
	unsigned int hcl = 0;
	FILE* fp;

	/* Open the file for reading */
	fp = fopen(path, "rb");
	if (!fp) {
		printf("Error opening file'%s'\n", path);
		return -1;
	}

	/* Create a SHA-256 hash of the file */
	sha256_starts(&ctx);
	for (;;) {
		int n = fread(buf, 1, sizeof(buf), fp);
		if (n <= 0)
			break;
		hcl += n;
		sha256_update(&ctx, buf, n);
	}
	sha256_finish(&ctx, hash);

	/* Sign the hash with the token */
	rc = sign_hash(pin, label, hash, sizeof(hash), &pCms);
	if (rc <= 0) {
		printf("ERROR sign_hash returned %d\n", rc);
		return -1;
	}

	/* Write the signature to file */
	n = snprintf(new_sig_path, sizeof(new_sig_path), "%s.%d.p7s", path, hcl);
	if (n < 0 || n >= sizeof(new_sig_path)) {
		printf("ERROR constructing new sig path '%s.%d.p7s'\n", path, hcl);
		return -1;
	}
	SaveToFile(new_sig_path, pCms, rc);
	printf("'%s' sig file created/updated\n", new_sig_path);

	/* Create (or update) the metadata file with the new hashed content length */
	if (write_metadata(md_path, hcl) != 0)
		printf("'%s' ERROR writing metadata file '%s'\n", path, md_path);

	return hcl;
}

void sign_all_files(const char* pin, const char* label, const char* path)
{
	int n, err;
    DIR* dir;
    struct dirent* entry;
	const char* ext;
	struct stat entry_info, old_sig_info;
	char entry_path[MAX_PATH], md_path[PATH_MAX], old_sig_path[PATH_MAX];
	metadata_t md;
	unsigned int new_sig_hcl;

    /* Open directory stream */
    dir = opendir(path);
    if (dir == NULL) {
		int e = errno;
		printf("Error opening path '%s': %s\n", path, strerror(e));
		return;
	}

	/* Loop through each entry in the specified path */
    while ((entry = readdir(dir)) != NULL) {

		/* Skip "./" "../" and hidden files that begin with '.' */
		if (entry->d_name[0] == '.')
			continue;

		/* Create the full path to the entry */
		n = snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);
		if (n < 0 || n >= sizeof(entry_path)) {
			printf("ERROR constructing entry path for %s/%s\n", path, entry->d_name);
			continue;
		}

		/* Recursively call this function on sub-directories */
		if (entry->d_type == DT_DIR) {
			sign_all_files(pin, label, entry_path);
			continue;
		}

		/* Skip any .p7s files  TODO: delete any orphaned .p7s files*/
		ext = strrchr(entry->d_name, '.');
		if (ext && (strcmp(ext, ".p7s") == 0))
			continue;

		/* Stat the entry */
		if (stat(entry_path, &entry_info) == -1) {
			int e = errno;
			printf("ERROR opening file '%s': %s\n", entry_path, strerror(e));
			continue;
		}

		/* Get the metadata from the previous signing (from the .<filename> hidden metadata file) */
		n = snprintf(md_path, sizeof(md_path), "%s/.%s", path, entry->d_name);
		if (n < 0 || n >= sizeof(md_path)) {
			printf("ERROR constructing metadata path '%s/.%s'\n", path, entry->d_name);
			continue;
		}
		err = read_metadata(md_path, &md);

		/* Recreate the old (existing) signature filename */
		n = snprintf(old_sig_path, sizeof(old_sig_path), "%s/%s.%d.p7s", path, entry->d_name, md.hashed_content_len);
		if (n < 0 || n >= sizeof(md_path)) {
			printf("ERROR constructing old sig path '%s/%s.%d.p7s'\n", path, entry->d_name, md.hashed_content_len);
			continue;
		}

		/* Create a new signature (if necessary) */
		if (!err) { /* If a sig metadata file was found */

			/* stat the old sig file to make sure it still exists */
			err = stat(old_sig_path, &old_sig_info);

			/* If the sig file still exists & the content file is unmodified just keep the old signature and continue */
			if (!err) {
				if (entry_info.st_size == md.hashed_content_len) {
					printf("'%s' file is unmodified\n", entry_path);
					continue;
				}
				printf("'%s' file is modified\n", entry_path);
			} else {
				/* If the signature file no longer exists, log an error */
				printf("'%s' sig file missing!\n", old_sig_path);
			}

			/* If the content file is shrinking, log an error */
			if (entry_info.st_size < md.hashed_content_len)
				printf("'%s' file is shrinking!\n", entry_path);

			/* Now create a new signature file */
			new_sig_hcl = sign_file(pin, label, entry_path, md_path);

			/* If no error occurred, delete the old signature file (but ONLY if it has a new name i.e. different hashed content len!) */
			if (new_sig_hcl > 0 && new_sig_hcl != md.hashed_content_len) {
				err = remove(old_sig_path);
				if (err) {
					int e = errno;
					printf("'%s' ERROR deleting old sig file '%s': %s\n", entry_path, old_sig_path, strerror(e));
				} else {
					printf("'%s' sig file (old) deleted\n", old_sig_path);
				}
			}

		} else { /* otherwise no metadata file was found (or an error occurred while reading the metadata file) */
			/* So create a new signature file (either no signature file exists yet or it has to be recreated) */
			printf("'%s' file is not signed\n", entry_path);
			sign_file(pin, label, entry_path, md_path);
		}
    }

	/* Close the directory stream */
    closedir(dir);
}

int main(int argc, char** argv)
{
	const char * pin, * label, * path;
	struct stat info;

	/* Check args */
	if (argc != 4) {
		printf("Usage: %s <pin> <label> <path>\n", argv[0]);
		return 1;
	}
	pin = argv[1];
	label = argv[2];
	path = argv[3];

	/* Verify the specified folder exists */
	if (stat(path, &info) == -1) {
		int e = errno;
		printf("Could not find path '%s': %s\n", path, strerror(e));
		return e;
	}

	/*
	 * TODO: Create a mutex for controlling access to token.
	 * NOTE: Only necessary for simultaneous access to token.
	 */

	/* Sign all files in the specified directory */
	sign_all_files(pin, label, path);

	/* Clean up */
	release_template();

	/* TODO: Destroy mutex */

#if defined(_WIN32) && defined(DEBUG)
	_CrtDumpMemoryLeaks();
#endif
	return 0;
}
