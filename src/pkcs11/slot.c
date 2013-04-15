/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2003. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 *
 * Abstract :       Functions for token management in a specific slot
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    slot.c
 * \author  Frank Thater (fth)
 * \brief   Functions for token management in a specific slot
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef WIN32
#include <io.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#endif

#ifndef _O_RDONLY
#define _O_RDONLY O_RDONLY
#endif

#ifndef _O_BINARY
#define _O_BINARY 0
#endif

#ifndef _S_IREAD
#define _S_IREAD S_IREAD
#endif

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif

#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>

#include <strbpcpy.h>

extern struct p11Context_t *context;

/**
 * addToken adds a token to the specified slot.
 *
 * @param slot       Pointer to slot structure.
 * @param token      Pointer to token structure.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is already a token in the slot   </TD>
 *                   </TR>
 *                   </TABLE></P>
 */

int addToken(struct p11Slot_t *slot, struct p11Token_t *token)

{
    if (slot->token != NULL) {
        return CKR_FUNCTION_FAILED;
    }
            
    slot->token = token;                    /* Add token to slot                */
    slot->info.flags = CKF_TOKEN_PRESENT;   /* indicate the presence of a token */

    return CKR_OK;
}

/**
 * removeToken removes a token from the specified slot.
 *
 * @param slot       Pointer to slot structure.
 * @param token      Pointer to token structure.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is no token in the slot          </TD>
 *                   </TR>
 *                   </TABLE></P>
 */

int removeToken(struct p11Slot_t *slot, struct p11Token_t *token)

{
    
    if (slot->token == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    
    free(slot->token);
 
    slot->info.flags = 0;
 
    slot->token = NULL;

    return CKR_OK;
}

/**
 * checkForToken scans a specific slot for a token.
 *
 * @param slot       Pointer to slot structure.
 * @param token      Pointer to pointer to token structure.
 *                   If a token is found, this pointer holds the specific token structure - otherwise NULL.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>Error opening slot directory           </TD>
 *                   </TR>
 *                   </TABLE></P>
 */

int checkForToken(struct p11Slot_t *slot, struct p11Token_t **token)

{
    struct p11Token_t *ptoken;
    char scr[_MAX_PATH];
    DIR *dir;
    struct dirent *dirent;
    int fh, rc, i;
    
    memset(scr, 0x00, sizeof(scr));

    strcat(scr, context->slotDirectory);
    strcat(scr, "/");
    strcat(scr, slot->slotDir);
    strcat(scr, "/");

    dir = opendir(scr);

#ifdef WIN32
    if (dir->handle == -1) {
        return CKR_GENERAL_ERROR;
    }
#else
    if (dir == NULL) {
            return CKR_GENERAL_ERROR;
    }
#endif

    *token = NULL;

    while((dirent = readdir(dir)) != NULL) {
    
            if (memcmp(dirent->d_name, ".", 1)) {
                
                ptoken = (struct p11Token_t *) malloc(sizeof(struct p11Token_t));

                if (ptoken == NULL) {
                    return CKR_HOST_MEMORY;
                }

                memset(ptoken, 0x00, sizeof(struct p11Token_t));

                i = 0;
                while (dirent->d_name[i] != 0x00) {
                	i++;
                }

                strbpcpy(ptoken->info.label, dirent->d_name, i);

                /* build the path to the token and read the content*/
                
                strcat(ptoken->tokenDir, scr);
                strcat(ptoken->tokenDir, dirent->d_name);
                strcat(ptoken->tokenDir, "/");
                
                memset(scr, 0x00, sizeof(scr));
                strcat(scr, ptoken->tokenDir);
                strcat(scr, ptoken->info.label);

                fh = open(scr, _O_RDONLY | _O_BINARY, _S_IREAD);

                if (fh < 0) {
#ifdef DEBUG
                	debug("[checkForToken] Error reading data from token file %s ...\n", strerror(errno));
#endif
                    return -1;
                }

                rc = read(fh, ptoken, sizeof(struct p11Token_t));

                if (rc < sizeof(struct p11Token_t)) {
                    return -1;   
                }

                close(fh);
                
                rc = loadObjects(slot, ptoken, TRUE);

                if (rc < 0) {
                    return rc;
                }

                *token = ptoken;
                break;

            }

            dirent = NULL;
    }

    closedir(dir);

    return CKR_OK;

}
