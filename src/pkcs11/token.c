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
 * Abstract :       Functions for token authentication and token management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    token.c
 * \author  Frank Thater (fth)
 * \brief   Functions for token authentication and token management
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>      
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#include <dirent.h>
#endif

#ifndef _O_RDONLY
#define _O_RDONLY O_RDONLY
#endif

#ifndef _O_RDWR
#define _O_RDWR O_RDWR
#endif

#ifndef _O_BINARY
#define _O_BINARY 0
#endif

#ifndef _O_CREAT
#define _O_CREAT O_CREAT
#endif

#ifndef _S_IREAD
#define _S_IREAD S_IREAD | S_IROTH
#endif

#ifndef _S_IWRITE
#define _S_IWRITE S_IWRITE | S_IWOTH
#endif

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif

#ifndef _stat
#define _stat stat
#endif

#include <openssl/des.h>

#include <strbpcpy.h>

#include <pkcs11/token.h>
#include <pkcs11/object.h>
#include <pkcs11/secretkeyobject.h>
#include <pkcs11/dataobject.h>

// #define USE_CRYPTO
// #define USE_MAC

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

extern struct p11Context_t *context;

//return the length of result string. support only 10 radix for easy use and better performance
char *my_itoa(int val, char* buf)
{
    const unsigned int radix = 10;

    char* p;
    unsigned int a;        //every digit
    int len;
    char* b;            //start of the digit char
    char temp;
    unsigned int u;

    p = buf;

    if (val < 0)
    {
        *p++ = '-';
        val = 0 - val;
    }
    u = (unsigned int)val;

    b = p;

    do {
        a = u % radix;
        u /= radix;

        *p++ = a + '0';

    } while (u > 0);

    len = (int)(p - buf);

    *p-- = 0;

    //swap
    do {
        temp = *p;
        *p = *b;
        *b = temp;
        --p;
        ++b;

    } while (b < p);

    return buf;
}


int addObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject)

{   
    struct p11Object_t *obj, *tmp;

    tmp = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;
    
    if (tmp == NULL) {
        
        object->next = NULL;
               
        if (publicObject) {
            token->numberOfTokenObjects = 1;
            token->tokenObjList = object;
        } else {
            token->numberOfPrivateTokenObjects = 1;
            token->tokenPrivObjList = object;
        }

        if (!object->handle) { 
            object->handle = token->freeObjectNumber++;
        }

    } else {

        obj = tmp;

        while (obj->next != NULL) {
            obj = obj->next;
        }

        obj->next = object;
        
        if (publicObject) {
            token->numberOfTokenObjects++;
        } else {
            token->numberOfPrivateTokenObjects++;
        }
        
        if (!object->handle) { 
            object->handle = token->freeObjectNumber++;
        }
        
        object->next = NULL;

    }

    object->dirtyFlag = 1;

    return CKR_OK;
}

int findObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject)

{
    struct p11Object_t *obj;
    int pos = 0;            /* remember the current position in the list */

    obj = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;
    *object = NULL;

    while (obj != NULL) {
    
        if (obj->handle == handle) {

            *object = obj;
            return pos;
        }
        
        obj = obj->next;
        pos++;
    }

    return -1;
}

int removeObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)

{
    struct p11Object_t *object = NULL;
    struct p11Object_t *prev = NULL;
    int rc;

    rc = findObject(token, handle, &object, publicObject);
    
    /* no object with this handle found */
    if (rc < 0) {
        return rc;
    }

    if (rc > 0) {      /* there is more than one element in the pool */
        
        prev = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;

        while (prev->next->handle != handle) {
            prev = prev->next;
        }
    
        prev->next = object->next;
        
    }

    removeAllAttributes(object);

    free(object);
    
    token->numberOfTokenObjects--;

    if (rc == 0) {      /* We removed the last element from the list */
        if (publicObject) {
            token->tokenObjList = NULL;
        } else {
            token->tokenPrivObjList = NULL;
        }
    }

    return CKR_OK;
}


int removeObjectLeavingAttributes(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)

{
    struct p11Object_t *object = NULL;
    struct p11Object_t *prev = NULL;
    int rc;

    rc = findObject(token, handle, &object, publicObject);
    
    /* no object with this handle found */
    if (rc < 0) {
        return rc;
    }

    if (rc > 0) {      /* there is more than one element in the pool */
        
        prev = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;

        while (prev->next->handle != handle) {
            prev = prev->next;
        }
    
        prev->next = object->next;
        
    }

    free(object);
    
    token->numberOfTokenObjects--;

    if (rc == 0) {      /* We removed the last element from the list */
        if (publicObject) {
            token->tokenObjList = NULL;
        } else {
            token->tokenPrivObjList = NULL;
        }
    }

    return CKR_OK;
}


int loadObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObjects)

{   char path[_MAX_PATH];
    char scr[_MAX_PATH];
    int fh, rc, i, pos;
    DIR *dir;
    struct dirent *dirent;
    struct p11Object_t *pObject;
    CK_ATTRIBUTE attrData[50];
    unsigned long size = 0;
    unsigned char *buffer;
    unsigned int j;
    struct CryptoSession_t *cs = NULL;    
#ifdef WIN32
    struct _stat statBuffer;
#else
    struct stat statBuffer;
#endif
    char *publicObjectsExt = ".pub";
    char *privateObjectsExt = ".pri";
    char *extFilter;
    unsigned char mac[8], newmac[8];
   
    memset(path, 0x00, sizeof(scr));
    memset(attrData, 0x00, sizeof(attrData));

    extFilter = publicObjects == TRUE ? publicObjectsExt : privateObjectsExt;

    strcat(path, context->slotDirectory);
    strcat(path, "/");
    strcat(path, slot->slotDir);
    strcat(path, "/");
    strcat(path, token->tokenDir);
    strcat(path, "/");
    
    dir = opendir(path);

#ifdef WIN32
    if (dir->handle == -1) {
#else
    if (dir == NULL) {
#endif
#ifdef DEBUG
        printf("\n[loadObjects] Error opening token directory %s ...", path);  
#endif  
        return -1;
    }

    while((dirent = readdir(dir)) != NULL) {

#ifdef WIN32
            if (!memcmp(dirent->d_name + dirent->d_size - 4, extFilter, 4)) {
#else
            if (!memcmp(strchr(dirent->d_name, '\0') - 4, extFilter, 4)) {
#endif

                memcpy(scr, path, sizeof(path));
                strcat(scr, dirent->d_name);
                
                pObject = malloc(sizeof(struct p11Object_t));
                memset(pObject, 0x00, sizeof(struct p11Object_t));
                
                pObject->handle = atoi(dirent->d_name);

                /* for the actual filesize */
                _stat(scr, &statBuffer);
                
                fh = open(scr, _O_RDONLY | _O_BINARY, _S_IREAD);

                if (fh == -1) {
#ifdef DEBUG
                    printf("\n[loadObjects] Error opening objects file %s ...", scr);  
#endif  
                    return -1;
                }

                i = 0;
                j = 0;                
                
                size = statBuffer.st_size;

                /* read the MAC */
                rc = read(fh, mac, 8);

                if (rc < 8) {
#ifdef DEBUG
                    printf("\n[loadObjects] Error loading MAC from file %s ...", scr);  
#endif  
                    return -1;
                }
                
                size -= 8;

                buffer = (unsigned char *) malloc(size);
                
                if (buffer == NULL) {
#ifdef DEBUG
                    printf("\n[loadObjects] Error allocating buffer ...");  
#endif  
                    return -1;
                }
                
#ifdef USE_CRYPTO
                if (!publicObjects) {
                    decryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey1, (des_cblock *) token->transportKey1);
                    decryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey2, (des_cblock *) token->transportKey2);
                
                    decReadInit(&cs, token->transportKey1, token->transportKey2, fh);

                    encryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey1, (des_cblock *) token->transportKey1);
                    encryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey2, (des_cblock *) token->transportKey2);
            
                    rc = decRead(cs, buffer, size);

                    if (rc < (signed) size) {
#ifdef DEBUG
                        printf("\n[loadObjects] Error loading data from file %s ...", scr);  
#endif  
                        return -1;
                    }

                    decReadFinal(cs);

                } else {
#endif
                    rc = read(fh, buffer, size);
    
                    if (rc < (signed) size) {
#ifdef DEBUG
                        printf("\n[loadObjects] Error loading data from file %s ...", scr);  
#endif  
                        free(buffer);
                        close(fh);
                        return -1;
                    }
#ifdef USE_CRYPTO
                }
#endif

                close(fh);

#ifdef USE_MAC
                calculateMAC((des_cblock *) token->objMACKey, buffer, size, newmac);

                if (memcmp(mac, newmac, 8)) {
#ifdef DEBUG
                    printf("\n[loadObjects] Wrong MAC ...");  
#endif  
                    return -1;
                }
#endif
                
                while ((size - j) > sizeof(CK_ATTRIBUTE)) {
                                 
                    memcpy(&attrData[i], buffer + j, sizeof(CK_ATTRIBUTE));

                    j += sizeof(CK_ATTRIBUTE);

                    attrData[i].pValue = malloc(attrData[i].ulValueLen);

                    if (attrData[i].pValue == NULL) {
#ifdef DEBUG
                        printf("\n[loadObjects] Error allocating block for attribute ...");  
#endif  
                        free(buffer);
                        return -1;
                    }
                    
                    memcpy(attrData[i].pValue, buffer + j, attrData[i].ulValueLen);

                    j += attrData[i].ulValueLen;
                    i++;

                }
                
                free(buffer);

                pos = findAttributeInTemplate(CKA_CLASS, attrData, i);
    
                if (pos == -1) {
                    free(pObject);
                    return CKR_TEMPLATE_INCOMPLETE;
                }

                switch (*(CK_LONG *)attrData[pos].pValue) {
                    case CKO_DATA:
                        rc = createDataObject(attrData, i, pObject);
                        break;

                    case CKO_SECRET_KEY:
                        rc = createSecretKeyObject(attrData, i, pObject);
                        break;
        
                    default:
                        rc = CKR_FUNCTION_FAILED;
                        break;
                }

                if (rc != CKR_OK) {
#ifdef DEBUG
                    printf("\n[loadObjects] Error creating object from data ...");  
#endif      
                    free(pObject);
                    return -1;
                }
          
                addObject(token, pObject, publicObjects);
            }

            dirent = NULL;
    }

    closedir(dir);    
    
    return 0;
}


int saveObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObjects)

{   char path[_MAX_PATH];
    char scr[_MAX_PATH];
    unsigned char tmp[8];
    struct p11Object_t *object;
    unsigned char *tempBuffer, *paddedTempBuffer;
    unsigned int tempBufLength, paddedTempBufLength;
    int fh, rc;
    struct CryptoSession_t *cs = NULL;
    char *publicObjectsExt = ".pub";
    char *privateObjectsExt = ".pri";
    char *extFilter;
  
    memset(path, 0x00, sizeof(path));

    extFilter = publicObjects == TRUE ? publicObjectsExt : privateObjectsExt;

    strcat(path, context->slotDirectory);
    strcat(path, "/");
    strcat(path, slot->slotDir);
    strcat(path, "/");
    strcat(path, token->tokenDir);
    strcat(path, "/");
    
    /* Get the first object */
    object = publicObjects == TRUE ? token->tokenObjList : token->tokenPrivObjList;

    while (object) {

        if (object->dirtyFlag) {
            memcpy(scr, path, sizeof(path));
        
            strcat(scr, my_itoa( object->handle, tmp));
            strcat(scr, extFilter);
        
            fh = open(scr, _O_CREAT | _O_RDWR | O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);

            if (fh == -1) {
               return -1;
            }

            rc = serializeObject(object, &tempBuffer, &tempBufLength);

            if (rc) {
               return -1;
            }

            memset(tmp, 0x00, 8);
#ifdef USE_MAC
            padObjectSize(tempBuffer, tempBufLength, &paddedTempBuffer, &paddedTempBufLength);
            calculateMAC((des_cblock *) token->objMACKey, paddedTempBuffer, paddedTempBufLength, tmp);
#endif
            /* write the MAC */
            rc = write(fh, tmp, 8);
                
            if (rc < 8) {
                free(paddedTempBuffer);
                close(fh);
                return -1;
            }

#ifdef USE_CRYPTO
            if (!object->publicObj) {
                decryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey1, (des_cblock *) token->transportKey1);
                decryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey2, (des_cblock *) token->transportKey2);
                
                encWriteInit(&cs, token->transportKey1, token->transportKey2, fh);

                encryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey1, (des_cblock *) token->transportKey1);
                encryptTransportKey((des_cblock *) token->pinUser, (des_cblock *) token->transportKey2, (des_cblock *) token->transportKey2);
            
                rc = encWrite(cs, paddedTempBuffer, paddedTempBufLength);
                
                if (rc < (signed) paddedTempBufLength) {
                    free(paddedTempBuffer);
                    free(tempBuffer);
                    close(fh);
                    return -1;
                }

                rc = encWriteFinal(cs);

            } else {
#endif
                rc = write(fh, paddedTempBuffer, paddedTempBufLength);
                
                if (rc < (signed) paddedTempBufLength) {
                    free(paddedTempBuffer);
                    free(tempBuffer);                    
                    close(fh);
                    return -1;
                }

#ifdef USE_CRYPTO                
            }

#endif

            close(fh);
            free(paddedTempBuffer);
            free(tempBuffer);
            
            object->dirtyFlag = 0;
        }   
        
        object = object->next;
    }
    
    return 0;

}


int destroyObject(struct p11Slot_t *slot, struct p11Token_t *token, struct p11Object_t *object)

{   char path[_MAX_PATH];
    char tmp[10];
    int rc;
    char *publicObjectsExt = ".pub";
    char *privateObjectsExt = ".pri";
    char *extFilter;
   
    memset(path, 0x00, sizeof(path));

    extFilter = object->publicObj == TRUE ? publicObjectsExt : privateObjectsExt;

    strcat(path, context->slotDirectory);
    strcat(path, "/");
    strcat(path, slot->slotDir);
    strcat(path, "/");
    strcat(path, token->tokenDir);
    strcat(path, "/");
    
    strcat(path, my_itoa( object->handle, tmp));
    strcat(path, extFilter);

    rc = remove(path);

    if (rc) {
        return -1;
    }

    return 0;
}


int synchronizeTokenToDisk(struct p11Slot_t *slot, struct p11Token_t *token) 

{

    char scr[_MAX_PATH];
    int fh, rc;
    struct p11Token_t tempToken;

    /* save all public token objects */
    rc = saveObjects(slot, token, TRUE);

    if (rc < 0) {
#ifdef DEBUG
        debug("[synchronizeTokenToDisk] Error saving public objects ...\n");  
#endif 
        return CKR_GENERAL_ERROR;
    }

    /* save all private token objects */
    rc = saveObjects(slot, token, FALSE);

    if (rc < 0) {
#ifdef DEBUG
        debug("[synchronizeTokenToDisk] Error saving private objects ...\n");  
#endif 
        return CKR_GENERAL_ERROR;
    }

    memset(scr, 0x00, sizeof(scr));

    strcat(scr, context->slotDirectory);
    strcat(scr, "/");
    strcat(scr, slot->slotDir);
    strcat(scr, "/");
    strcat(scr, token->tokenDir);
    strcat(scr, "/");
    strcat(scr, token->tokenDir);
      
    fh = open(scr, _O_CREAT | _O_RDWR | O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);

    if (fh == -1) {
#ifdef DEBUG
        debug("[synchronizeTokenToDisk] Error opening token file %s ...\n", scr);  
#endif  
        return CKR_GENERAL_ERROR;
    }

    /* Clear the pointer */
    memcpy(&tempToken, token, sizeof(struct p11Token_t));
    tempToken.numberOfTokenObjects = 0;
    tempToken.numberOfPrivateTokenObjects = 0;
    tempToken.tokenObjList = NULL;
    tempToken.tokenPrivObjList = NULL;

    rc = write(fh, &tempToken, sizeof(struct p11Token_t));
    
    if (rc <= 0) {
#ifdef DEBUG
        debug("[synchronizeTokenToDisk] Error writing data to token file %s ...\n", scr);  
#endif  
        return CKR_GENERAL_ERROR;
    }
    
    close(fh);

    return 0;

}

