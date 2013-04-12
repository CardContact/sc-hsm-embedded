/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |�**> <**�|  Copyright (c) 1999-2006. All rights reserved
 *  --------- 
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Main API interface according to MKT specification
 *
 * Author :         Frank Thater (FTH), David Corcoran
 *
 * Last modified:   04/04/2000
 *
 *****************************************************************************/

#ifndef __ctapi_h__                     /* Prevent from including twice      */
#define __ctapi_h__

#ifdef __cplusplus                      /* Support for C++ compiler          */
extern "C" {
#endif

#define MAX_APDULEN     1040            /* Maximum lenght of APDU            */

signed char CT_init (
    unsigned short ctn,                 /* Number assigned to terminal       */
    unsigned short pn                   /* Port allocated for terminal       */
    );

signed char CT_close(
    unsigned short ctn                  /* Number assigned to terminal       */
    );                 

signed char CT_data(
    unsigned short ctn,                /* Number assigned to terminal       */
    unsigned char  *dad,               /* Destination ADdress               */
    unsigned char  *sad,               /* Source ADdress                    */
    unsigned short lc,                 /* Length of command in cmd          */
    unsigned char  *cmd,               /* Command APDU buffer               */
    unsigned short *lr,                /* Length of response APDU           */
    unsigned char  *rsp                /* Response APDU buffer              */
    );

/* CTAPI - response codes                                                   */

#define OK               0             /* Successfull completion            */
#define ERR_INVALID     -1             /* Invalid parameter or value        */
#define ERR_CT          -8             /* Cardterminal error                */
#define ERR_TRANS       -10            /* Transmission error                */
#define ERR_MEMORY      -11            /* Memory allocate error             */
#define ERR_HOST        -127           /* Function aborted by host os       */
#define ERR_HTSI        -128           /* 'HTSI' error                      */

/* CTAPI / CTBCS SW1/2 states                                               */

#define SMARTCARD_SUCCESS           0x9000
#define SMARTCARD_SUCCESS_ASYNC     0X9001
#define NOT_SUCCESSFUL              0x6400

#define W_NO_CARD_PRESENTED         0x6200
#define W_ICC_ALREADY_PRESENT       0x6201

#define DATA_CORRUPTED              0x6281
#define NO_CARD_PRESENT             0x64A1
#define CARD_NOT_ACTIVATED          0x64A2
#define WRONG_LENGTH                0x6700
#define COMMAND_NOT_ALLOWED         0x6900
#define VERIFICATION_METHOD_BLOCK   0x6983
#define VERIFICATION_UNSUCCESSFUL   0x63C0
#define WRONG_PARAMETERS_P1_P2      0x6A00
#define FILE_NOT_FOUND              0x6A82
#define OUT_OF_RANGE                0x6B00
#define WRONG_LENGTH_LE             0x6C00
#define WRONG_INSTRUCTION           0x6D00
#define CLASS_NOT_SUPPORTED         0x6E00
#define COMMUNICATION_NOT_POSSIBLE  0x6F00

#ifndef HIGH
#define HIGH(x)   ((x >> 8))
#define LOW(x)    ((x & 0xff))
#endif


#define CT              1
#define HOST            2
#ifdef __cplusplus
}
#endif

#endif












