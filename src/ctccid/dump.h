/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |.**> <**.|  Copyright (c) 2013. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Simple abstraction layer for USB devices using libusb
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-05-07
 *
 *****************************************************************************/

#ifndef __DUMP_H__                     /* Prevent from including twice      */
#define __DUMP_H__

#ifdef __cplusplus                      /* Support for C++ compiler          */
extern "C" {
#endif

void ctccidDump(void *ptr, int len);

#ifdef __cplusplus
}
#endif

#endif
