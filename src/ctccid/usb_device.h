/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |�**> <**�|  Copyright (c) 2013. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Simple abstraction layer for USB devices using libusb
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifndef _USB_DEVICE_H_
#define _USB_DEVICE_H_

#include <stdint.h>
#include "ccidT1.h"

#define SCM_VENDOR_ID 0x04e6
#define SCM_SCR_35XX_DEVICE_ID 0x5410
#define SCM_SCR_3310_DEVICE_ID 0x5116

#define ERR_TIMEOUT -10
#define ERR_EDC     -11

#define USB_WRITE_TIMEOUT (5 * 1000)
#define USB_READ_TIMEOUT  (3 * 1000)

typedef struct usb_device {

    struct libusb_device_handle *handle;
    struct libusb_config_descriptor *configuration_descriptor;

    int maxMessageLength;

    uint8_t bulk_in;
    uint8_t bulk_out;
    uint8_t interrupt;

} usb_device_t;

int Open(unsigned short pn, usb_device_t **device);
int Close(usb_device_t **device);
int Write(usb_device_t *device, unsigned int length, unsigned char *buffer);
int Read(usb_device_t *device, unsigned int *length, unsigned char *buffer);
int MaxMessageLength(usb_device_t *device);
#endif

