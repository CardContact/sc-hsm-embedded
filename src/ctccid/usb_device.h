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

/**
 * Vendor ID for SCM Microsystems
 */
#define SCM_VENDOR_ID 0x04e6

/**
 * Device ID for SCR 355
 */
#define SCM_SCR_35XX_DEVICE_ID 0x5410

/**
 * Device ID for SCR 3310
 */
#define SCM_SCR_3310_DEVICE_ID 0x5116

/**
 * Timeout value for writing data
 */
#define USB_WRITE_TIMEOUT (5 * 1000)

/**
 * Timeout value for reading data
 */
#define USB_READ_TIMEOUT  (3 * 1000)

#define USB_OK               0             /* Successful completion           */
#define ERR_NO_READER       -1             /* Invalid parameter or value      */
#define ERR_USB             -2             /* USB error                       */

/**
 * Data structure encapsulating all information necessary
 * to perform USB communication with a device, e.g. device handles,
 * descriptors, bulk pipe ids.
 */
typedef struct usb_device {

    struct libusb_device_handle *handle;
    struct libusb_config_descriptor *configuration_descriptor;

    uint8_t bulk_in;
    uint8_t bulk_out;
    uint8_t interrupt;

} usb_device_t;

int Open(unsigned short pn, usb_device_t **device);
int Close(usb_device_t **device);
int Write(usb_device_t *device, unsigned int length, unsigned char *buffer);
int Read(usb_device_t *device, unsigned int *length, unsigned char *buffer);

#endif

