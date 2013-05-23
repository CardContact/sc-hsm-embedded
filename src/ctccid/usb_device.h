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

        /**
         * Libusb device handle
         */
        struct libusb_device_handle *handle;
        /**
         * Libusb device configuration descriptor
         */
        struct libusb_config_descriptor *configuration_descriptor;

        /**
         * ID of bulk in
         */
        uint8_t bulk_in;

        /**
         * ID of bulk out
         */
        uint8_t bulk_out;
 
} usb_device_t;

int USB_Open(unsigned short pn, usb_device_t **device);
int USB_Close(usb_device_t **device);
int USB_Write(usb_device_t *device, unsigned int length, unsigned char *buffer);
int USB_Read(usb_device_t *device, unsigned int *length, unsigned char *buffer);

#endif

