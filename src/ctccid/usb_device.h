/**
 * CT-API for CCID Driver
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
 * @file usb_device.h
 * @author Frank Thater
 * @brief Simple abstraction layer for USB devices
 */

#ifndef _USB_DEVICE_H_
#define _USB_DEVICE_H_

#include <stdint.h>

/**
 * Vendor ID for SCM Microsystems
 */
#define SCM_VENDOR_ID 0x04e6

/**
 * Device IDs
 */
#define SCM_SCR_3310_DEVICE_ID   0x5116		/* Contactreader */
#define SCM_SCR_35XX_DEVICE_ID   0x5410		/* Old JCOP 2.4.1r3 Token */
#define UTRUST_JCOP2_DEVICE_ID   0x5817		/* New JCOP 2.4.1r3 Token */
#define UTRUST_SAM_DEVICE_ID     0x5816		/* SAM Slot Token */
#define UTRUST_2700R_DEVICE_ID   0x5810		/* uTrust 2700 R */

#define NITROKEY_VENDOR_ID	0x20a0
#define NITROKEY_HSM		0x4230

#define KEYXENTIC_VENDOR_ID	0x2f76
#define KEYXENTIC_KX9096	0x0906

#define NO_READER_NAME           0x0001		/* Do not return reader names in USB_Enumerate */

/**
 * Timeout value for writing data
 */
#define USB_WRITE_TIMEOUT (5 * 1000)

/**
 * Timeout value for reading data
 */
#define USB_READ_TIMEOUT  (3 * 1000)

#define USB_OK               0             /* Successful completion           */
#define ERR_NO_READER       -1             /* Reader not found                */
#define ERR_USB             -2             /* USB error                       */
#define ERR_ARG             -3             /* Invalid parameter or value      */

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

        /*
         * The offset into the list of interfaces
         */

        int ifidx;

        /**
         * ID of bulk in
         */
        uint8_t bulk_in;

        /**
         * ID of bulk out
         */
        uint8_t bulk_out;

} usb_device_t;

int USB_Enumerate(unsigned char *readers, int *len, int options);
int USB_Open(unsigned short pn, usb_device_t **device);
int USB_Close(usb_device_t **device);
void USB_GetCCIDDescriptor(usb_device_t *device, unsigned char const **desc, int *length);
int USB_Write(usb_device_t *device, unsigned int length, unsigned char *buffer);
int USB_Read(usb_device_t *device, unsigned int *length, unsigned char *buffer);

#endif

