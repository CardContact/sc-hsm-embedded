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
 * @file usb_device.c
 * @author Frank Thater
 * @brief Simple abstraction layer for USB devices
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include <libusb-1.0/libusb.h>

#include "usb_device.h"

#ifdef DEBUG

#include "ctccid_debug.h"

static char* libusb_error_to_string(const int error) {
	static char strError[60];

	switch (error) {
		case LIBUSB_SUCCESS :
			(void) strncpy(strError, "Success", sizeof(strError));
			break;
		case LIBUSB_ERROR_IO :
			(void) strncpy(strError, "Input/output error", sizeof(strError));
			break;
		case LIBUSB_ERROR_INVALID_PARAM :
			(void) strncpy(strError, "Invalid parameter", sizeof(strError));
			break;
		case LIBUSB_ERROR_ACCESS :
			(void) strncpy(strError, "Access denied", sizeof(strError));
			break;
		case LIBUSB_ERROR_NO_DEVICE :
			(void) strncpy(strError, "No such device/device disconnected", sizeof(strError));
			break;
		case LIBUSB_ERROR_NOT_FOUND :
			(void) strncpy(strError, "Entity not found", sizeof(strError));
			break;
		case LIBUSB_ERROR_BUSY :
			(void) strncpy(strError, "Resource busy", sizeof(strError));
			break;
		case LIBUSB_ERROR_TIMEOUT :
			(void) strncpy(strError, "Operation timed out", sizeof(strError));
			break;
		case LIBUSB_ERROR_OVERFLOW :
			(void) strncpy(strError, "Overflow", sizeof(strError));
			break;
		case LIBUSB_ERROR_PIPE :
			(void) strncpy(strError, "Pipe error", sizeof(strError));
			break;
		case LIBUSB_ERROR_INTERRUPTED :
			(void) strncpy(strError, "System call interrupted", sizeof(strError));
			break;
		case LIBUSB_ERROR_NO_MEM :
			(void) strncpy(strError, "Insufficient memory", sizeof(strError));
			break;
		case LIBUSB_ERROR_NOT_SUPPORTED :
			(void) strncpy(strError, "Operation not supported or unimplemented on this platform", sizeof(strError));
			break;
		case LIBUSB_ERROR_OTHER :
			(void) strncpy(strError, "Other error.", sizeof(strError));
			break;
	};

	/* add a null byte */
	strError[sizeof(strError) - 1] = '\0';
	return strError;
}

#endif

/*
 * Context for libusb/libusbx
 */
static libusb_context *context = NULL;

/*
 * Reference counter for context
 */
static int refcnt = 0;



int isSupported(struct libusb_device_descriptor *desc)
{
	if ((desc->idVendor == SCM_VENDOR_ID) &&
	    ((desc->idProduct == SCM_SCR_3310_DEVICE_ID) ||
	     (desc->idProduct == SCM_SCR_35XX_DEVICE_ID) ||
	     (desc->idProduct == UTRUST_JCOP2_DEVICE_ID) ||
	     (desc->idProduct == UTRUST_2700R_DEVICE_ID) ||
	     (desc->idProduct == UTRUST_SAM_DEVICE_ID))) {
		return 1;
	}

	if ((desc->idVendor == NITROKEY_VENDOR_ID) && (desc->idProduct == NITROKEY_HSM)) {
		return 1;
	}

	return 0;
}



int USB_Enumerate(unsigned char *readers, int *len, int options)
{
	int rc, cnt, i;
	unsigned char *po;
	unsigned char param[128];
	libusb_device **devs, *dev;

	/*
	 * We implement our own context handling to avoid a bug in the default context implementation
	 * of the libusbx library version <= 1.0.15
	 *
	 * See https://github.com/libusbx/libusbx/commit/ce75e9af3f9242ec328b0dc2336b69ff24287a3c#libusb/core.c
	 */
	if (!context) {
		rc = libusb_init(&context);

		if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
			ctccid_debug("libusb_init failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
			return ERR_USB;
		}
	}

	refcnt++;

#ifdef DEBUG
	libusb_set_debug(context, 3);
#endif

	cnt = libusb_get_device_list(context, &devs);

	if (cnt < 0) {
		refcnt--;
		return ERR_NO_READER;
	}

	/* Iterate through all devices to find a reader */
	i = 0;
	cnt = 0;
	po = readers;
	rc = USB_OK;

	while ((dev = devs[i++]) != NULL ) {
		struct libusb_device_descriptor desc;
		struct libusb_device_handle *handle;

		rc = libusb_get_device_descriptor(dev, &desc);

		if (rc < 0) {
			/* error */
			continue;
		}

		if (isSupported(&desc)) {
			uint8_t bus = libusb_get_bus_number(dev);
			uint8_t addr = libusb_get_device_address(dev);

			if (*len - cnt < 3) {
				rc = ERR_ARG;
				break;
			}

			*po++ = bus;
			*po++ = addr;
			cnt += 2;

			if (!(options & NO_READER_NAME)) {
				if (desc.iSerialNumber) {
					rc = libusb_open(dev, &handle);

					if (rc != LIBUSB_SUCCESS) {
						rc = ERR_USB;
						break;
					}
					rc = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, param, sizeof(param));
					libusb_close(handle);
				} else {
					rc = snprintf((char *)param, sizeof(param), "%04x", (bus << 8 | addr));
				}

				if (*len - cnt < (15 + rc + 1)) {	// "SmartCard-HSM (" + serial + ")"
					rc = ERR_ARG;
					break;
				}

				memcpy(po, "SmartCard-HSM (", 15);
				po += 15;
				cnt += 15;
				memcpy(po, param, rc);
				po += rc;
				cnt += rc;
				*po++ = ')';
				cnt++;
			}

			*po++ = 0;
			cnt++;
		}
	}

	if (rc == USB_OK) {
		*len = cnt;
	}

	libusb_free_device_list(devs, 1);

	refcnt--;
	if (refcnt == 0) {
		libusb_exit(context);
		context = NULL;
	}

	return rc;
}



/**
 * Open USB device at the specified port and allocate necessary resources
 *
 * @param pn Port number
 * @param device Structure holding device specific data
 * @return Status code \ref USB_OK, \ref ERR_NO_READER, \ref ERR_USB
 */
int USB_Open(unsigned short pn, usb_device_t **device)
{

	int rc, cnt, i;
	libusb_device **devs, *dev;

	/*
	 * We implement our own context handling to avoid a bug in the default context implementation
	 * of the libusbx library version <= 1.0.15
	 *
	 * See https://github.com/libusbx/libusbx/commit/ce75e9af3f9242ec328b0dc2336b69ff24287a3c#libusb/core.c
	 */
	if (!context) {
		rc = libusb_init(&context);

		if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
			ctccid_debug("libusb_init failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
			return ERR_USB;
		}
	}

	refcnt++;

#ifdef DEBUG
	libusb_set_debug(context, 3);
#endif

	cnt = libusb_get_device_list(context, &devs);

	if (cnt < 0) {
		refcnt--;
		return ERR_NO_READER;
	}

	/* Iterate through all devices to find a reader */
	i = 0;
	cnt = 0;

	while ((dev = devs[i++]) != NULL ) {
		struct libusb_device_descriptor desc;

		rc = libusb_get_device_descriptor(dev, &desc);

		if (rc < 0) {
			/* error */
			continue;
		}

		if (isSupported(&desc)) {
			uint8_t bus = libusb_get_bus_number(dev);
			uint8_t address = libusb_get_device_address(dev);
			unsigned short port = bus << 8 | address;

			/*
			 * Found the desired reader?
			 */
			if ((cnt == pn) || (port == pn)) {
#ifdef DEBUG
				ctccid_debug("Reader index (%i) and requested port number (%i) match.\n", cnt, pn);
#endif
				*device = calloc(1, sizeof(usb_device_t));
				break;
			} else {
#ifdef DEBUG
				ctccid_debug("Reader index (%i) and requested port number (%i) do not match.\n", cnt, pn);
#endif
				cnt++;
			}
		}
	}

	if (dev != NULL ) { /* reader found */
		rc = libusb_open(dev, &((*device)->handle));

		if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
			ctccid_debug("libusb_open failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
			free(*device);
			libusb_free_device_list(devs, 1);
			refcnt--;
			if (refcnt == 0) {
				libusb_exit(context);
				context = NULL;
			}
			return ERR_USB;
		}

		rc = libusb_get_active_config_descriptor(dev, &((*device)->configuration_descriptor));

		if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
			ctccid_debug("libusb_get_active_config_descriptor failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
			libusb_close((*device)->handle);
			free(*device);
			libusb_free_device_list(devs, 1);
			refcnt--;
			if (refcnt == 0) {
				libusb_exit(context);
				context = NULL;
			}
			return ERR_USB;
		}

		rc = libusb_claim_interface((*device)->handle, (*device)->configuration_descriptor->interface->altsetting->bInterfaceNumber);

		if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
			ctccid_debug("libusb_claim_interface failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
			libusb_close((*device)->handle);
			free(*device);
			libusb_free_device_list(devs, 1);
			refcnt--;
			if (refcnt == 0) {
				libusb_exit(context);
				context = NULL;
			}
			return ERR_USB;
		}

		/*
		 * Search for the bulk in/out endpoints
		 */
		for (i = 0; i < (*device)->configuration_descriptor->interface->altsetting->bNumEndpoints; i++) {

			uint8_t bEndpointAddress;

			if ((*device)->configuration_descriptor->interface->altsetting->endpoint[i].bmAttributes
					== LIBUSB_TRANSFER_TYPE_INTERRUPT) {
				/*
				 * Ignore the interrupt endpoint
				 */
				continue;
			}

			if (((*device)->configuration_descriptor->interface->altsetting->endpoint[i].bmAttributes
					& LIBUSB_TRANSFER_TYPE_BULK) != LIBUSB_TRANSFER_TYPE_BULK) {
				/*
				 * No bulk endpoint - try the next one
				 */
				continue;
			}

			bEndpointAddress = (*device)->configuration_descriptor->interface->altsetting->endpoint[i].bEndpointAddress;

			if ((bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
				(*device)->bulk_in = bEndpointAddress;
			}

			if ((bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
				(*device)->bulk_out = bEndpointAddress;
			}
		}

		rc = USB_OK;

	} else { /* no reader found */
		rc = ERR_NO_READER;
	}

	libusb_free_device_list(devs, 1);

	if (rc == ERR_NO_READER) {
		refcnt--;
		if (refcnt == 0) {
			libusb_exit(context);
			context = NULL;
		}
	}

	return rc;
}



/**
 * Return the 54 byte CCID Descriptor
 *
 * @param device Structure with device specific data
 * @return Status code \ref USB_OK, \ref ERR_USB
 */
void USB_GetCCIDDescriptor(usb_device_t *device, unsigned char const **desc, int *length)
{
	if (length)
		*length = device->configuration_descriptor->interface->altsetting->extra_length;
	if (desc)
		*desc = device->configuration_descriptor->interface->altsetting->extra;
}



/**
 * Close USB device and free allocated resources
 *
 * @param device Structure with device specific data
 * @return Status code \ref USB_OK, \ref ERR_USB
 */
int USB_Close(usb_device_t **device)
{

	int rc;

	rc = libusb_release_interface((*device)->handle,
								  (*device)->configuration_descriptor->interface->altsetting->bInterfaceNumber);

	if (rc != LIBUSB_SUCCESS) {
#ifdef DEBUG
		ctccid_debug("libusb_release_interface failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
		return ERR_USB;
	}

	libusb_free_config_descriptor((*device)->configuration_descriptor);
	libusb_close((*device)->handle);
	free(*device);
	*device = NULL;

	refcnt--;
	if (refcnt == 0) {
		libusb_exit(context);
		context = NULL;
	}

	return USB_OK;
}



/**
 * Write data block to specified USB device using bulk transfer
 *
 * @param device Device specific data
 * @param length Length of data to write
 * @param buffer Data buffer
 * @return Status code \ref USB_OK, \ref ERR_USB
 */
int USB_Write(usb_device_t *device, unsigned int length, unsigned char *buffer)
{
	int rc;
	int send;

	rc = libusb_bulk_transfer(device->handle, device->bulk_out, buffer, length, &send, USB_WRITE_TIMEOUT);

	if (rc != LIBUSB_SUCCESS || (send != length)) {
#ifdef DEBUG
		ctccid_debug("libusb_bulk_transfer (write) failed. rc = %i (%s), send=%i, length=%i\n", rc, libusb_error_to_string(rc), send, length);
#endif
		return ERR_USB;
	}

	return USB_OK;
}



/**
 * Read data block from specified USB device using bulk transfer
 *
 * @param device Device specific data
 * @param length Length of data buffer
 * @param buffer Data buffer
 * @return Status code \ref USB_OK, \ref ERR_USB
 */
int USB_Read(usb_device_t *device, unsigned int *length, unsigned char *buffer)
{
	int rc;
	int read;

	rc = libusb_bulk_transfer(device->handle, device->bulk_in, buffer, *length, &read, USB_READ_TIMEOUT);

	if (rc != LIBUSB_SUCCESS) {
		*length = 0;
#ifdef DEBUG
		ctccid_debug("libusb_bulk_transfer (read) failed. rc = %i (%s)\n", rc, libusb_error_to_string(rc));
#endif
		return ERR_USB;
	}

	*length = read;

	return USB_OK;
}
