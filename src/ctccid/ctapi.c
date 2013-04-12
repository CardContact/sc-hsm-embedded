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
 * Author :         Andreas Schwier
 *
 * Last modified:   2006-02-20
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libusb-1.0/libusb.h>

#include "ctapi.h"

#if 0
static struct usb_device *LookupReader()

{
	struct usb_bus *bus;
	struct usb_device *dev;
	struct usb_bus *busses;

	usb_init();
	usb_find_busses();
	usb_find_devices();
	busses = usb_get_busses();

	for (bus = busses; bus; bus = bus->next)
		for (dev = bus->devices; dev; dev = dev->next)
			if ((dev->descriptor.idVendor == 0x04e6)
					&& (dev->descriptor.idProduct == 0x5410))
				return dev;

	return NULL ;
}
#endif

/*
 * Initialise the interface to the card reader attached
 * to the port number specified in <pn>
 *
 */

signed char CT_init(unsigned short ctn, unsigned short pn)

{	int rv, cnt, i;
	libusb_device **devs, *dev;

	rv = libusb_init(NULL);

	if (rv != 0) {
		return -1;
	}

	cnt = libusb_get_device_list(NULL, &devs);

	if (cnt < 0) {
		return -1;
	}

	/* Iterate through all devices to find a reader */
	i = 0;

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *config_desc;
		uint8_t bus_number = libusb_get_bus_number(dev);
		uint8_t device_address = libusb_get_device_address(dev);

		int r = libusb_get_device_descriptor(dev, &desc);

		if (r < 0)	{
			// error
			continue;
		}

		if (desc.idVendor == 0x04e6 && desc.idProduct == 0x5410) {
			printf("Found reader %04X:%04X", desc.idVendor, desc.idProduct);
		}
	}


	// libusb_open()
	// libusb_get_configuration() - check that current active config is the one we need - otherwise change that (OS may set the correct one)
	// libusb_claim_interface()

	libusb_free_device_list(devs, 1);

	return OK;
}

/*
 * Close the interface and free all allocated resources
 *
 */

signed char CT_close(unsigned short ctn)

{

	// libusb_release()
	// libusb_close()

	libusb_exit(NULL);

	return OK;
}

/*
 * Pass a command to the reader driver and receive the response
 *
 */

signed char CT_data(unsigned short ctn, unsigned char *dad, unsigned char *sad,
		unsigned short lc, unsigned char *cmd, unsigned short *lr,
		unsigned char *rsp)

{
	int rc;
	unsigned int ilr;

	ilr = (int) *lr; /* Overcome problem with lr size     */

	rc = 0;
	if (*dad == 1) {
		*sad = 1; /* Source Reader    */
		*dad = 2; /* Destination Host */

		/*******************/
		/* CT-BCS Commands */
		/*******************/

		if (cmd[0] == 0x20) {
			ilr = 2;
		} else if (cmd[0] == 0x80) {
		} else /* Wrong class for CTAPI */
		{
			rsp[0] = HIGH(CLASS_NOT_SUPPORTED);
			rsp[1] = LOW(CLASS_NOT_SUPPORTED);
			ilr = 2;
		}
	} else if (*dad == 0) { /* This command goes to the card     */

		// Don't get confused here this is for the return saying
		// the source was the card and the destination the host

		*sad = 0; /* Source Smartcard */
		*dad = 2; /* Destination Host */

		*sad = 1; /* Shows that response comes from CTAPI */
		*dad = 2;
		rc = 0;
		rsp[0] = HIGH(COMMUNICATION_NOT_POSSIBLE);
		rsp[1] = LOW(COMMUNICATION_NOT_POSSIBLE);
		ilr = 2;
	} else {
		rc = ERR_INVALID; /* Invalid SAD/DAD Address */
		ilr = 0;
	}

	*lr = ilr;
	return rc;
}
