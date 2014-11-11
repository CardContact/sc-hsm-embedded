#!/bin/bash

#
# SmartCard-HSM USB-Stick shipping from November 2014 has a new USB product ID
# that might not be contained in libccid. This script add the proper product ID.
#
# Find Info.plist for libccid package
# Check if the SmartCard-HSM product ID is contained
# Added the product ID

LOCS=( "/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
       "/usr/lib64/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
       "/usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents/Info.plist" )

for i in "${LOCS[@]}"
    do
        echo "Trying $i";
	if [ -e "$i" ]; then
		if [ -L "$i" ]; then
			LOC=`readlink $i`
		else
			LOC=$i;
		fi
		break;
	fi
    done

if [ -z "$LOC" ]; then
	echo "No libccid configuration file found"
	exit 1
fi

echo "Found libccid configuration in $LOC"

if grep --quiet 0x5817 "$LOC"; then
	echo "SmartCard-HSM product id already contained in libccid configuration."
else
	echo "Adding product id to libccid configuration"
	sed -i.bak '/ifdVendorID/ {
n
a \
		\<string\>0x04E6\<\/string\>
}
/ifdProductID/ {
n
a \
		\<string\>0x5817\<\/string\>
}
/ifdFriendlyName/ {
n
a \
		\<string\>CardContact SmartCard-HSM\<\/string\>
}' "$LOC"
fi
