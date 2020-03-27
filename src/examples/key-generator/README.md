Key generator for boot level integration
========================================

This is an example application to help implement a disk encryption
system that operates during the boot process, before a PC/SC subsystem
is available.

The tools uses the CT-API/CCID subsystem to interface with the
SmartCard-HSM in order to perform an initial pairing and subsequent
disk encryption key generation.

The tools supports three operations

    key-generator --init --transportpin 123456

Performs a device initialization and sets a Transport-PIN 123456.

In a subsequent invocation the code will check, if the PIN is in state
transport. In that case a pairing is performed, in which the user is prompted
for the transport PIN and a user selected PIN. The function then generates
a master key and derives a key value that is then printed.

In further invocations the user PIN is prompted and after successfull
authentication a key is derived and printed.

PIN values can be provided on the command line:

    key-generator --transportpin 123456 --pin 648219

A pairing secret can be provided with the --pairingsecret parameter.
The pairing secret is a locally stored secret that is prepended to the
user PIN.

    key-generator --transportpin 123456 --pin 648219 --pairingsecret ABCD

A derivation parameter can be selected using the --label parameter.
Without the parameter the default label "Disk1" is used.

    key-generator --pin 648219 --label XYZ

The module needs to be compiled with

    ./configure --enable-ctapi

You can use

    ./configure --enable-ctapi --enable-debug

to create debugging output.
