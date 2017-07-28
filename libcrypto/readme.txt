libcrypto (libeay for Windows)
------------------------------
Extracted from OpenSSL 1.0.2g with source from

git clone git://git.openssl.org/openssl.git
git checkout OpenSSL_1_0_2g

Compiled in Windows SDK 7.1 Command Prompt with

	cd openssl
	setenv /x86 /release
	perl Configure VC-WIN32 -no-asm
	nmake -a -f ms\nt.mak
	copy out32\libeay32.lib ..\libcrypto\lib\libeay32.lib

	setenv /x64 /release
	perl Configure VC-WIN64A -no-asm
	nmake -a -f ms\nt.mak
	copy out32\libeay32.lib ..\libcrypto\lib\libeay64.lib

