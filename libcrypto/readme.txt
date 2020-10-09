libcrypto (libeay for Windows)
------------------------------

git clone git://git.openssl.org/openssl.git
git checkout OpenSSL_1_1_1h

In x86 Native Tools Command Prompt:
	perl Configure VC-WIN32 -no-asm
	nmake
	copy libcrypto_static.lib ..\sc-hsm-embedded\libcrypto\lib\libeay32.lib

In x64 Native Tools Command Prompt:
	perl Configure VC-WIN64A -no-asm
	nmake
	copy libcrypto_static.lib ..\sc-hsm-embedded\libcrypto\lib\libeay64.lib
