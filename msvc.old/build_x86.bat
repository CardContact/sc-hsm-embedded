cd /d %~dp0

call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd"

call "setenv" /x86

msbuild sc-hsm-pcsc-pkcs11.vcxproj /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-pcsc-pkcs11.vcxproj /property:Configuration=Debug;Platform=Win32

msbuild sc-hsm-pcsc-pkcs11-test.vcxproj /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-pcsc-pkcs11-test.vcxproj /property:Configuration=Debug;Platform=Win32
