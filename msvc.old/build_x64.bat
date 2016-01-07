cd /d %~dp0

call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd"

call "setenv" /x64

msbuild sc-hsm-pcsc-pkcs11.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-pcsc-pkcs11.vcxproj /property:Configuration=Debug;Platform=x64

msbuild sc-hsm-pcsc-pkcs11-test.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-pcsc-pkcs11-test.vcxproj /property:Configuration=Debug;Platform=x64
