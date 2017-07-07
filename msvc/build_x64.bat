cd /d %~dp0

call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd"

call "setenv" /x64

msbuild sc-hsm-pkcs11-pcsc\sc-hsm-pkcs11-pcsc.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-pkcs11-pcsc\sc-hsm-pkcs11-pcsc.vcxproj /property:Configuration=Debug;Platform=x64

msbuild sc-hsm-pkcs11-test\sc-hsm-pkcs11-test.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-pkcs11-test\sc-hsm-pkcs11-test.vcxproj /property:Configuration=Debug;Platform=x64

msbuild sc-hsm-minidriver\sc-hsm-minidriver.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-minidriver\sc-hsm-minidriver.vcxproj /property:Configuration=Debug;Platform=x64

msbuild sc-hsm-minidriver-test\sc-hsm-minidriver-test.vcxproj /property:Configuration=Release;Platform=x64

msbuild sc-hsm-minidriver-test\sc-hsm-minidriver-test.vcxproj /property:Configuration=Debug;Platform=x64
