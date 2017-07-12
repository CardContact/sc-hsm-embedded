cd /d %~dp0

call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd"

call "setenv" /x86

msbuild sc-hsm-pkcs11-pcsc\sc-hsm-pkcs11-pcsc.vcxproj /t:Clean;Rebuild /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-pkcs11-pcsc\sc-hsm-pkcs11-pcsc.vcxproj /t:Clean;Rebuild /property:Configuration=Debug;Platform=Win32

msbuild sc-hsm-pkcs11-test\sc-hsm-pkcs11-test.vcxproj /t:Clean;Rebuild /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-pkcs11-test\sc-hsm-pkcs11-test.vcxproj /t:Clean;Rebuild /property:Configuration=Debug;Platform=Win32

msbuild sc-hsm-minidriver\sc-hsm-minidriver.vcxproj /t:Clean;Rebuild /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-minidriver\sc-hsm-minidriver.vcxproj /t:Clean;Rebuild /property:Configuration=Debug;Platform=Win32

msbuild sc-hsm-minidriver-test\sc-hsm-minidriver-test.vcxproj /t:Clean;Rebuild /property:Configuration=Release;Platform=Win32

msbuild sc-hsm-minidriver-test\sc-hsm-minidriver-test.vcxproj /t:Clean;Rebuild /property:Configuration=Debug;Platform=Win32

msbuild ram-client\ram-client.vcxproj /t:Clean;Rebuild /property:Configuration=Release;Platform=Win32

msbuild ram-client\ram-client.vcxproj /t:Clean;Rebuild /property:Configuration=Debug;Platform=Win32
