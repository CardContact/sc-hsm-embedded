
msbuild /t:clean,build /property:Configuration=Debug;Platform=Win32
msbuild /t:clean,build /property:Configuration=Release;Platform=Win32
msbuild /t:clean,build /property:Configuration=Debug;Platform=x64
msbuild /t:clean,build /property:Configuration=Release;Platform=x64

set WIXBIN="c:\Program Files (x86)\WiX Toolset v3.11\bin"

set VERSION=2.12.0
set DEBREL=Debug

%WIXBIN%\candle -arch x86 installer.wxs -dPlatform=x86 -dDebRel=Release -dVersion=%VERSION%
%WIXBIN%\light -out sc-hsm-middleware-x86.msi installer.wixobj

%WIXBIN%\candle -arch x64 installer.wxs -dPlatform=x64 -dDebRel=Release -dVersion=%VERSION%
%WIXBIN%\light -out sc-hsm-middleware-x64.msi installer.wixobj

%WIXBIN%\candle -arch x86 installer.wxs -dPlatform=x86 -dDebRel=Debug -dVersion=%VERSION%
%WIXBIN%\light -out sc-hsm-middleware-x86-debug.msi installer.wixobj

%WIXBIN%\candle -arch x64 installer.wxs -dPlatform=x64 -dDebRel=Debug -dVersion=%VERSION%
%WIXBIN%\light -out sc-hsm-middleware-x64-debug.msi installer.wixobj
