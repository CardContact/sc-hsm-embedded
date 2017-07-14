set WIXBIN="c:\Program Files (x86)\WiX Toolset v3.11\bin"

set DEBREL=Debug

%WIXBIN%\candle -arch x86 installer.wxs -dPlatform=x86 -dDebRel=%DEBREL% -dVersion=2.10.0
%WIXBIN%\light -out sc-hsm-middleware-x86.msi installer.wixobj

%WIXBIN%\candle -arch x64 installer.wxs -dPlatform=x64 -dDebRel=%DEBREL% -dVersion=2.10.0
%WIXBIN%\light -out sc-hsm-middleware-x64.msi installer.wixobj
