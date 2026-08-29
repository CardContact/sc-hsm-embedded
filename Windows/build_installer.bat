
set WIXBIN="c:\Program Files (x86)\WiX Toolset v3.11\bin"

set VERSION=2.13.0
set DEBREL=Release

%WIXBIN%\candle -arch x64 installer.wxs -dPlatform=x64 -dDebRel=%DEBREL% -dVersion=%VERSION%
%WIXBIN%\light -out sc-hsm-middleware-x64.msi installer.wixobj
