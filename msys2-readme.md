# Compiling on Windows with MSYS2

Install [MSYS2](https://www.msys2.org/).

Open MSYS2 UCRT terminal.

Install compiler

    pacman -S mingw-w64-ucrt-x86_64-gcc

Install meson

    pacman -S mingw-w64-ucrt-x86_64-meson

Install CA Certificates

    pacman -S mingw-w64-ucrt-x86_64-ca-certificate

Create build environment

    meson setup build-win

Build

    cd build-win
    meson compile

Bundle src/ramoverthttp/ram-client.exe with libcurl-4.dll libwinpthread-1.dll libzstd.dll zlib1.dll
from /msys64/ucrt64/lib.
