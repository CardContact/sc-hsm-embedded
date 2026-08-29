# Compiling on Windows with MSYS2

Install [MSYS2](https://www.msys2.org/).

Open MSYS2 UCRT terminal.

Install compiler

    pacman -S mingw-w64-ucrt-x86_64-gcc

Install meson

    pacman -S mingw-w64-ucrt-x86_64-meson

Install CA Certificates

    pacman -S mingw-w64-ucrt-x86_64-ca-certificate

Install libcurl

    pacman -S mingw-w64-ucrt-x86_64-curl

Create build environment

    meson setup --prefer-static build

Build

    cd build
    meson compile -v

