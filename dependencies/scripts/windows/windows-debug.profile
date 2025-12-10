[settings]
os=Windows
arch=x86_64
build_type=Debug
compiler=gcc
compiler.version=14
compiler.cppstd=20
compiler.libcxx=libstdc++11

[conf]
tools.cmake.cmaketoolchain:generator=Ninja

[buildenv]
CFLAGS=-Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=implicit-function-declaration
CXXFLAGS=-Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=implicit-function-declaration
CC=clang
CXX=clang++
