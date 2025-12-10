@echo on
rem Firstly MSYS2:
rem Install mingw-w64 with clang, gcc, ninja, cmake, toolchain...
rem Python, conan...
rem Then you can execute this file.
set DEPENDENCIES_DIR=%~dpnx0\..\..\..
conan install "%DEPENDENCIES_DIR%" ^
    --build=missing ^
    -pr:h=%~dpnx0\..\windows-debug.profile ^
    -pr:b=%~dpnx0\..\windows-debug.profile
