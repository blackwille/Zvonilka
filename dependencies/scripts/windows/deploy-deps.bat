@echo on
setlocal enabledelayedexpansion

REM Get the script directory and navigate up three levels
set "SCRIPT_DIR=%~dp0"
set "DEPENDENCIES_DIR=%SCRIPT_DIR%..\.."
set "DEPENDENCIES_DIR=%DEPENDENCIES_DIR:\=\%"

REM Convert to absolute path
for %%I in ("%DEPENDENCIES_DIR%") do set "DEPENDENCIES_DIR=%%~fI"

REM Set installation directory
set "INSTALL_BIN_DIR=%DEPENDENCIES_DIR%\..\deploy\windows\bin"
set "INSTALL_BIN_DIR=%INSTALL_BIN_DIR:\=\%"

set "MINGW_BIN=C:\msys64\mingw64\bin"
REM Copying MinGW runtime DLLs...
for %%f in (libgcc_s_seh-1.dll libwinpthread-1.dll libstdc++-6.dll) do (
    if exist "%MINGW_BIN%\%%f" (
        copy /y "%MINGW_BIN%\%%f" "%INSTALL_BIN_DIR%\" >nul && (
            echo   Copied %%f to %INSTALL_BIN_DIR%
        ) || (
            echo   ERROR copying %%f
        )
    ) else (
        echo   WARNING: %%f not found in %MINGW_BIN%
    )
)
