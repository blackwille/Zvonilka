@echo on
setlocal enabledelayedexpansion

REM Get the script directory and navigate up three levels
set "SCRIPT_DIR=%~dp0"
set "DEPENDENCIES_DIR=%SCRIPT_DIR%..\.."
set "DEPENDENCIES_DIR=%DEPENDENCIES_DIR:\=\%"

REM Convert to absolute path
for %%I in ("%DEPENDENCIES_DIR%") do set "DEPENDENCIES_DIR=%%~fI"

REM Set installation directory
set "INSTALL_BASE_DIR=%DEPENDENCIES_DIR%\..\deploy\windows"
set "INSTALL_BIN_DIR=%INSTALL_BASE_DIR%\bin"
set "INSTALL_BIN_DIR=%INSTALL_BIN_DIR:\=\%"

REM Create windows and windows/bin directories if they don't exist
if not exist "%INSTALL_BASE_DIR%" (
    mkdir "%INSTALL_BASE_DIR%"
    echo   Created directory: %INSTALL_BASE_DIR%
)
if not exist "%INSTALL_BIN_DIR%" (
    mkdir "%INSTALL_BIN_DIR%"
    echo   Created directory: %INSTALL_BIN_DIR%
)

REM Check if MinGW bin directory exists
set "MINGW_BIN=C:\msys64\mingw64\bin"
if not exist "%MINGW_BIN%\" (
    echo   ERROR: MinGW directory not found: %MINGW_BIN%
    echo   Please check your MinGW installation.
    pause
    exit /b 1
)

echo   Copying MinGW runtime DLLs...
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

echo   Done.
pause
