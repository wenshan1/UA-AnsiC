@ECHO off
REM ****************************************************************************************************************
REM ** This script builds CURL for use by the ANSI C samples.
REM ** This requires CMAKE to be installed.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set CMAKEEXE=cmake
set SRCDIR=%~dp0\src\curl
set INSTALLDIR=%~dp0

IF NOT EXIST %SRCDIR% GOTO noSource
cd %SRCDIR%

IF "%1"=="no-clean" GOTO noClean
ECHO STEP 1) Deleting old projects.
IF EXIST %INSTALLDIR%\curl rmdir /s /q %INSTALLDIR%\curl
IF EXIST .\build rmdir /s /q .\build
:noClean

IF NOT EXIST .\build MKDIR .\build

ECHO STEP 2) Running CMAKE...
set OpenSSLDir=%INSTALLDIR%\openssl
cd .\build
%CMAKEEXE% -DHTTP_ONLY:BOOL=ON -DBUILD_CURL_EXE:BOOL=OFF -DCMAKE_INSTALL_PREFIX=%INSTALLDIR%\curl ..

ECHO STEP 3) Building project...
msbuild /t:libcurl /p:Configuration=Debug CURL.sln

ECHO STEP 4) Install CURL...
msbuild INSTALL.vcxproj /p:Configuration=Debug 

ECHO *** ALL DONE ***
GOTO theEnd

:noSource
ECHO.
ECHO CURL source not found. Please check the path.
ECHO Searched for: %SRCDIR%
GOTO theEnd

:theEnd
ENDLOCAL