@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the ANSI-C OAuth2 samples.
REM ** This requires CMAKE to be installed.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set CMAKEEXE=cmake
set SRCDIR=%~dp0
set INSTALLDIR=%~dp0

IF "%1"=="no-clean" GOTO noClean
ECHO STEP 1) Deleting old projects.
IF EXIST %INSTALLDIR%\bin rmdir /s /q %INSTALLDIR%\bin
IF EXIST .\build rmdir /s /q .\build
:noClean

IF NOT EXIST .\build MKDIR .\build

ECHO STEP 1) Running CMAKE...
set OPENSSL_ROOT_DIR=%INSTALLDIR%\..\..\third-party\openssl
cd .\build
%CMAKEEXE% ..

ECHO STEP 2) Building project...
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug 

ECHO STEP 4) Install Samples...

cd ..
IF NOT EXIST %INSTALLDIR% MKDIR %INSTALLDIR%
IF NOT EXIST %INSTALLDIR%\bin MKDIR %INSTALLDIR%\bin

XCOPY /Y /Q /I /S ".\build\tlstestclient\Debug\*.*" "%INSTALLDIR%\bin"
XCOPY /Y /Q /I /S ".\build\tlstestserver\Debug" "%INSTALLDIR%\bin"
XCOPY /Y /Q /I /S ".\PKI" "%INSTALLDIR%\bin\PKI"

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL