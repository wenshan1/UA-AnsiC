@ECHO off
REM ****************************************************************************************************************
REM ** This script builds the ANSI-C WebSockets samples.
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
set OPENSSL_ROOT_DIR=%INSTALLDIR%..\..\third-party\openssl
cd .\build
%CMAKEEXE% .. -DCMAKE_INSTALL_PREFIX=%INSTALLDIR%

ECHO STEP 2) Building project...
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug 

ECHO STEP 4) Install Samples...

msbuild  INSTALL.vcxproj /p:Configuration=Debug 
cd ..

ECHO *** ALL DONE ***
GOTO theEnd

:theEnd
ENDLOCAL