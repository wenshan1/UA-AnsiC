@ECHO off
REM ****************************************************************************************************************
REM ** This script builds Azure-uAMQP-C for use by the ANSI C samples.
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

ECHO STEP 2) Running CMAKE...
set OpenSSLDir=%INSTALLDIR%\openssl
cd .\build
%CMAKEEXE% ..

ECHO STEP 3) Building project...
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug 

ECHO STEP 4) Install Samples...

cd ..
IF NOT EXIST %INSTALLDIR% MKDIR %INSTALLDIR%
IF NOT EXIST %INSTALLDIR%\bin MKDIR %INSTALLDIR%\bin

XCOPY /Y /Q ".\build\amqp_ansic_publisher\Debug\*.*" "%INSTALLDIR%\bin"
XCOPY /Y /Q ".\build\amqp_ansic_subscriber\Debug\*.*" "%INSTALLDIR%\bin"

ECHO *** ALL DONE ***
GOTO theEnd

:noSource
ECHO.
ECHO Azure-uAMQP-C source not found. Please check the path.
ECHO Searched for: %SRCDIR%
GOTO theEnd

:theEnd
ENDLOCAL