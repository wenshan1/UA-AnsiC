@ECHO off
REM ****************************************************************************************************************
REM ** This script builds Json-C for use by the ANSI C samples.
REM ** This requires CMAKE to be installed.
REM ** This must be run from a Visual Studio command line.
REM ****************************************************************************************************************
SETLOCAL

set CMAKEEXE=cmake
set SRCDIR=%~dp0\src\json-c
set INSTALLDIR=%~dp0

IF NOT EXIST %SRCDIR% GOTO noSource

cd %SRCDIR%

IF "%1"=="no-clean" GOTO noClean
ECHO STEP 1) Deleting old projects.
IF EXIST .\build rmdir /s /q .\build
:noClean

IF NOT EXIST .\build MKDIR .\build

ECHO STEP 2) Running CMAKE...
cd .\build
%CMAKEEXE% ..

ECHO STEP 3) Building project...
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug 

ECHO STEP 4) Install Json-C...

cd ..
IF NOT EXIST %INSTALLDIR%\json-c MKDIR %INSTALLDIR%\json-c
IF NOT EXIST %INSTALLDIR%\json-c\include MKDIR %INSTALLDIR%\json-c\include
IF NOT EXIST %INSTALLDIR%\json-c\lib MKDIR %INSTALLDIR%\json-c\lib

XCOPY /Y /Q ".\build\Debug\*.*" "%INSTALLDIR%\json-c\lib"
XCOPY /Y /Q ".\*.h" "%INSTALLDIR%\json-c\include" 
XCOPY /Y /Q ".\build\include\*.h" "%INSTALLDIR%\json-c\include" 

ECHO *** ALL DONE ***
GOTO theEnd

:noSource
ECHO.
ECHO Json-C source not found. Please check the path.
ECHO Searched: %SRCDIR%
GOTO theEnd

:theEnd
ENDLOCAL