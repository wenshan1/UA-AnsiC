# ANSI-C AMQP Sample Subscriber and Publisher

## Overview
This package contains sample application which publish and consume JSON messages sent via AMQP.
The samples include BAT files with the credentials for 2 OPC Foundaton prototype AMQP broker instances:

  1. Azure ServiceBus at opcfoundation-prototyping.servicebus.windows.net
  2. ActiveMQ at opcfoundation-prototyping.org

## Prerequistes
The samples require that the following third party projects be built:
  1. openssl
  2. azure-uamqp-c
  3. json-c
  
The [README](..\..\third-party\readme.md) for the third-party folder has more information.
  
## Building the Samples
```
mkdir build
cd build
cmake ..
msbuild ALL_BUILD.vcxproj /p:Configuration=Debug 
```

Cmake can be downloaded from here: https://cmake.org/download/
After building the executables are in the build\<project name>\Debug directory.

## Running the Samples
Both samples take the same input arguments:

    - "-h" or "-help": Calls the help function. 
    - "-b": The broker url (starting with amqps://)
    - "-u": The broker username
    - "-p": The broker password
    - "-t": The broker AMQP node name (e.g. Queue or Topic Name)
	- "-i": The number of messages to send or receive before exiting.
  
The username and password must be [URLencoded](http://meyerweb.com/eric/tools/dencoder/).
Batch files for the 2 sample brokers are copied into the output directory when cmake runs.
