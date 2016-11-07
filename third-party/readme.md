# UA-ANSIC Third Party Library Readme #
## Overview ##
This directory contains references to other GitHub projects which the samples depend on.
For each project there is BATCH file which builds and installes the headers and libs in the third-party directory.
The source respository must be cloned first.

## azure-uamqp-c ##
uAMQP is a general purpose C library for AMQP.

The respository is here: https://github.com/Azure/azure-uamqp-c.git

The command to clone is:

```
cd src
git clone --recursive https://github.com/Azure/azure-uamqp-c.git
```

## json-c ##
A simple JSON parser.
Home page for json-c: https://github.com/json-c/json-c/wiki
The respository is here: https://github.com/json-c/json-c.git

The command to clone is:

```
cd src
git clone https://github.com/json-c/json-c.git
```

## openssl ##
An open source cryptography library.
The respository is here: https://github.com/openssl/openssl.git

The command to clone is:

```
cd src
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout tags/OpenSSL_1_0_2h
```

As new versions are published the tag reference in the command above should be adjusted accordingly.

## curl ##
A library for using HTTPS
The respository is here: https://github.com/curl/curl

The command to clone is:

```
cd src
git clone https://github.com/curl/curl
cd openssl
git checkout tags/curl-7_48_0
```

Versions >curl-7_48_0 will produce compile errors with test programs.
When this issue is fixed this readme will be updated.