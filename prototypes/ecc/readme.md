OPC UA ANSIC<->NET ECC Test Program
------------------------------

This program is used to test interoperability between .NET and OpenSSL ECC APIs.
Requires VS2017 with .NET Framework 4.7.1.

Build steps:

1) Fetch submodules:
git submodule update --init --recursive

2) Build OpenSSL:
cd .\third-party
build_openssl.bat

3) Build samples:
cd .\prototypes\ecc
EccTestClient.sln

The sample creates an OpenSecureChannelRequest in .NET which contains an ephemeral key and a ECDSA signature.
The ANSI C code verifies the ECDSA signature, generates an ephemeral key and returns an OpenSecureChannelResponse.
The .NET verifies ECDSA signature and checks that the 'server' shared secret is the same as the 'client' shared secret.
