# OPC Foundation UA ANSI C Stack - Prototyping Branch

The OPC Foundation has formally released the OPC Unified Architecture ANSI C Stack and Sample Code to the community.

Please review official site page (http://opcfoundation.github.io/UA-AnsiC/) for:
 * Overview
 * Licensing
 * Sample Applications overview

## Contributing

We strongly encourage community participation and contribution to this project. First, please fork the repository and commit your changes there. Once happy with your changes you can generate a 'pull request'.

You must agree to the contributor license agreement before we can accept your changes. The CLA and "I AGREE" button is automatically displayed when you perform the pull request. You can preview CLA [here](https://opcfoundation.org/license/cla/ContributorLicenseAgreementv1.0.pdf).

OPC UA, empowering the Industrial Internet of Things (IIOT) and Industrie 4.0.
 
## Building the Projects
Projects in the Prototyping branch are build with CMake.
It can be downloaded here:
https://cmake.org/download/

After cloning the repository the subprojects in the third-party directory need to be fetched using this command:
```
cd third-party
git submodule update --init --recursive
```

The batch files in the third-party directory are used to build the different libraries.
build_openssl.bat and build_json.bat must be run for all projects.
build_curl.bat is needed for the oauth2 project.
build_azure-uamqp-c.bat is needed for the amqp project. 

Once the third-party libraries are built each project can be built from a Visual Studio command prompt:
```
cd prototypes/<project name>
mkdir build
cd build
cmake ..
```

Each project has a batch file called 'build_<project name>' which does the above.

A Visual Studio solution will appear in the build subdirectory.

### Package file structure description

The following tree shows the directory layout as required by the included project:

- /-- UA-AnsiC
- |  |- Stack                   
- |     |- core                      Configuration and utilities
- |     |- platforms
- |        |- linux                  Platform adaption to OpenSSL and linux API
- |        |- win32                  Platform adaption to OpenSSL and Win32 API
- |     |- proxystub
- |        |- clientproxy            Client side top level API (optional)
- |        |- serverstub             Server side top level API (optional)
- |     |- securechannel             OPC UA secure conversation
- |     |- stackcore                 Base types and interfaces
- |     |- transport
- |        |- https                  HTTPS transport (optional)
- |        |- tcp                    OPC TCP Binary transport
- |- prototypes   					 Root directory for all prototype projects.
- |  |- amqp						 Sample subscribers and publishers that use AMQP.
- |  |- oauth2						 Sample clients that use OAuth2 to request user identity tokens.
- |  |- websockets				 	 Sample client and server which implement the WebSockets transport. 


## Known issues


