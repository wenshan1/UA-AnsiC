OPC UA ANSI C Stack
-------------------

Please read this entire file BEFORE using the ANSI C stack. These instructions will save you a lot
of time enabling you to compile and run the source code quickly and easily.



1. Development Environment:

				This ANSI C UA Stack source code includes a Microsoft Visual Studio 2008 solution
				(UA AnsiC Stack.sln) and an implementation of the platform layer interface for
				the Win32 API, and OpenSSL. All build and configuration descriptions in this
				document refer to VS2008 settings and project layout.


2. Third Party Components:

				OpenSSL v0.9.8i was used in development and testing of this stack and is required
				for the Crypto and PKI implementations, and must be installed on the build machine
				at specific locations (see "3. Project Structure and Components"). If you need to
				use a different version (because of bug fixes or availability in your system) you
				may have to update the implementation particularly if the OpenSSL API has changed.

				OpenSSL has several algorithms which are patented and have import/export restrictions
				to some states, therefore please download a copy from the project website
				(http://www.openssl.org/source). Please consult the OpenSSL documentation for
				help building the library.


3. Project Structure and Components:

				The following tree shows the directory layout as required by the included project:

				/-- ANSICStack
				 |  |- Documentation
				 |  |- SourceCode                   Location of Visual Studio Solution (*.SLN)
				 |     |- core                      Configuration and utilities
				 |     |- platforms
				 |        |- win32                  Platform adaption to OpenSSL and Win32 API
				 |     |- proxystub
				 |        |- clientproxy            Client side top level API (optional)
				 |        |- serverstub             Server side top level API (optional)
				 |     |- securechannel             OPC UA secure conversation
				 |     |- stackcore                 Base types and interfaces
				 |     |- test                      Samples and tests (optional)
				 |        |- PKI                    PKI directory sample used by test apps
				 |           |- ca                  root certificate
				 |           |- certs               Trusted certificates
				 |           |- crl                 Certificate revocation list
				 |           |- issuers             Issuer certificates
				 |           |- private             Private key
				 |        |- simpleuatestclient     Example client application
				 |        |- simpleuatestserver     Example server application
				 |        |- unittest               Unit test (several folders for components)
				 |     |- transport
				 |        |- https                  HTTPS transport (optional)
				 |        |- tcp                    OPC TCP Binary transport
				 |- third-party                     Required third-party libraries
					|- openssl
					   |- out32                     libeay32.lib, ssleay32.lib
					   |- out32.dbg                 libeay32.lib, ssleay32.lib
					   |- out32dll                  libeay32.lib, ssleay32.lib
					   |- out32dll.dbg              libeay32.lib, ssleay32.lib
					   |- inc32                     OpenSSL header files
						  |- openssl

				The components marked as optional may be removed through configuration flags which
				are described in the section "4. Project Configuration".

				The "test" folder contains three applications and a sample PKI structure. These
				applications are not platform independent and are targeted to the win32 platform.
				Feel free to adapt them to your target environment.

				The unit test applications contain a test framework and a set of test case
				implementations for testing the stack’s internal base classes and interfaces.
				If you port the stack to another platform then these tests provide an easy
				way to test your platform layer implementation; however, only low level functionality
				is tested. These test cases also serve as examples for using several basic interfaces.
				The test Client and Server applications serve as a starting point for your OPC UA
				application development as they show the basic steps an OPC UA application uses
				to initialize the stack API, invoke a UA service in the UA Client, and how to
				handle the service call in the UA Server. Both the Client and Server are programmed
				to communicate with each other by establishing a connection and using the special
				test stack service. More information about the demonstrations and their configuration
				follows in section "4. Project Configuration". These applications are samples which
				demonstrate aspects of the stack and are not OPC UA applications!

4. Project Configuration:

		Stack:

				The stack consists of two main components:
					- the platform-independent core component
					- the platform layer component.
				The core stack configuration is "core/opcua_configuration.h".
				The configuration of the platform layer depends on the implementation. The win32
				platform layer (included) is configured in "platforms/win32/opcua_p_interface.h"
				and "platforms/win32/opcua_platformdefs.h".
				Detailed information exists at the top of these files.
				All settings are described within the source code.

		Sample Client and Server:

				Both applications provide a large number of settings at the top of each file. Each
				application can run in single-thread or multi-threaded mode, use the synchronous
				or asynchronous API, as well as different security modes. You can change the trace
				settings and influence the content of the request and response. These options are
				documented in the source code.


5. Building from Source:

		With Security (requires OpenSSL):

				The default source code distribution assumes security is desired. Simply compile the code 
				as it is distributed. The following instructions will guide you through the entire process 
				of incorporating and using the exact same OpenSSL libraries that we used in testing.

			Preparing OpenSSL:

				1. Download and install Perl, if you do not have it installed: 
					a. Go to www.activeperl.com
					b. Download and install ActivePerl.

				2. Download the OpenSSL libraries. We tested version 0.9.8i
				   (http://www.openssl.org/source/openssl-0.9.8i.tar.gz)

				3. Using 7zip, extract the contents; you will have one file: openssl-0.9.8i.tar
				4. Using 7zip again, extract the contents from openssl-0.9.8i.tar.
				5. A folder called "openssl-0.9.8i" will exist with all source contained therein.
				6. Follow this guide to compile OpenSSL: 

				   NOTE: There are MANY, MANY ways of configuring and compiling OpenSSL.
				         Please review the INSTALL file within the openssl source folder. 
						 Instructions are provided for compiling x86, x64, single-thread or
						 multi-thread, debug or release, using VisualC or other tools etc.

				   a. Open a developer command prompt from the Visual Studio 2008 tools folder.
				   b. Go to the openssl that was extracted (e.g. openssl-0.9.8i)
				   c. Enter the following commands for Windows 32-bit:
						perl Configure VC-WIN32
						ms\do_masm
						nmake -f ms\nt.mak

				7. Copy the compiled openssl files to your ANSI C source code folder:
						copy <openssl>\inc32 <ansic>\third-party\openssl\
						copy <openssl>\out32 <ansic>\third-party\openssl\

						NOTE: <openssl> refers to the folder where your openssl source was compiled.
						      <ansic> refers to the folder where your UA ANSIC source resides.

				8. Everything should be ready to be able to compile the code (as is) within VSNET.

					NOTE: In some cases we have experienced errors compiling the source code due to errors within the 
						  openssl source code (generated earlier). In this case you may find errors in VSNET like this: 

						  "Error 1 error C2059: syntax error : 'type' c:\...\ossl_typ.h 178 UA AnsiC Win32 Platform Layer"

						  Simply double-click the error and then comment-out the offending line of code and then recompile.



		Without Security (does not require OpenSSL):

				You can build the Stack without OpenSSL by disabling the built-in support for the
				TLS transport (HTTPS), and the PKI and Crypto provider APIs (encryption and
				certificate handling). To achieve this set the following configuration parameters:

				platforms/win32/source files/opcua_p_interface.h:
					#define OPCUA_P_SOCKETMANAGER_SUPPORT_SSL                  OPCUA_CONFIG_NO

				platforms/win32/source files/opcua_platformdefs.h:
					#define OPCUA_HAVE_OPENSSL                                 0
					#define OPCUA_SUPPORT_SECURITYPOLICY_BASIC128RSA15         OPCUA_CONFIG_NO
					#define OPCUA_SUPPORT_SECURITYPOLICY_BASIC256              OPCUA_CONFIG_NO
					#define OPCUA_SUPPORT_PKI								   OPCUA_CONFIG_NO

				core/header files/opcua_config.h:
					# define OPCUA_HAVE_HTTPS                           	   OPCUA_CONFIG_NO

				test/simpleuatestserver/source files/uatestserver.c:
					#define UATESTSERVER_SUPPORT_SECURE_COMMUNICATION          0

				test/simpleuatestclient/source files/uatestclient.c:
					#define UATESTCLIENT_USE_SIGNING                           0
					#define UATESTCLIENT_USE_ENCRYPTION                        0

				Additionally, you must remove the OpenSSL libraries from the linker input settings
				of the included test applications (found in the "test" folder): 
					1. Right-click on the "simpleuatestserver" project 
					2. Choose "Properties"
					3. Go to Configuration Properties > Linker > Input
					4. Open the setting "Additional Dependencies" by clicking the "..." button
					5. Remove these files from the list:
							libeay32.lib
							ssleay32.lib

					6. Click OK to save and close the dialog.
					7. Repeat steps 2-6 for the "simpletestclient" project.
					8. Repeat steps 2-6 for the "unitTest" project.

				Lastly, we need to check a setting in the simpleuatestclient project properties: 
					1. right-click on the project and choose Properties
					2. go to Configuration Properties > Linker > Input and click "..." beside "Additional Dependencies"
					3. in the "Additional Dependences" check/enable the option "Inherit from parent or project defaults".

				Instruct visual studio to "Clean" the environment and then rebuild the solution.


6. History:

		Version 1.2.336

			Highlights:
				- Added FindServersOnNetwork and RegisterServer2 services.
				- Added Basic256Sha256 security policy.
	
			Mantis issues, resolved:
				- 3242 Basic256Sha256 iop problem with other stacks
				- 3108 Limit depth of recursion for variant arrays and diagnosticInfo
				- 2996 Possible inconsistency in function converting DateTime to String
				- 2682 Trace functionality needs to be extended with info about Trace Level
				- 2634 Wrong or out-date comments
				- 2628 Missing casts cause warning when compiling for x64
				- 2687 Error label using must be refactored
				- 2618 Need access to SecureChannel for cleaning up resources
				- 2657 FileType properties have typos
				- 2648 New SecurityToken should not be used directly
				- 2870 ever-recurrence of OPCUA_SOCKET_CLOSE_EVENT or OPCUA_SOCKET_SHUTDOWN_EVENT
				- 2565 Add implementation of SecurityPolicy Basic256Sha256

			Other:
				- Windows XP IPv6 socket not opening properly is now resolved.
				- Updated NodeIds from schemas/NodeIds.csv
				- Upgraded OpenSSL to 1.0.1p
				- Fixed and added a unit test for binary decoder recursion limit.




		Version 1.2.334 build #3

			Highlights:
				- NEW: Support for transport profile HTTPS Binary.
				- NEW: Support for certificate chains.
				- NEW: Influence certificate validation result in Endpoint event callback (new event type).
				- API Change: Added SSL certificate validation hook functionality to Channel event callback.
				- API Change: Endpoint and Channel API (creation and event callback).
				- API Change: New default (OpenSSL) PKI file store layout and configuration.
				- Change: Protocol handlers switched to non-blocking write on sockets.
				- Update: Types and Services adhere to the current Specification level (1.02).

			Mantis issues, resolved: 
				- 2518  trivial Implementation Bug  Copy/paste error in OpcUa_StatusCode OpcUa_CertificateStoreConfiguration_Clear
				- 2438  major   Implementation Bug  Crash in OpenSecureChannel handler during renew
				- 2406  minor   Implementation Bug  Wrong use of const together with OpcUa_StringA
				- 2440  minor   Implementation Bug  Pointer to Integer conversion problem on 64 bit systems in tcp listener connectionmanager class
				- 2439  major   Implementation Bug  Invalid unlock order for critical section in secure listener
				- 2338  minor   Implementation Bug  OpcUa_Guid conversion includes curly braces
				- 2398  block   Implementation Bug  Inconsistency between UpdateEventDetails in spec and stacks
				- 1885  minor   Implementation Bug  OpcUa_TcpListener_ProcessHelloMessage is a cause of memory leak possibly.
				- 1388  minor   Implementation Bug  Can't connect to or host on servers with extended Unicode characters in their host-name (Win32 only).
				- 1839  major   Implementation Bug  OpcUa_TcpListener_ConnectionManager_Initialize() does not provide address of mutex
				- 1835  minor   API Change  Problem with key length larger 2048 bits
				- 2117  major   API Change  CA certificates can not be separated from trust list
				- 2073  major   Feature Request Add HTTPS protocol mapping to AnsiC Stack
				- 2213  minor   Implementation Bug  Integration of several minor fixes, improvements and code tweaks from Unified Automation
				- 2212  major   Implementation Bug  Secure channel may get closed without notifying the application
				- 1312  minor   Performance Problem Inefficiency in the OpenSSL CStack OpcUa_P_OpenSSL_SeedPRNG function.
				- 2122  major   API Change  Memory leaks
				- 2116  major   API Change  Optional security checks for certificates
				- 1816  minor   Feature Request It would be nice to see in trace message a Level Trace flag.
				- 2119  minor   API Change  Open Secure Channel policy None
				- 2123  minor   Feature Request Client Peer information
				- 2115  major   API Change  UaServer_EndpointCallback missing information for AuditOpenSecureChannelEventType
				- 2118  minor   API Change  Remove function pointer list for platform layer
				- 2124  major   Implementation Bug  Memory Leak in OpcUa_TcpListener_ConnectionManager_RemoveConnections (opcua_tcplistener_connectionmanager.c)
				- 2099  minor   Implementation Bug  Inconsistency in OpcUa_EndpointDescription name attribute



7. Talk to us:
--------------
	Have improvement suggestions?
		Tell us at uaansicstack@opcfoundation.org 

	Found a bug in the source code? 
		Please log a bug at www.opcfoundation.org/mantis 