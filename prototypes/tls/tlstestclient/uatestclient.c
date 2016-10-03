/* ========================================================================
 * Copyright (c) 2005-2011 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

/*********************************************************************************************/
/*****************     A simple UA test client based on the Ansi C Stack     *****************/
/*********************************************************************************************/

/*********************************************************************************************/
/***********************                     Config                   ************************/
/*********************************************************************************************/
/* !0 == active, 0 == inactive */
/* use visual studio debug heap */
#define UATESTCLIENT_USE_CRTDBG                             1
/* use visual leak detector for visual studio */
#define UATESTCLIENT_USE_VISUAL_LEAK_DETECTOR               0
/* client signs the messages */
#define UATESTCLIENT_USE_SIGNING                            1
/* client encrypts the messages */
#define UATESTCLIENT_USE_ENCRYPTION                         1
/* use the synchronous api - only possible when multithreading is supported */
#define UATESTCLIENT_USE_SYNC_API                           1
/* standard timeout for connect process */
#define UATESTCLIENT_TIMEOUT                                OPCUA_INFINITE
/* URL of the server */
#define UATESTCLIENT_SERVER_URL                             "opc.tcp://localhost:48040"
#define UATESTCLIENT_SERVER_TLS_URL                         "opc.tls://localhost:48043"
/* wait for user input after shutting down */
#define UATESTCLIENT_WAIT_FOR_USER_INPUT                    1
/* how often the request should be repeated */
#define UATESTCLIENT_NO_OF_REQUESTS                         1
/* set to 1 if the client should stop when a request finishes with error. */
#define UATESTCLIENT_BREAK_ON_ERROR                         1
/* set to 1 to use the content of UaTestClient_g_HugeCharArray instead of the string Hello for requests. */
#define UATESTCLIENT_LARGE_REQUEST                          0
/* defines how often the connect-requests-disconnect cycle is executed before this application terminates. */
#define UATESTCLIENT_NUMBER_OF_CONNECTS                     1
/* the used trace level */
#define UATESTCLIENT_TRACE_LEVEL                            OPCUA_TRACE_OUTPUT_LEVEL_SYSTEM
/* defines whether Win32 PKI is used or OpenSSL */
#define UATESTCLIENT_USEWIN32PKI                            0
/* select request variant content (string or UINT32 array) */
#define UATESTCLIENT_STRING_REQUEST                         1
/* use selfsigned certificate as application certificate */
#define UATESTCLIENT_SELFSIGNED                             1

#if UATESTCLIENT_LARGE_REQUEST
    /* define the size in bytes of the large requests body (count of elements in UaTestClient_g_HugeCharArray). */
    #define UATESTCLIENT_LARGE_BODY                         4194304
#endif /* UATESTCLIENT_LARGE_REQUEST */

#if !UATESTCLIENT_STRING_REQUEST
    /* define the number of elements in the UInt32 array  (count of elements in UaTestClient_g_UInt32Array). */
    #define UATESTCLIENT_UINT32_ARRAY_SIZE                  1000
#endif /* UATESTCLIENT_STRING_REQUEST */

/* PKI Locations - this may need to be changed with other platform layers! */
#if UATESTCLIENT_USEWIN32PKI
#define UATESTCLIENT_CERTIFICATE_TRUST_LIST_LOCATION                "UA Applications"
#define UATESTCLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION           "UA Applications"
#define UATESTCLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION         "UA Certificate Authorities"
#define UATESTCLIENT_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION    "UA Certificate Authorities"
#define UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION                    L"UA Sample Client"
#define UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION                    (OpcUa_CharA*)L"UA Sample Client"
#define UATESTCLIENT_SERVER_CERTIFICATE_LOCATION                    L"UA Sample Server"
#else /* UATESTCLIENT_USEWIN32PKI */
#if 1 /* UA TCP */

#if UATESTCLIENT_SELFSIGNED
#define UATESTCLIENT_CERTIFICATE_TRUST_LIST_LOCATION                "./PKI/certs/"
#define UATESTCLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION           "./PKI/crl/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION         "./PKI/issuers/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION    "./PKI/crl/"
#define UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION                    "./PKI/certs/selfsigned.der"
#define UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION                    "./PKI/private/selfsignedkey.pem"
#else /* UATESTCLIENT_SELFSIGNED */
#define UATESTCLIENT_CERTIFICATE_TRUST_LIST_LOCATION                "../PKI/certs/"
#define UATESTCLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION           "../PKI/crl/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION         "../PKI/issuers/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION    "../PKI/crl/"
#define UATESTCLIENT_CLIENT_CA_CERTIFICATE_LOCATION                 "../PKI/ca/rootca.der"
#define UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION                    "../PKI/certs/rootcasigned.der"
#define UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION                    "../PKI/private/rootcasignedkey.pem"
#endif /* UATESTCLIENT_SELFSIGNED */

#define UATESTCLIENT_SERVER_CERTIFICATE_LOCATION                    "./PKI/certs/selfsigned.der"

#else /* HTTPS */

#define UATESTCLIENT_CERTIFICATE_TRUST_LIST_LOCATION                "../PKI/CA/certs/"
#define UATESTCLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION           "../PKI/CA/crl/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION         "../PKI/CA/issuers/"
#define UATESTCLIENT_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION    "../PKI/CA/crl/"
#define UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION                    OpcUa_Null
#define UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION                    OpcUa_Null
#define UATESTCLIENT_SERVER_CERTIFICATE_LOCATION                    OpcUa_Null
#endif
#endif /* UATESTCLIENT_USEWIN32PKI */

/* configuration checks */
#if UATESTCLIENT_USE_SIGNING || UATESTCLIENT_USE_ENCRYPTION
    #define UATESTCLIENT_USE_SECURE_COMMUNICATION               1
#else
    #define UATESTCLIENT_USE_SECURE_COMMUNICATION               0
#endif

#if UATESTCLIENT_USE_ENCRYPTION
    #if UATESTCLIENT_USE_SIGNING
        /* encryption always includes signing - undef for evaluation only */
        #undef UATESTCLIENT_USE_SIGNING
    #endif
#endif

#if UATESTCLIENT_USE_SECURE_COMMUNICATION
    /* verify the servers certificate after loading, before connecting */
    #define UATESTCLIENT_VERIFY_SERVER_CERTIFICATE_LOCALLY  1
    /* verify the clients certificate after loading, before connecting */
    #define UATESTCLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY  1
#endif

/* switch between security policies based on above configuration */
#if UATESTCLIENT_USE_ENCRYPTION
    #define UATESTCLIENT_SECURITY_POLICY                    OpcUa_SecurityPolicy_Basic256
    #define UATESTCLIENT_SECURITY_POLICY_LENGTH             OpcUa_StrLenA(OpcUa_SecurityPolicy_Basic256)
    #define UATESTCLIENT_SECURITY_MODE                      OpcUa_MessageSecurityMode_SignAndEncrypt
#endif

#if UATESTCLIENT_USE_CRTDBG
    #ifndef _WIN32
        #undef UATESTCLIENT_USE_CRTDBG
    #endif /* _WIN32  */
#endif /* UATESTCLIENT_USE_CRTDBG */

/*********************************************************************************************/
/***********************                     Header                   ************************/
/*********************************************************************************************/
/* system */
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <conio.h>
#else
#include <sys/socket.h>
#endif /* _WIN32  */

#include <stdio.h>

#if UATESTCLIENT_USE_CRTDBG
#include <crtdbg.h>
#endif /* UATESTCLIENT_USE_CRTDBG */

/* vld */
#if UATESTCLIENT_USE_VISUAL_LEAK_DETECTOR
#include <vld.h>
#endif /* UATESTCLIENT_USE_VISUAL_LEAK_DETECTOR */

/* ProxyStub */
#include <opcua_clientproxy.h>
#include <opcua_memory.h>
#include <opcua_core.h>
#include <opcua_trace.h>
#include <opcua_string.h>

#if OPCUA_HAVE_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/*********************************************************************************************/
/***********************                    Types                     ************************/
/*********************************************************************************************/
typedef struct _UaTestClient_CertificateLocations
{
    OpcUa_StringA CertificateRevocationListLocation;
    OpcUa_StringA CertificateTrustListLocation;
    OpcUa_StringA ClientCertificateLocation;
    OpcUa_StringA ClientPrivateKeyLocation;
    OpcUa_StringA ServerCertificateLocation;
} UaTestClient_CertificateLocations;

#if !UATESTCLIENT_USE_SYNC_API

typedef enum _eUaTestClient_State
{
    UaTestClient_e_Invalid,
    UaTestClient_e_Connecting,
    UaTestClient_e_Connected,
    UaTestClient_e_Request,
    UaTestClient_e_Disconnecting,
    UaTestClient_e_Disconnected
} UaTestClient_State;

typedef struct _UaTestClient_AsyncContext
{
    OpcUa_Channel       hChannel;
    UaTestClient_State  eState;
    OpcUa_UInt32        uRemainingNumberOfRequests;
    /* other stuff - like session info for example */
} UaTestClient_AsyncContext;

#endif /* !UATESTCLIENT_USE_SYNC_API */

/*********************************************************************************************/
/***********************                 Prototypes                   ************************/
/*********************************************************************************************/

#if !UATESTCLIENT_USE_SYNC_API
OpcUa_StatusCode UaTestClient_DoAsyncRequest(UaTestClient_AsyncContext* pAsyncContext);
#endif /* !UATESTCLIENT_USE_SYNC_API */

/*********************************************************************************************/
/***********************                  Globals                     ************************/
/*********************************************************************************************/
OpcUa_Handle                                UaTestClient_g_pPortLayerHandle          = OpcUa_Null;
OpcUa_StatusCode                            UaTestClient_g_uStatus                   = OpcUa_Good;

/* security configuration */
OpcUa_PKIProvider                           UaTestClient_g_PkiProvider               = { OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null };
OpcUa_String*                               UaTestClient_g_pSecurityPolicy           = OpcUa_Null;
OpcUa_MessageSecurityMode                   UaTestClient_g_SecurityMode              = UATESTCLIENT_SECURITY_MODE;
OpcUa_ByteString                            UaTestClient_g_ClientCertificate         = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ByteString                            UaTestClient_g_ServerCertificate         = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ByteString                            UaTestClient_g_ClientPrivateKey          = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ProxyStubConfiguration                UaTestClient_g_pProxyStubConfiguration;
OpcUa_P_OpenSSL_CertificateStore_Config     UaTestClient_g_PkiConfig;

#if UATESTCLIENT_STRING_REQUEST

#if UATESTCLIENT_LARGE_REQUEST
OpcUa_CharA                                 UaTestClient_g_HugeCharArray[UATESTCLIENT_LARGE_BODY];
#endif /* UATESTCLIENT_LARGE_REQUEST */

#else /* UATESTCLIENT_STRING_REQUEST */

OpcUa_Int32                                 UaTestClient_g_UInt32ArrayLength        = UATESTCLIENT_UINT32_ARRAY_SIZE;
OpcUa_UInt32                                UaTestClient_g_UInt32Array[UATESTCLIENT_UINT32_ARRAY_SIZE];

#endif /* UATESTCLIENT_STRING_REQUEST */

/*********************************************************************************************/
/***********************               Internal Helpers               ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Configuration checks.                                                             */
/*===========================================================================================*/
#if UATESTCLIENT_USE_SYNC_API
    #if !OPCUA_MULTITHREADED
        #error Synchronous API only available in multithread configuration!
    #endif /* OPCUA_MULTITHREADED */
#endif /* UATESTCLIENT_USE_SYNC_API */

/*===========================================================================================*/
/** @brief Wait for x to be pressed.                                                         */
/*===========================================================================================*/
OpcUa_Boolean UaTestClient_CheckForKeypress()
{
    if(!_kbhit()){}else{if (_getch()=='x'){return 1;}}return 0;
}

/*===========================================================================================*/
/** @brief Sets a servers and clients certificate and private key.                           */
/*===========================================================================================*/
static OpcUa_StatusCode UaTestClient_InitializePKI()
{
    OpcUa_Handle        hCertificateStore   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "InitializePKI");

#if UATESTCLIENT_USE_SECURE_COMMUNICATION
#if UATESTCLIENT_USEWIN32PKI
    UaTestClient_g_PkiConfig.strPkiType                                 = OPCUA_P_PKI_TYPE_WIN32;
    UaTestClient_g_PkiConfig.uFlags                                     = OPCUA_P_PKI_WIN32_STORE_MACHINE;
#else  /* UATESTCLIENT_USEWIN32PKI */ 
    UaTestClient_g_PkiConfig.PkiType                                    = OpcUa_OpenSSL_PKI;
#endif /* UATESTCLIENT_USEWIN32PKI */
#else /* UATESTCLIENT_USE_SECURE_COMMUNICATION */
    UaTestClient_g_PkiConfig.strPkiType                                 = OPCUA_PKI_TYPE_NONE;
#endif

    UaTestClient_g_PkiConfig.CertificateTrustListLocation      = UATESTCLIENT_CERTIFICATE_TRUST_LIST_LOCATION;
    UaTestClient_g_PkiConfig.CertificateRevocationListLocation = UATESTCLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION;
    UaTestClient_g_PkiConfig.CertificateUntrustedListLocation  = UATESTCLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION;

    /****************************** create PKI Config ******************************/
    uStatus = OpcUa_PKIProvider_Create(&UaTestClient_g_PkiConfig, &UaTestClient_g_PkiProvider);
    OpcUa_ReturnErrorIfBad(uStatus);

#if UATESTCLIENT_USE_SECURE_COMMUNICATION

    /* Open Certificate Store */
    uStatus = UaTestClient_g_PkiProvider.OpenCertificateStore(  &UaTestClient_g_PkiProvider, 
                                                                &hCertificateStore);
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to open certificate store! (0x%08X)\n", uStatus);
        OpcUa_GotoError;
    }

#ifdef UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION

#if UATESTCLIENT_SELFSIGNED

    /*** Get client certificate ***/
    uStatus = UaTestClient_g_PkiProvider.LoadCertificate(   &UaTestClient_g_PkiProvider,
                                                            UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION,
                                                            hCertificateStore,
                                                            &UaTestClient_g_ClientCertificate);
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to load client certificate \"%s\"! (0x%08X)\n", UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION, uStatus);
        OpcUa_GotoError;
    }

#if UATESTCLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY
    {
        OpcUa_Int iValidationCode = 0;

        uStatus = UaTestClient_g_PkiProvider.ValidateCertificate(   &UaTestClient_g_PkiProvider,
                                                                    &UaTestClient_g_ClientCertificate,
                                                                    hCertificateStore,
                                                                    &iValidationCode);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Client certificate invalid!\n");
            return uStatus;
        }
    }
#endif /* UATESTCLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY */

#else /* UATESTCLIENT_SELFSIGNED */

    /*** load CA certificate and append to client certificate ***/
    uStatus = UaTestClient_g_PkiProvider.LoadCertificate(   &UaTestClient_g_PkiProvider,
                                                            UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION,
                                                            hCertificateStore,
                                                            &UaTestClient_g_ClientCertificate);

    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to load client certificate \"%s\"! (0x%08X)\n", UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION, uStatus);
        OpcUa_GotoError;
    }
    else
    {
        OpcUa_ByteString bsCertificate = OPCUA_BYTESTRING_STATICINITIALIZER;

#if UATESTCLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY
        {
            OpcUa_Int iValidationCode = 0;

            uStatus = UaTestClient_g_PkiProvider.ValidateCertificate(   &UaTestClient_g_PkiProvider,
                                                                        &UaTestClient_g_ClientCertificate,
                                                                        hCertificateStore,
                                                                        &iValidationCode);
            if(OpcUa_IsBad(uStatus))
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Client certificate invalid!\n");
                return uStatus;
            }
        }
#endif /* UATESTCLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY */

        uStatus = UaTestClient_g_PkiProvider.LoadCertificate(   &UaTestClient_g_PkiProvider,
                                                                UATESTCLIENT_CLIENT_CA_CERTIFICATE_LOCATION,
                                                                hCertificateStore,
                                                                &bsCertificate);

        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to load CA certificate \"%s\"! (0x%08X)\n", UATESTCLIENT_CLIENT_CA_CERTIFICATE_LOCATION, uStatus);
            OpcUa_GotoError;
        }

        uStatus = OpcUa_ByteString_Concatenate( &bsCertificate,
                                                &UaTestClient_g_ClientCertificate,
                                                0);

        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Could not append client certificate! (0x%08X)\n", uStatus);
            OpcUa_GotoError;
        }

        OpcUa_ByteString_Clear(&bsCertificate);
    }

#endif /* UATESTCLIENT_SELFSIGNED */

#endif /* UATESTCLIENT_CLIENT_CERTIFICATE_LOCATION */

#ifdef UATESTCLIENT_SERVER_CERTIFICATE_LOCATION
    /*** Get server certificate ***/
    uStatus = UaTestClient_g_PkiProvider.LoadCertificate(   &UaTestClient_g_PkiProvider,
                                                            UATESTCLIENT_SERVER_CERTIFICATE_LOCATION,
                                                            hCertificateStore,
                                                            &UaTestClient_g_ServerCertificate);
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to load server certificate \"%s\"! (0x%08X)\n", UATESTCLIENT_SERVER_CERTIFICATE_LOCATION, uStatus);
        OpcUa_GotoError;
    }

#if UATESTCLIENT_VERIFY_SERVER_CERTIFICATE_LOCALLY
    {
        OpcUa_Int iValidationCode = 0;

        uStatus = UaTestClient_g_PkiProvider.ValidateCertificate(   &UaTestClient_g_PkiProvider,
                                                                    &UaTestClient_g_ServerCertificate,
                                                                    hCertificateStore,
                                                                    &iValidationCode);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Server certificate invalid!\n");
            return uStatus;
        }
    }
#endif /* UATESTCLIENT_VERIFY_SERVER_CERTIFICATE_LOCALLY */
#endif

#ifdef UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION
    {
        /*** Get private key ***/
        uStatus = UaTestClient_g_PkiProvider.LoadPrivateKeyFromFile(UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION, 
                                                                    OpcUa_Crypto_Encoding_PEM, 
                                                                    OpcUa_Null, 
                                                                    &UaTestClient_g_ClientPrivateKey);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Failed to load client private key \"%s\"! (0x%08X)\n", UATESTCLIENT_CLIENT_PRIVATE_KEY_LOCATION, uStatus);
            OpcUa_GotoError;
        }
    }
#endif

    /* Close Certificate Store */
    UaTestClient_g_PkiProvider.CloseCertificateStore(   &UaTestClient_g_PkiProvider,
                                                        &hCertificateStore);

#endif /* UATESTCLIENT_USE_SECURE_COMMUNICATION */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
    
    OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestClient_InitializePKI: Could not initialize client PKI.\n");

    if(hCertificateStore != OpcUa_Null)
    {
        UaTestClient_g_PkiProvider.CloseCertificateStore(   &UaTestClient_g_PkiProvider,
                                                            &hCertificateStore);
    }

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Initializes the demo application.                                                 */
/*===========================================================================================*/
OpcUa_StatusCode UaTestClient_Initialize(OpcUa_Void)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

	UaTestClient_g_pProxyStubConfiguration.bProxyStub_Trace_Enabled              = OpcUa_True;
    UaTestClient_g_pProxyStubConfiguration.uProxyStub_Trace_Level                = UATESTCLIENT_TRACE_LEVEL;
    UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxAlloc                  = -1;
    UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxStringLength           = -1;
    UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxByteStringLength       = -1;
    UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxArrayLength            = -1;
    UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxMessageSize            = -1;
	UaTestClient_g_pProxyStubConfiguration.iSerializer_MaxRecursionDepth         = 100;
    UaTestClient_g_pProxyStubConfiguration.bSecureListener_ThreadPool_Enabled    = OpcUa_False;
    UaTestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MinThreads = -1;
    UaTestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxThreads = -1;
    UaTestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxJobs    = -1;
    UaTestClient_g_pProxyStubConfiguration.bSecureListener_ThreadPool_BlockOnAdd = OpcUa_True;
    UaTestClient_g_pProxyStubConfiguration.uSecureListener_ThreadPool_Timeout    = OPCUA_INFINITE;
    UaTestClient_g_pProxyStubConfiguration.iTcpListener_DefaultChunkSize         = -1;
    UaTestClient_g_pProxyStubConfiguration.iTcpConnection_DefaultChunkSize       = -1;
    UaTestClient_g_pProxyStubConfiguration.iTcpTransport_MaxMessageLength        = -1;
    UaTestClient_g_pProxyStubConfiguration.iTcpTransport_MaxChunkCount           = -1;
    UaTestClient_g_pProxyStubConfiguration.bTcpListener_ClientThreadsEnabled     = OpcUa_False;
    UaTestClient_g_pProxyStubConfiguration.bTcpStream_ExpectWriteToBlock         = OpcUa_True;

    uStatus = OpcUa_P_Initialize(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        &UaTestClient_g_pPortLayerHandle
#endif /* !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        );
    OpcUa_ReturnErrorIfBad(uStatus);

    uStatus = OpcUa_ProxyStub_Initialize(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        UaTestClient_g_pPortLayerHandle,
#endif /* #if !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        &UaTestClient_g_pProxyStubConfiguration);
    OpcUa_ReturnErrorIfBad(uStatus);

    uStatus = OpcUa_String_CreateNewString( UATESTCLIENT_SECURITY_POLICY,
                                            UATESTCLIENT_SECURITY_POLICY_LENGTH,
                                            0,
                                            OpcUa_True,
                                            OpcUa_True,
                                            &UaTestClient_g_pSecurityPolicy);
    OpcUa_ReturnErrorIfBad(uStatus);

    uStatus = UaTestClient_InitializePKI();

#if UATESTCLIENT_LARGE_REQUEST
    OpcUa_MemSet(UaTestClient_g_HugeCharArray, 'A', sizeof(UaTestClient_g_HugeCharArray));
    UaTestClient_g_HugeCharArray[UATESTCLIENT_LARGE_BODY - 1] = '\0';
#endif /* UATESTCLIENT_LARGE_REQUEST */

    return uStatus;
}

/*===========================================================================================*/
/** @brief Cleans up all security ressources from the demo application.                      */
/*===========================================================================================*/
OpcUa_Void UaTestClient_SecurityClear(OpcUa_Void)
{
    OpcUa_String_Delete(&UaTestClient_g_pSecurityPolicy);
    
    OpcUa_ByteString_Clear(&UaTestClient_g_ClientPrivateKey);
    OpcUa_ByteString_Clear(&UaTestClient_g_ClientCertificate);
    OpcUa_ByteString_Clear(&UaTestClient_g_ServerCertificate);

    /* delete PKI provider */
    OpcUa_PKIProvider_Delete(&UaTestClient_g_PkiProvider);
}

/*===========================================================================================*/
/** @brief Cleans up all ressources from the demo application.                               */
/*===========================================================================================*/
OpcUa_Void UaTestClient_Clean(OpcUa_Void)
{
    /* clear pki and security policies */
    UaTestClient_SecurityClear();

    OpcUa_ProxyStub_Clear();

    OpcUa_P_Clean(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        &UaTestClient_g_pPortLayerHandle
#endif /* !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        );
}

/*===========================================================================================*/
/** @brief Receives events from the channel.                                                 */
/*===========================================================================================*/
OpcUa_StatusCode UaTestClient_ChannelCallback(  OpcUa_Channel                   a_hChannel,
                                                OpcUa_Void*                     a_pvCallbackData,
                                                OpcUa_Channel_Event             a_eEvent,
                                                OpcUa_StatusCode                a_uStatus)
{
OpcUa_InitializeStatus(OpcUa_Module_Client, "ChannelCallback");

    OpcUa_ReferenceParameter(a_hChannel);
    OpcUa_ReferenceParameter(a_pvCallbackData);
    OpcUa_ReferenceParameter(a_uStatus);

    switch(a_eEvent)
    {
    case eOpcUa_Channel_Event_Connected:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestClient_ChannelCallback: Channel has been established.\n");
            break;
        }
    case eOpcUa_Channel_Event_Disconnected:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestClient_ChannelCallback: Channel has been lost.\n");
            break;
        }

#if OPCUA_HAVE_HTTPS
    case eOpcUa_Channel_Event_VerifyCertificate:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM,
                        "UaTestClient_ChannelCallback: UaTestClient_ChannelCallback: Certificate validation returned 0x%08X.\n",
                        a_uStatus);
            uStatus = OpcUa_BadContinue; 
            break;
        }
#endif

    default:
        {
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*********************************************************************************************/
/****************************     Main Service Call Chains     *******************************/
/*********************************************************************************************/
static OpcUa_StringA GetErrorText(OpcUa_StatusCode uStatusCode)
{
	OpcUa_StringA sError = OpcUa_Null;

	switch (uStatusCode)
	{
		case OpcUa_BadTimeout:
		{
			sError = "OpcUa_BadTimeout";
			break;
		}
		case OpcUa_BadCommunicationError:
		{
			sError = "OpcUa_BadCommunicationError";
			break;
		}
		case OpcUa_BadConnectionClosed:
		{
			sError = "OpcUa_BadConnectionClosed";
			break;
		}
		case OpcUa_BadCertificateInvalid:
		{
			sError = "OpcUa_BadCertificateInvalid";
			break;
		}
		case OpcUa_BadCertificateTimeInvalid:
		{
			sError = "OpcUa_BadCertificateTimeInvalid";
			break;
		}
		case OpcUa_BadCertificateRevoked:
		{
			sError = "OpcUa_BadCertificateRevoked";
			break;
		}
		case OpcUa_BadCertificateUntrusted:
		{
			sError = "OpcUa_BadCertificateUntrusted";
			break;
		}
		case OpcUa_BadCertificateIssuerRevocationUnknown:
		{
			sError = "OpcUa_BadCertificateIssuerRevocationUnknown";
			break;
		}
		case OpcUa_BadConnectionRejected:
		{
			sError = "OpcUa_BadConnectionRejected";
			break;
		}
		case OpcUa_BadFileNotFound:
		{
			sError = "OpcUa_BadFileNotFound";
			break;
		}
		case OpcUa_BadSecurityConfig:
		{
			sError = "OpcUa_BadSecurityConfig";
			break;
		}
		case OpcUa_BadInternalError:
		{
			sError = "OpcUa_BadInternalError";
			break;
		}
		case OpcUa_BadHostUnknown:
		{
			sError = "OpcUa_BadHostUnknown";
			break;
		}
		default:
		{
			sError = "unknown";
		}
	}

	return sError;
}

static OpcUa_StatusCode CheckResult(OpcUa_StringA a_sCallName, OpcUa_StatusCode a_uStatus, OpcUa_ResponseHeader* a_pResponseHeader)
{
	if (OpcUa_IsBad(a_uStatus))
	{
		if (a_uStatus == OpcUa_BadTimeout)
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "%s Timeout *-*\n", a_sCallName);
		}
		else
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Invoke %s failed: 0x%X\r\n", a_sCallName, a_uStatus);
		}
	}
	else
	{
		if (a_pResponseHeader != NULL)
		{
			if (OpcUa_IsBad(a_pResponseHeader->ServiceResult))
			{
				OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Invoke %s failed: 0x%X\r\n", a_sCallName, a_pResponseHeader->ServiceResult);
				a_uStatus = a_pResponseHeader->ServiceResult;
			}

			OpcUa_ResponseHeader_Clear(a_pResponseHeader);
		}
	}

	return a_uStatus;
}

OpcUa_StatusCode UaTestClient_DoNoSecurityTest(
	OpcUa_Channel a_hChannel,
	OpcUa_StringA a_sServerUrl)
{
	OpcUa_Int32 ii = 0;
    OpcUa_RequestHeader RequestHeader;
    OpcUa_ResponseHeader ResponseHeader;
	OpcUa_Int32 nNoOfServers = 0;
	OpcUa_ApplicationDescription* pServers = OpcUa_Null;
	OpcUa_Int32 nNoOfEndpoints = 0;
	OpcUa_EndpointDescription* pEndpoints = OpcUa_Null;
	OpcUa_String sEndpointUrl;
	OpcUa_String sSecurityPolicy;
	OpcUa_StringA sTransportProfile = OpcUa_TransportProfile_UaTcp;

OpcUa_InitializeStatus(OpcUa_Module_Client, "UaTestClient_DoSyncRequest");

    OpcUa_RequestHeader_Initialize(&RequestHeader);
    OpcUa_ResponseHeader_Initialize(&ResponseHeader);

	if (strncmp(a_sServerUrl, "opc.tls", 7) == 0)
	{
		sTransportProfile = OpcUa_TransportProfile_UaTls;
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[Connecting to EndpointUrl] %s\r\n", a_sServerUrl);

	uStatus = OpcUa_String_AttachReadOnly(&sEndpointUrl, a_sServerUrl);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_String_AttachReadOnly(&sSecurityPolicy, OpcUa_SecurityPolicy_None);
	OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Channel_Connect(
		a_hChannel,
		a_sServerUrl,
		UaTestClient_ChannelCallback,
        OpcUa_Null,
        &UaTestClient_g_ClientCertificate,
        &UaTestClient_g_ClientPrivateKey,
        OpcUa_Null,
		&UaTestClient_g_PkiConfig,
		&sSecurityPolicy,
		OPCUA_SECURITYTOKEN_LIFETIME_MAX,
		OpcUa_MessageSecurityMode_None,
		UATESTCLIENT_TIMEOUT); 

    if (OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "* Connect failed with 0x%08X (%s)!\n", uStatus, GetErrorText(uStatus));
        OpcUa_GotoErrorIfBad(uStatus);
    }

    RequestHeader.TimeoutHint = UATESTCLIENT_TIMEOUT;
    RequestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	uStatus = OpcUa_ClientApi_FindServers(
		a_hChannel,
		&RequestHeader,
		&sEndpointUrl,
		0,
		OpcUa_Null,
		0,
		OpcUa_Null,
		&ResponseHeader,
		&nNoOfServers,
		&pServers);

	uStatus = CheckResult("FindServers", uStatus, &ResponseHeader);
	OpcUa_GotoErrorIfBad(uStatus);

	for (ii = 0; ii < nNoOfServers; ii++)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[ApplicationDescription] %s|%s\r\n", OpcUa_String_GetRawString(&pServers[ii].ApplicationName.Text), OpcUa_String_GetRawString(&pServers[ii].ApplicationUri));
		OpcUa_ApplicationDescription_Clear(&pServers[ii]);
	}
	
	OpcUa_Free(pServers);
	pServers = OpcUa_Null;

	RequestHeader.TimeoutHint = UATESTCLIENT_TIMEOUT;
	RequestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	uStatus = OpcUa_ClientApi_GetEndpoints(
		a_hChannel,
		&RequestHeader,
		&sEndpointUrl,
		0,
		OpcUa_Null,
		0,
		OpcUa_Null,
		&ResponseHeader,
		&nNoOfEndpoints,
		&pEndpoints);

	uStatus = CheckResult("GetEndpoints", uStatus, &ResponseHeader);
	OpcUa_GotoErrorIfBad(uStatus);

	for (ii = 0; ii < nNoOfEndpoints; ii++)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[EndpointDescription] %s|%u\r\n", OpcUa_String_GetRawString(&pEndpoints[ii].EndpointUrl), pEndpoints[ii].SecurityMode);

		if (pEndpoints[ii].SecurityMode != OpcUa_MessageSecurityMode_None && strncmp(a_sServerUrl, OpcUa_String_GetRawString(&pEndpoints[ii].EndpointUrl), 7) == 0)
		{
			OpcUa_ByteString_Clear(&UaTestClient_g_ServerCertificate);

			UaTestClient_g_ServerCertificate.Data = (OpcUa_Byte*)OpcUa_Alloc(pEndpoints[ii].ServerCertificate.Length);
			OpcUa_GotoErrorIfAllocFailed(UaTestClient_g_ServerCertificate.Data);
			UaTestClient_g_ServerCertificate.Length = pEndpoints[ii].ServerCertificate.Length;
			OpcUa_MemCpy(UaTestClient_g_ServerCertificate.Data, UaTestClient_g_ServerCertificate.Length, pEndpoints[ii].ServerCertificate.Data, pEndpoints[ii].ServerCertificate.Length);
		}

		OpcUa_EndpointDescription_Clear(&pEndpoints[ii]);
	}

	OpcUa_Free(pEndpoints);
	pEndpoints = OpcUa_Null;

	OpcUa_String_Clear(&sEndpointUrl);
	OpcUa_String_Clear(&sSecurityPolicy);
    OpcUa_ResponseHeader_Clear(&ResponseHeader);
    OpcUa_Channel_Disconnect(a_hChannel);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pServers != OpcUa_Null)
	{
		for (ii = 0; ii < nNoOfServers; ii++)
		{
			OpcUa_ApplicationDescription_Clear(&pServers[ii]);
		}

		OpcUa_Free(pServers);
	}

	if (pEndpoints != OpcUa_Null)
	{
		for (ii = 0; ii < nNoOfEndpoints; ii++)
		{
			OpcUa_EndpointDescription_Clear(&pEndpoints[ii]);
		}
	}

	OpcUa_String_Clear(&sEndpointUrl);
	OpcUa_String_Clear(&sSecurityPolicy);
	OpcUa_ResponseHeader_Clear(&ResponseHeader);
    OpcUa_Channel_Disconnect(a_hChannel);

OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode UaTestClient_DoSecurityTest(
	OpcUa_Channel a_hChannel,
	OpcUa_StringA a_sServerUrl)
{
	OpcUa_Int32 ii = 0;
	OpcUa_RequestHeader RequestHeader;
	OpcUa_ResponseHeader ResponseHeader;
	OpcUa_Int32 nNoOfNodesToRead = 0;
	OpcUa_ReadValueId* pNodesToRead = OpcUa_Null;
	OpcUa_Int32 nNoOfValues = 0;
	OpcUa_DataValue* pValues = OpcUa_Null;
	OpcUa_Int32 nNoOfDiagnosticInfos = 0;
	OpcUa_DiagnosticInfo* pDiagnosticInfos = OpcUa_Null;
	OpcUa_StringA sTransportProfile = OpcUa_TransportProfile_UaTcp;

OpcUa_InitializeStatus(OpcUa_Module_Client, "UaTestClient_DoSecurityTest");

	OpcUa_RequestHeader_Initialize(&RequestHeader);
	OpcUa_ResponseHeader_Initialize(&ResponseHeader);

	if (strncmp(a_sServerUrl, "opc.tls", 7) == 0)
	{
		sTransportProfile = OpcUa_TransportProfile_UaTls;
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[Connecting to EndpointUrl] %s\r\n", a_sServerUrl);

	uStatus = OpcUa_Channel_Connect(
		a_hChannel,
		a_sServerUrl,
		UaTestClient_ChannelCallback,
		OpcUa_Null,
		&UaTestClient_g_ClientCertificate,
		&UaTestClient_g_ClientPrivateKey,
		&UaTestClient_g_ServerCertificate,
		&UaTestClient_g_PkiConfig,
		UaTestClient_g_pSecurityPolicy,
		OPCUA_SECURITYTOKEN_LIFETIME_MAX,
		UaTestClient_g_SecurityMode,
		UATESTCLIENT_TIMEOUT);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Connect failed with 0x%08X (%s)!\n", uStatus, GetErrorText(uStatus));
		OpcUa_GotoErrorIfBad(uStatus);
	}

	RequestHeader.TimeoutHint = UATESTCLIENT_TIMEOUT;
	RequestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	nNoOfNodesToRead = 2;
	pNodesToRead = (OpcUa_ReadValueId*)OpcUa_Alloc(sizeof(OpcUa_ReadValueId)*nNoOfNodesToRead);
	OpcUa_GotoErrorIfAllocFailed(pNodesToRead);

	for (ii = 0; ii < nNoOfNodesToRead; ii++)
	{
		OpcUa_ReadValueId_Clear(&pNodesToRead[ii]);

		pNodesToRead[ii].NodeId.IdentifierType = OpcUa_IdentifierType_Numeric;
		pNodesToRead[ii].NodeId.NamespaceIndex = 1;
		pNodesToRead[ii].NodeId.Identifier.Numeric = ii + 1;
		pNodesToRead[ii].AttributeId = OpcUa_Attributes_Value;
	}

	uStatus = OpcUa_ClientApi_Read(
		a_hChannel,
		&RequestHeader,
		0,
		OpcUa_TimestampsToReturn_Both,
		nNoOfNodesToRead,
		pNodesToRead,
		&ResponseHeader,
		&nNoOfValues,
		&pValues,
		&nNoOfDiagnosticInfos,
		&pDiagnosticInfos);

	uStatus = CheckResult("Read", uStatus, &ResponseHeader);

	if (uStatus == OpcUa_BadSessionIdInvalid)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not connect to a Server which requires a Session be created before calling Read!\r\n");
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_GotoErrorIfBad(uStatus);

	for (ii = 0; ii < nNoOfValues; ii++)
	{
		if (OpcUa_IsBad(pValues[ii].StatusCode))
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[DataValue] StatusCode=0x%08X\r\n", pValues[ii].StatusCode);
		}
		else if (pValues[ii].Value.Datatype == OpcUaType_Double)
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[DataValue] Value=%g\r\n", pValues[ii].Value.Value.Double);
		}
		else if (pValues[ii].Value.Datatype == OpcUaType_String)
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[DataValue] Value=%s\r\n", OpcUa_String_GetRawString(&pValues[ii].Value.Value.String));
		}
		else
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "[DataValue] Value=<unknown>\r\n");
		}

		OpcUa_DataValue_Clear(&pValues[ii]);
	}

	OpcUa_Free(pValues);
	pValues = OpcUa_Null;

	for (ii = 0; pDiagnosticInfos != OpcUa_Null && ii < nNoOfDiagnosticInfos; ii++)
	{
		OpcUa_DiagnosticInfo_Clear(&pDiagnosticInfos[ii]);
	}

	OpcUa_Free(pDiagnosticInfos);
	pDiagnosticInfos = OpcUa_Null;

	for (ii = 0; ii < nNoOfNodesToRead; ii++)
	{
		OpcUa_ReadValueId_Clear(&pNodesToRead[ii]);
	}

	OpcUa_Free(pNodesToRead);

	OpcUa_ResponseHeader_Clear(&ResponseHeader);
	OpcUa_Channel_Disconnect(a_hChannel);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pNodesToRead != OpcUa_Null)
	{
		for (ii = 0; ii < nNoOfNodesToRead; ii++)
		{
			OpcUa_ReadValueId_Clear(&pNodesToRead[ii]);
		}

		OpcUa_Free(pNodesToRead);
	}

	if (pValues != OpcUa_Null)
	{
		for (ii = 0; ii < nNoOfValues; ii++)
		{
			OpcUa_DataValue_Clear(&pValues[ii]);
		}

		OpcUa_Free(pValues);
	}

	if (pDiagnosticInfos != OpcUa_Null)
	{
		for (ii = 0; ii < nNoOfDiagnosticInfos; ii++)
		{
			OpcUa_DiagnosticInfo_Clear(&pDiagnosticInfos[ii]);
		}

		OpcUa_Free(pDiagnosticInfos);
	}

	OpcUa_ResponseHeader_Clear(&ResponseHeader);
	OpcUa_Channel_Disconnect(a_hChannel);

OpcUa_FinishErrorHandling;
}


OpcUa_StatusCode UaTestClient_DoTest(OpcUa_StringA a_sServerUrl)
{
	OpcUa_Channel hChannel = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Client, "UaTestClient_DoTest");

	uStatus = OpcUa_Channel_Create(&hChannel, OpcUa_Channel_SerializerType_Binary);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "main: Channel creation error 0x%08X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	uStatus = UaTestClient_DoNoSecurityTest(hChannel, a_sServerUrl);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "main: UaTestClient_DoNoSecurityTest error 0x%08X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	uStatus = UaTestClient_DoSecurityTest(hChannel, a_sServerUrl);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "main: UaTestClient_DoSecurityTest error 0x%08X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_Channel_Delete(&hChannel);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (hChannel != OpcUa_Null)
	{
		OpcUa_Channel_Delete(&hChannel);
	}

OpcUa_FinishErrorHandling;
}
/*********************************************************************************************/
/***********************        Application Main Entry Point          ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Main entry function.                                                              */
/*===========================================================================================*/
int main(int argc, char* argv[])
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_CharA sEndpointUrl[MAX_PATH];

#if UATESTCLIENT_USE_CRTDBG
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    /*_CrtSetBreakAlloc(905);*/
#endif
    Sleep(2000); /* Waiting to startup the server in Multi debug environment */
    OpcUa_ReferenceParameter(argc);
    OpcUa_ReferenceParameter(argv);

	if (argc > 1 && argv[1] != 0)
	{
		strcpy(sEndpointUrl, argv[1]);
	}
	else
	{
		strcpy(sEndpointUrl, UATESTCLIENT_SERVER_TLS_URL);
	}

    uStatus = UaTestClient_Initialize();
    OpcUa_GotoErrorIfBad(uStatus);

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "\n**** Test Started ****\n");
	UaTestClient_DoTest(sEndpointUrl);
	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "\n**** Test Ended ****\n");

    UaTestClient_Clean();

#if UATESTCLIENT_WAIT_FOR_USER_INPUT
    printf("Shutdown complete!\nPress enter to exit!\n");
    getchar();
#endif

    return 0;

Error:

    UaTestClient_Clean();

#if UATESTCLIENT_WAIT_FOR_USER_INPUT
    printf("Shutdown complete!\nPress enter to exit!\n");
    getchar();
#endif

    return uStatus;
}

/*********************************************************************************************/
/***********************                End Of File                   ************************/
/*********************************************************************************************/
