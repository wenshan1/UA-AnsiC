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
/*****************     A simple UA test server based on the Ansi C Stack     *****************/
/*********************************************************************************************/

/*********************************************************************************************/
/***********************                     Config                   ************************/
/*********************************************************************************************/
/* !0 == active, 0 == inactive */
/* use visual studio debug heap */
#define UATESTSERVER_USE_CRTDBG                             1
/* use visual studio debug heap */
#define UATESTSERVER_USE_VISUAL_LEAK_DETECTOR               0
/* support service calls over insecure communication channels */
#define UATESTSERVER_SUPPORT_NONSECURE_COMMUNICATION        1
/* activate support secure communication - no PKI locations required if 0 */
#define UATESTSERVER_SUPPORT_SECURE_COMMUNICATION           1
/* use the synchronous api */
#define UATESTSERVER_SYNC                                   1
/* wait for user input after shutting down */
#define UATESTSERVER_WAIT_FOR_USER_INPUT                    1
/* URL of the server */
#define UATESTSERVER_ENDPOINT_URL                           "opc.tcp://localhost:48040"
/* Transport profile supported by the server */
#define UATESTSERVER_DEFAULT_TRANSPORT_PROFILE_URI          OpcUa_TransportProfile_UaTcp
/* URL of the server on TLS channel */
#define UATESTSERVER_ENDPOINT_TLS_URL                       "opc.wss://localhost:48043"
/* Transport profile supported by the server */
#define UATESTSERVER_WSS_TRANSPORT_PROFILE_URI              OpcUa_TransportProfile_UaWebSockets
/* set to 1 to use the content of UaTestServer_g_HugeCharArray instead of the string World for responses. */
#define UATESTSERVER_LARGE_RESPONSE                         0
/* the used trace level */
#define UATESTSERVER_TRACE_LEVEL                            OPCUA_TRACE_OUTPUT_LEVEL_INFO
/* defines whether Win32 PKI is used or OpenSSL */
#define UATESTSERVER_USEWIN32PKI                            0
/* print uastack version information */
#define UATESTSERVER_PRINT_VERSION                          1
/* use selfsigned certificate as application certificate */
#define UATESTSERVER_SELFSIGNED                             1

#if UATESTSERVER_LARGE_RESPONSE
    /* define the size in bytes of the large response body (count of elements in UaTestServer_g_HugeCharArray). */
    #define UATESTSERVER_LARGE_BODY                         4194304
#endif /* UATESTSERVER_LARGE_RESPONSE */

/* number of integers in the response array (used in response for uint32 array requests) */
#define UATESTSERVER_UINT32_ARRAY_SIZE                      1000

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION

# define UATESTSERVER_CERTIFICATE_TRUST_LIST_LOCATION             "./PKI/certs/"
# define UATESTSERVER_CERTIFICATE_REVOCATION_LIST_LOCATION        "./PKI/crl/"
# define UATESTSERVER_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION      "./PKI/issuers/"
# define UATESTSERVER_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION "./PKI/crl/"
# define UATESTSERVER_SERVER_CERTIFICATE_LOCATION                 "./PKI/certs/prototype_server.der"
# define UATESTSERVER_SERVER_PRIVATE_KEY_LOCATION                 "./PKI/private/prototype_server.pem"

#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    /* verify the servers certificate after loading, before connecting */
    #define UATESTSERVER_VERIFY_SERVER_CERTIFICATE_LOCALLY  1
#endif

#if UATESTSERVER_USE_CRTDBG
    #ifndef _WIN32
        #undef UATESTSERVER_USE_CRTDBG
    #endif /* _WIN32  */
#endif /* UATESTSERVER_USE_CRTDBG */

/*********************************************************************************************/
/***********************                     Header                   ************************/
/*********************************************************************************************/
/* system */
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <sys/socket.h>
#endif /* _WIN32  */

#include <stdio.h>

#if UATESTSERVER_USE_CRTDBG
#include <crtdbg.h>
#endif /* UATESTSERVER_USE_CRTDBG */

/* vld */
#if UATESTSERVER_USE_VISUAL_LEAK_DETECTOR
# include <vld.h>
#endif /* UaTestServer_USE_VISUAL_LEAK_DETECTOR */

/* serverstub (basic includes for implementing a server based on the stack) */
#include <opcua_serverstub.h>

/* extensions from the stack (get additional functionality) */
#include <opcua_thread.h>
#include <opcua_string.h>
#include <opcua_memory.h>
#include <opcua_core.h>
#include <opcua_guid.h>
#include <opcua_trace.h>
#include <opcua_crypto.h>

/*********************************************************************************************/
/***********************                 Prototypes                   ************************/
/*********************************************************************************************/
OpcUa_StatusCode UaTestServer_FindServers(
	OpcUa_Endpoint                 a_hEndpoint,
	OpcUa_Handle                   a_hContext,
	const OpcUa_RequestHeader*     a_pRequestHeader,
	const OpcUa_String*            a_pEndpointUrl,
	OpcUa_Int32                    a_nNoOfLocaleIds,
	const OpcUa_String*            a_pLocaleIds,
	OpcUa_Int32                    a_nNoOfServerUris,
	const OpcUa_String*            a_pServerUris,
	OpcUa_ResponseHeader*          a_pResponseHeader,
	OpcUa_Int32*                   a_pNoOfServers,
	OpcUa_ApplicationDescription** a_pServers);

OpcUa_StatusCode UaTestServer_GetEndpoints(
	OpcUa_Endpoint              a_hEndpoint,
	OpcUa_Handle                a_hContext,
	const OpcUa_RequestHeader*  a_pRequestHeader,
	const OpcUa_String*         a_pEndpointUrl,
	OpcUa_Int32                 a_nNoOfLocaleIds,
	const OpcUa_String*         a_pLocaleIds,
	OpcUa_Int32                 a_nNoOfProfileUris,
	const OpcUa_String*         a_pProfileUris,
	OpcUa_ResponseHeader*       a_pResponseHeader,
	OpcUa_Int32*                a_pNoOfEndpoints,
	OpcUa_EndpointDescription** a_pEndpoints); 

OpcUa_StatusCode UaTestServer_Read(
	OpcUa_Endpoint             a_hEndpoint,
	OpcUa_Handle               a_hContext,
	const OpcUa_RequestHeader* a_pRequestHeader,
	OpcUa_Double               a_nMaxAge,
	OpcUa_TimestampsToReturn   a_eTimestampsToReturn,
	OpcUa_Int32                a_nNoOfNodesToRead,
	const OpcUa_ReadValueId*   a_pNodesToRead,
	OpcUa_ResponseHeader*      a_pResponseHeader,
	OpcUa_Int32*               a_pNoOfResults,
	OpcUa_DataValue**          a_pResults,
	OpcUa_Int32*               a_pNoOfDiagnosticInfos,
	OpcUa_DiagnosticInfo**     a_pDiagnosticInfos);

/*********************************************************************************************/
/***********************                    Types                     ************************/
/*********************************************************************************************/
typedef struct _UaTestServer_AsyncRequestContext
{
    OpcUa_Endpoint        hEndpoint;
    OpcUa_Handle          hContext;
    OpcUa_Void*           pRequest;
    OpcUa_EncodeableType  RequestType;
} UaTestServer_AsyncRequestContext;

/*********************************************************************************************/
/***********************                  Globals                     ************************/
/*********************************************************************************************/
OpcUa_Int32                                 UaTestServer_g_intDummy                      = 555;
OpcUa_Handle                                UaTestServer_g_PlatformLayerHandle           = OpcUa_Null;
OpcUa_Boolean                               UaTestServer_g_gbStopServer                  = OpcUa_False;
OpcUa_UInt32                                UaTestServer_g_uiShutdownBlocked             = 0;                  
#if OPCUA_USE_SYNCHRONISATION
OpcUa_Mutex                                 UaTestServer_g_hShutdownFlagMutex            = OpcUa_Null;
#endif /* OPCUA_USE_SYNCHRONISATION */

OpcUa_PKIProvider                           UaTestServer_g_PkiProvider                   = {OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null };
/* security configuration */
#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
OpcUa_Key                                   UaTestServer_g_ServerPrivateKey              = {OpcUa_Crypto_KeyType_Rsa_Private, {0, OpcUa_Null}, OpcUa_Null};
OpcUa_ByteString                            UaTestServer_g_ServerCertificate             = OPCUA_BYTESTRING_STATICINITIALIZER;
#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

OpcUa_UInt32                                UaTestServer_g_uNoOfSecurityPolicies         = 0;
OpcUa_P_OpenSSL_CertificateStore_Config     UaTestServer_g_PkiConfig                     = { OpcUa_NO_PKI, OpcUa_Null, OpcUa_Null, OpcUa_Null, 0, OpcUa_Null };
OpcUa_Endpoint_SecurityPolicyConfiguration* UaTestServer_g_pSecurityPolicyConfigurations = OpcUa_Null;
OpcUa_ProxyStubConfiguration                UaTestServer_g_pProxyStubConfiguration;

/*********************************************************************************************/
/***********************            Service Declarations              ************************/
/*********************************************************************************************/
/** @brief The testservice. */
OpcUa_ServiceType UaTestServer_FindServersService =
{
	OpcUaId_FindServersRequest,
	&OpcUa_FindServersResponse_EncodeableType,
	(OpcUa_PfnBeginInvokeService*)OpcUa_Server_BeginFindServers,
	(OpcUa_PfnInvokeService*)UaTestServer_FindServers
};

OpcUa_ServiceType UaTestServer_GetEndpointsService =
{
	OpcUaId_GetEndpointsRequest,
	&OpcUa_GetEndpointsResponse_EncodeableType,
	(OpcUa_PfnBeginInvokeService*)OpcUa_Server_BeginGetEndpoints,
	(OpcUa_PfnInvokeService*)UaTestServer_GetEndpoints
};

OpcUa_ServiceType UaTestServer_ReadService =
{
	OpcUaId_ReadRequest,
	&OpcUa_ReadResponse_EncodeableType,
	(OpcUa_PfnBeginInvokeService*)OpcUa_Server_BeginRead,
	(OpcUa_PfnInvokeService*)UaTestServer_Read
};

/** @brief All supported services. */
OpcUa_ServiceType*  UaTestServer_SupportedServices[] = 
{
	&UaTestServer_FindServersService,
    &UaTestServer_GetEndpointsService,
	&UaTestServer_ReadService,
    OpcUa_Null
};

/*********************************************************************************************/
/***********************               Internal Helpers               ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Wait for x to be pressed.                                                         */
/*===========================================================================================*/
OpcUa_Boolean UaTestServer_CheckForKeypress()
{
    if(!_kbhit()){}else{if (_getch()=='x'){return 1;}}return 0;
}

/*===========================================================================================*/
/** @brief Part of initialization process. Fill the security policies.                       */
/*===========================================================================================*/
static OpcUa_StatusCode UaTestServer_CreateSecurityPolicies(OpcUa_Void)
{
    OpcUa_UInt32 uIndex = 0;

#if UATESTSERVER_SUPPORT_NONSECURE_COMMUNICATION
    ++UaTestServer_g_uNoOfSecurityPolicies;
#endif

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    UaTestServer_g_uNoOfSecurityPolicies += 2;
#endif

    /* allocate and initialize policy configurations */
    UaTestServer_g_pSecurityPolicyConfigurations = (OpcUa_Endpoint_SecurityPolicyConfiguration*)OpcUa_Alloc(sizeof(OpcUa_Endpoint_SecurityPolicyConfiguration) * UaTestServer_g_uNoOfSecurityPolicies);
    OpcUa_ReturnErrorIfAllocFailed(UaTestServer_g_pSecurityPolicyConfigurations);
    for(uIndex = 0; uIndex < UaTestServer_g_uNoOfSecurityPolicies; uIndex++)
    {
        OpcUa_String_Initialize(&((UaTestServer_g_pSecurityPolicyConfigurations[uIndex]).sSecurityPolicy));
        UaTestServer_g_pSecurityPolicyConfigurations[uIndex].pbsClientCertificate = OpcUa_Null;
    }

    uIndex = 0;

#if UATESTSERVER_SUPPORT_NONSECURE_COMMUNICATION
    OpcUa_String_AttachCopy(  &(UaTestServer_g_pSecurityPolicyConfigurations[uIndex].sSecurityPolicy),
                              OpcUa_SecurityPolicy_None); 
    UaTestServer_g_pSecurityPolicyConfigurations[uIndex].uMessageSecurityModes = OPCUA_ENDPOINT_MESSAGESECURITYMODE_NONE;
    ++uIndex;
#endif

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    OpcUa_String_AttachCopy(  &(UaTestServer_g_pSecurityPolicyConfigurations[uIndex].sSecurityPolicy),
                              OpcUa_SecurityPolicy_Basic128Rsa15);
    UaTestServer_g_pSecurityPolicyConfigurations[uIndex].uMessageSecurityModes = OPCUA_ENDPOINT_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    ++uIndex;

    OpcUa_String_AttachCopy(  &(UaTestServer_g_pSecurityPolicyConfigurations[uIndex].sSecurityPolicy),
                              OpcUa_SecurityPolicy_Basic256);
    UaTestServer_g_pSecurityPolicyConfigurations[uIndex].uMessageSecurityModes = OPCUA_ENDPOINT_MESSAGESECURITYMODE_SIGNANDENCRYPT;
#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

    return OpcUa_Good;
}

/*===========================================================================================*/
/** @brief Sets a servers certificate and private key.                                       */
/*===========================================================================================*/
static OpcUa_StatusCode UaTestServer_InitializePKI()
{
#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    OpcUa_Handle hCertificateStore = OpcUa_Null;
#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

OpcUa_InitializeStatus(OpcUa_Module_Server, "InitializePKI");

    OpcUa_MemSet(&UaTestServer_g_PkiProvider, 0, sizeof(OpcUa_PKIProvider));
    OpcUa_MemSet(&UaTestServer_g_PkiConfig,   0, sizeof(OpcUa_P_OpenSSL_CertificateStore_Config));

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION

    /****************************** create PKI Config ******************************/
#if UATESTSERVER_USEWIN32PKI    
    UaTestServer_g_PkiConfig.strPkiType                                 = OPCUA_P_PKI_TYPE_WIN32;
    UaTestServer_g_PkiConfig.uFlags                                     = OPCUA_P_PKI_WIN32_STORE_MACHINE;
#else /* UATESTSERVER_ */
    UaTestServer_g_PkiConfig.PkiType                                    = OpcUa_OpenSSL_PKI;
#endif /* UATESTSERVER_ */

    UaTestServer_g_PkiConfig.CertificateTrustListLocation               = UATESTSERVER_CERTIFICATE_TRUST_LIST_LOCATION;
    UaTestServer_g_PkiConfig.CertificateRevocationListLocation          = UATESTSERVER_CERTIFICATE_REVOCATION_LIST_LOCATION;
    UaTestServer_g_PkiConfig.CertificateUntrustedListLocation           = UATESTSERVER_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION;

    /* create application pki provider */
    uStatus = OpcUa_PKIProvider_Create(&UaTestServer_g_PkiConfig, &UaTestServer_g_PkiProvider);
    OpcUa_GotoErrorIfBad(uStatus);

    /* open certificate store */
    uStatus = UaTestServer_g_PkiProvider.OpenCertificateStore(  &UaTestServer_g_PkiProvider,
                                                                &hCertificateStore);
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestServer_InitializePKI: Failed to open certificate store! (0x%08X)\n", uStatus);
        OpcUa_GotoError;
    }

    /*** load server certificate ***/
    uStatus = UaTestServer_g_PkiProvider.LoadCertificate(   &UaTestServer_g_PkiProvider,
                                                            UATESTSERVER_SERVER_CERTIFICATE_LOCATION,
                                                            hCertificateStore,
                                                            &UaTestServer_g_ServerCertificate);

    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestServer_InitializePKI: Failed to load server certificate \"%s\"! (0x%08X)\n", UATESTSERVER_SERVER_CERTIFICATE_LOCATION, uStatus);
        OpcUa_GotoError;
    }

    /*** get server private key ***/
    uStatus = UaTestServer_g_PkiProvider.LoadPrivateKeyFromFile(UATESTSERVER_SERVER_PRIVATE_KEY_LOCATION,
                                                                OpcUa_Crypto_Encoding_PEM, 
                                                                OpcUa_Null, 
                                                                &UaTestServer_g_ServerPrivateKey.Key);

    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestServer_InitializePKI: Failed to load server private key \"%s\"! (0x%08X)\n", UATESTSERVER_SERVER_PRIVATE_KEY_LOCATION, uStatus);
        OpcUa_GotoError;
    }

    /* close certificate store */
    UaTestServer_g_PkiProvider.CloseCertificateStore(   &UaTestServer_g_PkiProvider,
                                                        &hCertificateStore);

#else /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

    /****************************** create PKI Config ******************************/
    UaTestServer_g_PkiConfig.strPkiType                             = OPCUA_PKI_TYPE_NONE;
    UaTestServer_g_PkiConfig.strTrustedCertificateListLocation      = OpcUa_Null;
    UaTestServer_g_PkiConfig.strRevokedCertificateListLocation      = OpcUa_Null;
    UaTestServer_g_PkiConfig.strIssuerCertificateStoreLocation      = OpcUa_Null;
    UaTestServer_g_PkiConfig.strRevokedIssuerCertificateListLocation= OpcUa_Null;

#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
    
    OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestServer_InitializePKI: Could not initialize server PKI.\n");

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    if(hCertificateStore != OpcUa_Null)
    {
        UaTestServer_g_PkiProvider.CloseCertificateStore(   &UaTestServer_g_PkiProvider,
                                                            &hCertificateStore);
    }
#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Initializes the demo application.                                                 */
/*===========================================================================================*/
OpcUa_StatusCode UaTestServer_Initialize(OpcUa_Void)
{
#if UATESTSERVER_PRINT_VERSION
    OpcUa_StringA strVersion = OpcUa_Null;
#endif /* UATESTSERVER_PRINT_VERSION */

OpcUa_InitializeStatus(OpcUa_Module_Server, "Initialize");

	UaTestServer_g_pProxyStubConfiguration.bProxyStub_Trace_Enabled				 = OpcUa_True;
    UaTestServer_g_pProxyStubConfiguration.uProxyStub_Trace_Level                = UATESTSERVER_TRACE_LEVEL;
    UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxAlloc                  = -1;
    UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxStringLength           = -1;
    UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxByteStringLength       = -1;
    UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxArrayLength            = -1;
    UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxMessageSize            = -1;
	UaTestServer_g_pProxyStubConfiguration.iSerializer_MaxRecursionDepth         =  100;
    UaTestServer_g_pProxyStubConfiguration.bSecureListener_ThreadPool_Enabled    = OpcUa_False;
    UaTestServer_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MinThreads = -1;
    UaTestServer_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxThreads = -1;
    UaTestServer_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxJobs    = -1;
    UaTestServer_g_pProxyStubConfiguration.bSecureListener_ThreadPool_BlockOnAdd = OpcUa_True;
    UaTestServer_g_pProxyStubConfiguration.uSecureListener_ThreadPool_Timeout    = OPCUA_INFINITE;
    UaTestServer_g_pProxyStubConfiguration.iTcpListener_DefaultChunkSize         = -1;
    UaTestServer_g_pProxyStubConfiguration.iTcpConnection_DefaultChunkSize       = -1;
    UaTestServer_g_pProxyStubConfiguration.iTcpTransport_MaxMessageLength        = -1;
    UaTestServer_g_pProxyStubConfiguration.iTcpTransport_MaxChunkCount           = -1;
    UaTestServer_g_pProxyStubConfiguration.bTcpListener_ClientThreadsEnabled     = OpcUa_False;
    UaTestServer_g_pProxyStubConfiguration.bTcpStream_ExpectWriteToBlock         = OpcUa_True;

    /* initialize platform layer */
    uStatus = OpcUa_P_Initialize(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        &UaTestServer_g_PlatformLayerHandle
#endif /* !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        );
    OpcUa_GotoErrorIfBad(uStatus);

    /* initialize stack */
    uStatus = OpcUa_ProxyStub_Initialize(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        UaTestServer_g_PlatformLayerHandle,
#endif /* #if !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        &UaTestServer_g_pProxyStubConfiguration);
    OpcUa_GotoErrorIfBad(uStatus);

#if UATESTSERVER_PRINT_VERSION

    /* get version string information */
    strVersion = OpcUa_ProxyStub_GetVersion();
    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OpcUa_ProxyStub_GetVersion: %s\n", strVersion);

    strVersion = OpcUa_ProxyStub_GetStaticConfigString();
    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OpcUa_ProxyStub_GetStaticConfigString: %s\n", strVersion);

    strVersion = OpcUa_ProxyStub_GetConfigString();
    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OpcUa_ProxyStub_GetConfigString: %s\n\n", strVersion);

#endif /* UATESTSERVER_PRINT_VERSION */

    /* initialize security configuration */
    uStatus = UaTestServer_InitializePKI();
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = UaTestServer_CreateSecurityPolicies();
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Cleans up all security ressources from the demo application.                      */
/*===========================================================================================*/
static OpcUa_Void UaTestServer_SecurityClear(OpcUa_Void)
{
    OpcUa_UInt32 uIndex = 0;

    /* clean up security policies */
    if(UaTestServer_g_pSecurityPolicyConfigurations != OpcUa_Null)
    {
        for(uIndex = 0; uIndex < UaTestServer_g_uNoOfSecurityPolicies; uIndex++)
        {
            OpcUa_String_Clear(&(UaTestServer_g_pSecurityPolicyConfigurations[uIndex].sSecurityPolicy));
            UaTestServer_g_pSecurityPolicyConfigurations[uIndex].pbsClientCertificate = OpcUa_Null;
        }

        OpcUa_Free(UaTestServer_g_pSecurityPolicyConfigurations);
    }

#if UATESTSERVER_SUPPORT_SECURE_COMMUNICATION
    OpcUa_ByteString_Clear(&UaTestServer_g_ServerPrivateKey.Key);
    OpcUa_ByteString_Clear(&UaTestServer_g_ServerCertificate);

    /* delete PKI provider */
    OpcUa_PKIProvider_Delete(&UaTestServer_g_PkiProvider);
#endif /* UATESTSERVER_SUPPORT_SECURE_COMMUNICATION */
}

/*===========================================================================================*/
/** @brief Cleans up all ressources from the demo application.                               */
/*===========================================================================================*/
OpcUa_Void UaTestServer_Clear(OpcUa_Void)
{
    UaTestServer_SecurityClear();

    OpcUa_ProxyStub_Clear();
    OpcUa_P_Clean(
#if !OPCUA_USE_STATIC_PLATFORM_INTERFACE
        &UaTestServer_g_PlatformLayerHandle
#endif /* !OPCUA_USE_STATIC_PLATFORM_INTERFACE */
        );
}

/*===========================================================================================*/
/** @brief Set shutdown flag and wait for all threads to leave the block.                    */
/*===========================================================================================*/
OpcUa_Void UaTestServer_SetAndWaitShutdown(OpcUa_Void)
{
#if OPCUA_USE_SYNCHRONISATION
    OpcUa_Mutex_Lock(UaTestServer_g_hShutdownFlagMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    UaTestServer_g_gbStopServer = OpcUa_True;
    while(UaTestServer_g_uiShutdownBlocked > 0)
    {

#if OPCUA_USE_SYNCHRONISATION
        OpcUa_Mutex_Unlock(UaTestServer_g_hShutdownFlagMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

#if OPCUA_MULTITHREADED
        OpcUa_Thread_Sleep(5);
#endif /* OPCUA_MULTITHREADED */

#if OPCUA_USE_SYNCHRONISATION
        OpcUa_Mutex_Lock(UaTestServer_g_hShutdownFlagMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    }

#if OPCUA_USE_SYNCHRONISATION
    OpcUa_Mutex_Unlock(UaTestServer_g_hShutdownFlagMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */
}
   
/*********************************************************************************************/
/***********************     Stack Callbacks and Service Handlers     ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Finish request by sending a service fault.                                        */
/*===========================================================================================*/
OpcUa_StatusCode UaTestServer_SendFault(    OpcUa_RequestHeader*    a_pRequestHeader,
                                            OpcUa_ResponseHeader*   a_pResponseHeader,
                                            OpcUa_Endpoint          a_hEndpoint,
                                            OpcUa_Handle*           a_phContext,
                                            OpcUa_StatusCode        a_uStatus)
{
    OpcUa_Void*             pFault              = OpcUa_Null;
    OpcUa_EncodeableType*   pFaultType          = OpcUa_Null;
    OpcUa_DiagnosticInfo*   pServiceDiagnostics = OpcUa_Null;
    OpcUa_Int32             nNoOfStringTable    = 0;
    OpcUa_Int32*            pNoOfStringTable    = &nNoOfStringTable;
    OpcUa_String**          pStringTable        = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "SendFault");

    /* check if response already started */
    if(a_pResponseHeader != OpcUa_Null)
    {
        pServiceDiagnostics = &a_pResponseHeader->ServiceDiagnostics;
        pNoOfStringTable    = &a_pResponseHeader->NoOfStringTable;
        pStringTable        = &a_pResponseHeader->StringTable;
    }
    else
    {
        OpcUa_Void*             pResponse           = OpcUa_Null;
        OpcUa_EncodeableType*   pResponseType       = OpcUa_Null;

        /* create new response */
        uStatus = OpcUa_Endpoint_BeginSendResponse(  a_hEndpoint,
                                                    *a_phContext,
                                                    &pResponse,
                                                    &pResponseType);
        OpcUa_ReturnErrorIfBad(uStatus);

        OpcUa_EncodeableObject_Delete(pResponseType, (OpcUa_Void**)&pResponse);
    }

    /* create a fault */
    uStatus = OpcUa_ServerApi_CreateFault(  a_pRequestHeader,
                                            a_uStatus,
                                            pServiceDiagnostics,
                                            pNoOfStringTable,
                                            pStringTable,
                                            &pFault,
                                            &pFaultType);

    if(OpcUa_IsGood(uStatus))
    {
        /* service fault created */
        OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "UaTestServer_SendFault: Sending service fault!\n");

        /* send service fault response */
        uStatus = OpcUa_Endpoint_EndSendResponse(   a_hEndpoint,
                                                    a_phContext,
                                                    OpcUa_Good,
                                                    pFault,
                                                    pFaultType);

        OpcUa_EncodeableObject_Delete(pFaultType, (OpcUa_Void**)&pFault);

        OpcUa_GotoErrorIfBad(uStatus);
    }
    else
    {
        /* creation of fault failed */
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "UaTestServer_SendFault: Can not send service fault!\n");

        /* finish response */
        uStatus = OpcUa_Endpoint_CancelSendResponse(    a_hEndpoint,
                                                        uStatus,
                                                        OpcUa_String_FromCString("UaTestServer_SendFault: Could not send service fault!"),
                                                        a_phContext);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Get notifications about secure channel events.                                    */
/*===========================================================================================*/
OpcUa_StatusCode UaTestServer_EndpointCallback(
    OpcUa_Endpoint          a_hEndpoint,
    OpcUa_Void*             a_pCallbackData,
    OpcUa_Endpoint_Event    a_eEvent,
    OpcUa_StatusCode        a_uStatus,
    OpcUa_UInt32            a_uSecureChannelId,
    OpcUa_ByteString*       a_pbsClientCertificate,
    OpcUa_String*           a_pSecurityPolicy,
    OpcUa_UInt16            a_uSecurityMode)
{
OpcUa_InitializeStatus(OpcUa_Module_Server, "EndpointCallback");

    OpcUa_ReferenceParameter(a_hEndpoint);
    OpcUa_ReferenceParameter(a_pCallbackData);
    OpcUa_ReferenceParameter(a_uSecureChannelId);
    OpcUa_ReferenceParameter(a_pSecurityPolicy);
    OpcUa_ReferenceParameter(a_pbsClientCertificate);
    OpcUa_ReferenceParameter(a_uSecurityMode);
    OpcUa_ReferenceParameter(a_uStatus);

    switch(a_eEvent)
    {
    case eOpcUa_Endpoint_Event_SecureChannelOpened:
        {
			OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM,
				"UaTestServer_EndpointCallback: SecureChannel %i opened with %s in mode %u status 0x%08X!\n",
				a_uSecureChannelId,
				(a_pSecurityPolicy) ? OpcUa_String_GetRawString(a_pSecurityPolicy) : "(not provided)",
				a_uSecurityMode,
				a_uStatus);

            break;
        }
    case eOpcUa_Endpoint_Event_SecureChannelClosed:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestServer_EndpointCallback: SecureChannel %i closed with status 0x%08X!\n", a_uSecureChannelId, a_uStatus);
            break;
        }
    case eOpcUa_Endpoint_Event_SecureChannelRenewed:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestServer_EndpointCallback: SecureChannel %i renewed!\n", a_uSecureChannelId);
            break;
        }
    case eOpcUa_Endpoint_Event_UnsupportedServiceRequested:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestServer_EndpointCallback: SecureChannel %i received request for unsupported service!\n", a_uSecureChannelId);
            break;
        }
    case eOpcUa_Endpoint_Event_DecoderError:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestServer_EndpointCallback: SecureChannel %i received a request that could not be decoded! (0x%08X)\n", a_uSecureChannelId, a_uStatus);
            break;
        }
    case eOpcUa_Endpoint_Event_Invalid:
    default:
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "UaTestServer_EndpointCallback: Unknown Endpoint event!\n");
            break;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

static OpcUa_StatusCode UaTestServer_GetApplicationDescription(OpcUa_ApplicationDescription* pDescription)
{
OpcUa_InitializeStatus(OpcUa_Module_Server, "UaTestServer_GetApplicationDescription");

	OpcUa_ReturnErrorIfArgumentNull(pDescription);

	OpcUa_ApplicationDescription_Initialize(pDescription);

	pDescription->ApplicationType = OpcUa_ApplicationType_Server;

	uStatus = OpcUa_String_AttachCopy(&pDescription->ApplicationName.Text, "Test Server");
	OpcUa_GotoErrorIfBad(uStatus);
	
	uStatus = OpcUa_String_AttachCopy(&pDescription->ApplicationName.Locale, "en");
	OpcUa_GotoErrorIfBad(uStatus);
	
	uStatus = OpcUa_String_AttachCopy(&pDescription->ApplicationUri, "urn:localhost:opcfoundation.org:TestServer");
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_String_AttachCopy(&pDescription->ProductUri, "urn:opcfoundation.org:TestServer");
	OpcUa_GotoErrorIfBad(uStatus);

	pDescription->NoOfDiscoveryUrls = 2;
	pDescription->DiscoveryUrls = OpcUa_Alloc(sizeof(OpcUa_String)*pDescription->NoOfDiscoveryUrls);
	OpcUa_GotoErrorIfAllocFailed(pDescription->DiscoveryUrls);

	OpcUa_String_Initialize(&pDescription->DiscoveryUrls[0]);
	uStatus = OpcUa_String_AttachCopy(&pDescription->DiscoveryUrls[0], UATESTSERVER_ENDPOINT_URL);
	OpcUa_GotoErrorIfBad(uStatus);

	OpcUa_String_Initialize(&pDescription->DiscoveryUrls[1]);
	uStatus = OpcUa_String_AttachCopy(&pDescription->DiscoveryUrls[1], UATESTSERVER_ENDPOINT_TLS_URL);
	OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ApplicationDescription_Clear(pDescription);

OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode UaTestServer_FindServers(
	OpcUa_Endpoint                 a_hEndpoint,
	OpcUa_Handle                   a_hContext,
	const OpcUa_RequestHeader*     a_pRequestHeader,
	const OpcUa_String*            a_pEndpointUrl,
	OpcUa_Int32                    a_nNoOfLocaleIds,
	const OpcUa_String*            a_pLocaleIds,
	OpcUa_Int32                    a_nNoOfServerUris,
	const OpcUa_String*            a_pServerUris,
	OpcUa_ResponseHeader*          a_pResponseHeader,
	OpcUa_Int32*                   a_pNoOfServers,
	OpcUa_ApplicationDescription** a_pServers)
{
	OpcUa_ApplicationDescription* pServers = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "UaTestServer_FindServers");

	OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "**** FindServers called! ****\n");

	/* validate arguments. */
	OpcUa_ReturnErrorIfArgumentNull(a_hEndpoint);
	OpcUa_ReturnErrorIfArgumentNull(a_hContext);
	OpcUa_ReturnErrorIfArgumentNull(a_pRequestHeader);
	OpcUa_ReturnErrorIfArgumentNull(a_pEndpointUrl);
	OpcUa_ReturnErrorIfArrayArgumentNull(a_nNoOfLocaleIds, a_pLocaleIds);
	OpcUa_ReturnErrorIfArrayArgumentNull(a_nNoOfServerUris, a_pServerUris);
	OpcUa_ReturnErrorIfArgumentNull(a_pResponseHeader);
	OpcUa_ReturnErrorIfArgumentNull(a_pNoOfServers);
	OpcUa_ReturnErrorIfArgumentNull(a_pServers);

	pServers = OpcUa_Alloc(sizeof(OpcUa_ApplicationDescription));
	OpcUa_GotoErrorIfAllocFailed(pServers);

	uStatus = UaTestServer_GetApplicationDescription(pServers);
	OpcUa_GotoErrorIfBad(uStatus);

	*a_pNoOfServers = 1;
	*a_pServers = pServers;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pServers != OpcUa_Null)
	{
		OpcUa_ApplicationDescription_Clear(pServers);
		OpcUa_Free(pServers);
	}

OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode UaTestServer_GetEndpoints(
	OpcUa_Endpoint              a_hEndpoint,
	OpcUa_Handle                a_hContext,
	const OpcUa_RequestHeader*  a_pRequestHeader,
	const OpcUa_String*         a_pEndpointUrl,
	OpcUa_Int32                 a_nNoOfLocaleIds,
	const OpcUa_String*         a_pLocaleIds,
	OpcUa_Int32                 a_nNoOfProfileUris,
	const OpcUa_String*         a_pProfileUris,
	OpcUa_ResponseHeader*       a_pResponseHeader,
	OpcUa_Int32*                a_pNoOfEndpoints,
	OpcUa_EndpointDescription** a_pEndpoints)
{
	OpcUa_UInt32 ii = 0;
	OpcUa_UInt32 uEndpointCount = 4;
	OpcUa_EndpointDescription* pEndpoints = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "UaTestServer_GetEndpoints");

	OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "**** GetEndpoints called! ****\n");

	/* validate arguments. */
	OpcUa_ReturnErrorIfArgumentNull(a_hEndpoint);
	OpcUa_ReturnErrorIfArgumentNull(a_hContext);
	OpcUa_ReturnErrorIfArgumentNull(a_pRequestHeader);
	OpcUa_ReturnErrorIfArgumentNull(a_pEndpointUrl);
	OpcUa_ReturnErrorIfArrayArgumentNull(a_nNoOfLocaleIds, a_pLocaleIds);
	OpcUa_ReturnErrorIfArrayArgumentNull(a_nNoOfProfileUris, a_pProfileUris);
	OpcUa_ReturnErrorIfArgumentNull(a_pResponseHeader);
	OpcUa_ReturnErrorIfArgumentNull(a_pNoOfEndpoints);
	OpcUa_ReturnErrorIfArgumentNull(a_pEndpoints);

	pEndpoints = OpcUa_Alloc(sizeof(OpcUa_EndpointDescription)*uEndpointCount);
	OpcUa_GotoErrorIfAllocFailed(pEndpoints);
	OpcUa_MemSet(pEndpoints, 0, sizeof(OpcUa_EndpointDescription)*uEndpointCount);

	for (ii = 0; ii < uEndpointCount; ii++)
	{
		if (ii % 2 == 2)
		{
			pEndpoints[ii].SecurityMode = OpcUa_MessageSecurityMode_None;
			pEndpoints[ii].SecurityLevel = 0;

			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].SecurityPolicyUri, OpcUa_SecurityPolicy_None);
			OpcUa_GotoErrorIfBad(uStatus);
		}
		else
		{
			pEndpoints[ii].SecurityMode = OpcUa_MessageSecurityMode_SignAndEncrypt;
			pEndpoints[ii].SecurityLevel = 10;

			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].SecurityPolicyUri, OpcUa_SecurityPolicy_Basic256);
			OpcUa_GotoErrorIfBad(uStatus);
		}
		
		if ((ii / 2) % 2 == 0)
		{
			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].EndpointUrl, UATESTSERVER_ENDPOINT_URL);
			OpcUa_GotoErrorIfBad(uStatus);

			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].TransportProfileUri, UATESTSERVER_DEFAULT_TRANSPORT_PROFILE_URI);
			OpcUa_GotoErrorIfBad(uStatus);
		}
		else
		{
			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].EndpointUrl, UATESTSERVER_ENDPOINT_TLS_URL);
			OpcUa_GotoErrorIfBad(uStatus);

			uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].TransportProfileUri, UATESTSERVER_WSS_TRANSPORT_PROFILE_URI);
			OpcUa_GotoErrorIfBad(uStatus);
		}

		uStatus = UaTestServer_GetApplicationDescription(&pEndpoints[ii].Server);
		OpcUa_GotoErrorIfBad(uStatus);

		pEndpoints[ii].ServerCertificate.Data = (OpcUa_Byte*)OpcUa_Alloc(UaTestServer_g_ServerCertificate.Length);
		OpcUa_GotoErrorIfAllocFailed(pEndpoints[ii].ServerCertificate.Data);
		pEndpoints[ii].ServerCertificate.Length = UaTestServer_g_ServerCertificate.Length;
		OpcUa_MemCpy(pEndpoints[ii].ServerCertificate.Data, pEndpoints[ii].ServerCertificate.Length, UaTestServer_g_ServerCertificate.Data, UaTestServer_g_ServerCertificate.Length);

		pEndpoints[ii].NoOfUserIdentityTokens = 1;
		pEndpoints[ii].UserIdentityTokens = OpcUa_Alloc(sizeof(OpcUa_UserTokenPolicy));
		OpcUa_GotoErrorIfAllocFailed(pEndpoints[ii].UserIdentityTokens);
		OpcUa_UserTokenPolicy_Initialize(pEndpoints[ii].UserIdentityTokens);

		pEndpoints[ii].UserIdentityTokens[0].TokenType = OpcUa_UserTokenType_Anonymous;
		uStatus = OpcUa_String_AttachCopy(&pEndpoints[ii].UserIdentityTokens[0].PolicyId, "1");
		OpcUa_GotoErrorIfBad(uStatus);
	}

	*a_pNoOfEndpoints = uEndpointCount;
	*a_pEndpoints = pEndpoints;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pEndpoints != OpcUa_Null)
	{
		for (ii = 0; ii < uEndpointCount; ii++)
		{
			OpcUa_EndpointDescription_Clear(&pEndpoints[ii]);
		}

		OpcUa_Free(pEndpoints);
	}

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Synchronous service handler.                                                      */
/*===========================================================================================*/

OpcUa_StatusCode UaTestServer_Read(
	OpcUa_Endpoint             a_hEndpoint,
	OpcUa_Handle               a_hContext,
	const OpcUa_RequestHeader* a_pRequestHeader,
	OpcUa_Double               a_nMaxAge,
	OpcUa_TimestampsToReturn   a_eTimestampsToReturn,
	OpcUa_Int32                a_nNoOfNodesToRead,
	const OpcUa_ReadValueId*   a_pNodesToRead,
	OpcUa_ResponseHeader*      a_pResponseHeader,
	OpcUa_Int32*               a_pNoOfResults,
	OpcUa_DataValue**          a_pResults,
	OpcUa_Int32*               a_pNoOfDiagnosticInfos,
	OpcUa_DiagnosticInfo**     a_pDiagnosticInfos)
{
	OpcUa_Int32 ii = 0;

OpcUa_InitializeStatus(OpcUa_Module_Server, "Read");

    OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "**** Read called! ****\n");

    /* validate arguments. */
    OpcUa_ReturnErrorIfArgumentNull(a_hEndpoint);
    OpcUa_ReturnErrorIfArgumentNull(a_hContext);
    OpcUa_ReturnErrorIfArgumentNull(a_pRequestHeader);
    OpcUa_ReturnErrorIfArgumentNull(a_pNodesToRead);
    OpcUa_ReturnErrorIfArgumentNull(a_pResponseHeader);
	OpcUa_ReturnErrorIfArgumentNull(a_pNoOfResults);
	OpcUa_ReturnErrorIfArgumentNull(a_pResults);
	OpcUa_ReturnErrorIfArgumentNull(a_pNoOfDiagnosticInfos);
	OpcUa_ReturnErrorIfArgumentNull(a_pDiagnosticInfos);

	OpcUa_ReferenceParameter(a_nMaxAge);
	OpcUa_ReferenceParameter(a_eTimestampsToReturn);

	*a_pResults = (OpcUa_DataValue*)OpcUa_Alloc(sizeof(OpcUa_DataValue)*a_nNoOfNodesToRead);
	OpcUa_GotoErrorIfAllocFailed(*a_pResults);
	*a_pNoOfResults = a_nNoOfNodesToRead;

	for (ii = 0; ii < a_nNoOfNodesToRead; ii++)
	{
		OpcUa_DataValue_Initialize(&(*a_pResults)[ii]);

		(*a_pResults)[ii].ServerTimestamp = OpcUa_DateTime_UtcNow();
		(*a_pResults)[ii].SourceTimestamp = OpcUa_DateTime_UtcNow();

		if (ii % 2 == 0)
		{
			(*a_pResults)[ii].Value.Datatype = OpcUaType_Double;
			(*a_pResults)[ii].Value.Value.Double = 3.1415;
		}
		else
		{
			(*a_pResults)[ii].Value.Datatype = OpcUaType_String;
			OpcUa_String_AttachCopy(&(*a_pResults)[ii].Value.Value.String, "Hello World!");
		}
	}

	a_pResponseHeader->RequestHandle = a_pRequestHeader->RequestHandle;
	a_pResponseHeader->Timestamp = OpcUa_DateTime_UtcNow();

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    /* nothing to do */

OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode UaTestServer_OpenEndpoint(OpcUa_StringA sEndpointUrl, OpcUa_StringA sProfileUrl, OpcUa_Endpoint* phEndpoint)
{
	OpcUa_Endpoint hEndpoint = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "UaTestServer_OpenEndpoint");

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OPEN ENDPOINT %s\n", sEndpointUrl);

	/* initialize endpoint */
	uStatus = OpcUa_Endpoint_Create(&hEndpoint, OpcUa_Endpoint_SerializerType_Binary, UaTestServer_SupportedServices);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_Endpoint_Open(
		hEndpoint,                                      /* Endpoint Instance        */
		sEndpointUrl,                                   /* Endpoint URL             */
		OpcUa_True,                                     /* The transport profile    */
		UaTestServer_EndpointCallback,                  /* Endpoint Callback        */
		OpcUa_Null,                                     /* Endpoint Callback Data   */
		&UaTestServer_g_ServerCertificate,              /* Server Certificate       */
		&UaTestServer_g_ServerPrivateKey,               /* Private Key              */
		&UaTestServer_g_PkiConfig,                      /* PKI Configuration        */
		UaTestServer_g_uNoOfSecurityPolicies,           /* NoOf SecurityPolicies    */
		UaTestServer_g_pSecurityPolicyConfigurations);  /* SecurityPolicies         */

	OpcUa_GotoErrorIfBad(uStatus);

	*phEndpoint = hEndpoint;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	/* Clean up comm */
	OpcUa_Endpoint_Delete(&hEndpoint);

OpcUa_FinishErrorHandling;
}

OpcUa_StatusCode UaTestServer_Serve(OpcUa_Void)
{
    OpcUa_Endpoint hTcpEndpoint = OpcUa_Null;
	OpcUa_Endpoint hTlsEndpoint = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "UaTestServer_Serve");

    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "********************** Starting Server! *************************\n");

	/* initialize TCP endpoint */
	uStatus = UaTestServer_OpenEndpoint(UATESTSERVER_ENDPOINT_URL, UATESTSERVER_DEFAULT_TRANSPORT_PROFILE_URI, &hTcpEndpoint);
	OpcUa_GotoErrorIfBad(uStatus);

	/* initialize TLS endpoint */
	uStatus = UaTestServer_OpenEndpoint(UATESTSERVER_ENDPOINT_TLS_URL, UATESTSERVER_WSS_TRANSPORT_PROFILE_URI, &hTlsEndpoint);
	OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "********************** Server started! *************************\n");
	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "Press 'x' to quit.\n");

    /******************************************************************************/
    /* Wait for user command to terminate the server thread.                      */
    /* While looping here, server is active.                                      */
    /* When in SingleThread config, we need to drive the socket event             */
    /* loop to keep message and timer processing active.                          */
    /******************************************************************************/
    /**/ while(!UaTestServer_CheckForKeypress())                                /**/
    /**/ {                                                                      /**/
#if OPCUA_MULTITHREADED                                                         /**/
    /**/    OpcUa_Thread_Sleep(100);                                            /**/
#else /* OPCUA_MULTITHREADED */                                                 /**/
    /**/    uStatus = OpcUa_SocketManager_Loop(OpcUa_Null, 100, OpcUa_True);    /**/
    /**/    if(OpcUa_IsBad(uStatus))                                            /**/
    /**/    {                                                                   /**/
    /**/        break;                                                          /**/
    /**/    }                                                                   /**/
#endif /* OPCUA_MULTITHREADED */                                                /**/
    /**/ }                                                                      /**/
    /******************************************************************************/

    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "********************** Stopping Server! ************************\n");

    /* wait for other threads to stop */
    UaTestServer_SetAndWaitShutdown();

    /* close endpoints */
    uStatus = OpcUa_Endpoint_Close(hTcpEndpoint);
    OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_Endpoint_Close(hTlsEndpoint);
	OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "********************** Server stopped! *************************\n");

    /* Clean up */
    OpcUa_Endpoint_Delete(&hTcpEndpoint);
	OpcUa_Endpoint_Delete(&hTlsEndpoint);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
    
    /* Clean up comm */
	OpcUa_Endpoint_Delete(&hTcpEndpoint);
	OpcUa_Endpoint_Delete(&hTlsEndpoint);

OpcUa_FinishErrorHandling;
}

/*********************************************************************************************/
/***********************        Application Main Entry Point          ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Main entry function.                                                              */
/*===========================================================================================*/
int main(void)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

#if UATESTSERVER_USE_CRTDBG
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    //_CrtSetBreakAlloc(140);
#endif


    char x[2013];
    GetCurrentDirectoryA(2000, x);

    /* Initialize Stack */
    uStatus = UaTestServer_Initialize();

    if (OpcUa_IsBad(uStatus))
    {
        printf("Could not initialize application!\n");
        OpcUa_GotoError;
    }

    uStatus = UaTestServer_Serve();

    /* Clean up Base */
    UaTestServer_Clear();
    
    return (int)uStatus;

Error:

#if UATESTSERVER_WAIT_FOR_USER_INPUT
    printf("Couldn't start server!\nPress enter to exit!\n");
    getchar();
#endif

    /* Clean up Base */
    UaTestServer_Clear();

    return (int)uStatus;
}

/*********************************************************************************************/
/***********************                End Of File                   ************************/
/*********************************************************************************************/
