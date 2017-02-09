#pragma once

/*********************************************************************************************/
/***********************                     Config                   ************************/
/*********************************************************************************************/
/* !0 == active, 0 == inactive */
/* use visual studio debug heap */
#define UACLIENT_USE_CRTDBG                             1
/* client signs the messages */
#define UACLIENT_USE_SIGNING                            1
/* client encrypts the messages */
#define UACLIENT_USE_ENCRYPTION                         1
/* use the synchronous api - only possible when multithreading is supported */
#define UACLIENT_USE_SYNC_API                           1
/* standard timeout for connect process */
#define UACLIENT_TIMEOUT                                OPCUA_INFINITE
/* URL of the server */
#define UACLIENT_SERVER_URL                             "opc.tcp://localhost:58810" // 62547
/* Transport profile used by the client */
#define UACLIENT_TRANSPORT_PROFILE_URI                  OpcUa_TransportProfile_UaTcp
/* the used trace level */
#define UACLIENT_TRACE_LEVEL                            OPCUA_TRACE_OUTPUT_LEVEL_SYSTEM
/* whether to wait for user input */
#define UACLIENT_WAIT_FOR_USER_INPUT                    1
/* whether to use session-less requests */
#define UACLIENT_USE_SESSIONLESS_REQUESTS               1

/* PKI Locations - this may need to be changed with other platform layers! */
#define UACLIENT_CERTIFICATE_TRUST_LIST_LOCATION                "./PKI/certs/"
#define UACLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION           "./PKI/crl/"
#define UACLIENT_ISSUER_CERTIFICATE_TRUST_LIST_LOCATION         "./PKI/issuers/"
#define UACLIENT_ISSUER_CERTIFICATE_REVOCATION_LIST_LOCATION    "./PKI/crl/"
#define UACLIENT_CERTIFICATE_LOCATION                           "./PKI/certs/selfsigned.der"
#define UACLIENT_PRIVATE_KEY_LOCATION                           "./PKI/private/selfsignedkey.pem"
#define UACLIENT_SERVER_CERTIFICATE_LOCATION                    "./PKI/certs/selfsigned.der"

#define UACLIENT_JWT_POLICYURI    "http://opcfoundation.org/UA/UserToken#JWT"
#define UACLIENT_JWT_CLIENTSECRET "secret"
#define UACLIENTNAME              "OAuth2TestClient"
#define UACLIENTURI               "urn:localhost:OAuth2TestClient"
#define UACLIENT_PRODUCTURI       "urn:opcfoundation.org:samples"

/* configuration checks */
#if UACLIENT_USE_SIGNING || UACLIENT_USE_ENCRYPTION
#define UACLIENT_USE_SECURE_COMMUNICATION               1
#else
#define UACLIENT_USE_SECURE_COMMUNICATION               0
#endif

#if UACLIENT_USE_ENCRYPTION
#if UACLIENT_USE_SIGNING
/* encryption always includes signing - undef for evaluation only */
#undef UACLIENT_USE_SIGNING
#endif
#endif

#if UACLIENT_USE_SECURE_COMMUNICATION
/* verify the servers certificate after loading, before connecting */
#define UACLIENT_VERIFY_SERVER_CERTIFICATE_LOCALLY  1
/* verify the clients certificate after loading, before connecting */
#define UACLIENT_VERIFY_CLIENT_CERTIFICATE_LOCALLY  1
#endif

/* switch between security policies based on above configuration */
#define UACLIENT_SECURITY_POLICY_NONE               OpcUa_SecurityPolicy_None

#if UACLIENT_USE_ENCRYPTION
#define UACLIENT_SECURITY_POLICY                    OpcUa_SecurityPolicy_Basic128Rsa15
#define UACLIENT_SECURITY_POLICY_LENGTH             OpcUa_StrLenA(OpcUa_SecurityPolicy_Basic128Rsa15)
#define UACLIENT_SECURITY_MODE                      OpcUa_MessageSecurityMode_SignAndEncrypt
#endif

#if UACLIENT_USE_SIGNING
#define UACLIENT_SECURITY_POLICY                    OpcUa_SecurityPolicy_Basic256
#define UACLIENT_SECURITY_POLICY_LENGTH             OpcUa_StrLenA(OpcUa_SecurityPolicy_Basic256)
#define UACLIENT_SECURITY_MODE                      OpcUa_MessageSecurityMode_Sign
#endif

#if !UACLIENT_USE_ENCRYPTION && !UACLIENT_USE_SIGNING
#define UACLIENT_SECURITY_POLICY                    OpcUa_SecurityPolicy_None
#define UACLIENT_SECURITY_POLICY_LENGTH             OpcUa_StrLenA(OpcUa_SecurityPolicy_None)
#define UACLIENT_SECURITY_MODE                      OpcUa_MessageSecurityMode_None
#endif

#if UACLIENT_USE_CRTDBG
#ifndef _WIN32
#undef UACLIENT_USE_CRTDBG
#endif /* _WIN32  */
#endif /* UACLIENT_USE_CRTDBG */

/*============================================================================
* OpcUa_Field_ClearArray
*===========================================================================*/
#define OpcUa_ClearArray(xType, xName, xCount)\
{ \
    int ii; \
\
    for (ii = 0; ii < (xCount) && (xName) != OpcUa_Null; ii++) \
    { \
        xType##_Clear(&((xName)[ii])); \
    } \
\
    OpcUa_Free((xName)); \
\
    xName = OpcUa_Null; \
	xCount = 0; \
}

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

#if UACLIENT_USE_CRTDBG
#include <crtdbg.h>
#endif /* UACLIENT_USE_CRTDBG */

/* vld */
#if UACLIENT_USE_VISUAL_LEAK_DETECTOR
#include <vld.h>
#endif /* UACLIENT_USE_VISUAL_LEAK_DETECTOR */

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

#include "json.h"
#include "oauth2api.h"
#include "print.h"

extern OpcUa_StatusCode OAuth2TestClient_Initialize();

extern void OAuth2TestClient_Cleanup();
