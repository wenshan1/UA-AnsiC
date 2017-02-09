/*********************************************************************************************/
/*****************     A simple UA test client based on the Ansi C Stack     *****************/
/*********************************************************************************************/

#include "main.h"

/*********************************************************************************************/
/***********************                    Types                     ************************/
/*********************************************************************************************/
typedef struct _OAuth2TestClient_CertificateLocations
{
	OpcUa_StringA CertificateRevocationListLocation;
	OpcUa_StringA CertificateTrustListLocation;
	OpcUa_StringA ClientCertificateLocation;
	OpcUa_StringA ClientPrivateKeyLocation;
	OpcUa_StringA ServerCertificateLocation;
} 
OAuth2TestClient_CertificateLocations;

/*********************************************************************************************/
/***********************                  Globals                     ************************/
/*********************************************************************************************/
OpcUa_Handle                                OAuth2TestClient_g_pPortLayerHandle = OpcUa_Null;
OpcUa_StatusCode                            OAuth2TestClient_g_uStatus = OpcUa_Good;
OpcUa_PKIProvider                           OAuth2TestClient_g_PkiProvider = { OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null, OpcUa_Null };
OpcUa_String                                OAuth2TestClient_g_pSecurityPolicy = OPCUA_STRING_STATICINITIALIZER;
OpcUa_ByteString                            OAuth2TestClient_g_ClientCertificate = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ByteString                            OAuth2TestClient_g_ServerCertificate = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ByteString                            OAuth2TestClient_g_ClientPrivateKey = OPCUA_BYTESTRING_STATICINITIALIZER;
OpcUa_ProxyStubConfiguration                OAuth2TestClient_g_pProxyStubConfiguration;
OpcUa_P_OpenSSL_CertificateStore_Config     OAuth2TestClient_g_PkiConfig;

/*********************************************************************************************/
/***********************               Internal Helpers               ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Wait for x to be pressed.                                                         */
/*===========================================================================================*/
OpcUa_Boolean OAuth2TestClient_CheckForKeypress()
{
	if (!_kbhit()) {}
	else { if (_getch() == 'x') { return 1; } }return 0;
}

/*===========================================================================================*/
/** @brief Sets a servers and clients certificate and private key.                           */
/*===========================================================================================*/
static OpcUa_StatusCode OAuth2TestClient_InitializePKI()
{
	OpcUa_Handle hCertificateStore = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Server, "InitializePKI");

	OAuth2TestClient_g_PkiConfig.PkiType = OpcUa_OpenSSL_PKI;
	OAuth2TestClient_g_PkiConfig.CertificateTrustListLocation = UACLIENT_CERTIFICATE_TRUST_LIST_LOCATION;
	OAuth2TestClient_g_PkiConfig.CertificateRevocationListLocation = UACLIENT_CERTIFICATE_REVOCATION_LIST_LOCATION;
	OAuth2TestClient_g_PkiConfig.Override = OpcUa_Null;

	uStatus = OpcUa_PKIProvider_Create(&OAuth2TestClient_g_PkiConfig, &OAuth2TestClient_g_PkiProvider);
	OpcUa_ReturnErrorIfBad(uStatus);

#if UACLIENT_USE_SECURE_COMMUNICATION

	/* Open Certificate Store */
	uStatus = OAuth2TestClient_g_PkiProvider.OpenCertificateStore(
		&OAuth2TestClient_g_PkiProvider,
		&hCertificateStore);
	
	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_InitializePKI: Failed to open certificate store! (0x%08X)\n", uStatus);
		OpcUa_GotoError;
	}

	/*** Get client certificate ***/
	uStatus = OAuth2TestClient_g_PkiProvider.LoadCertificate(
		&OAuth2TestClient_g_PkiProvider,
		UACLIENT_CERTIFICATE_LOCATION,
		hCertificateStore,
		&OAuth2TestClient_g_ClientCertificate);
	
	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_InitializePKI: Failed to load client certificate \"%s\"! (0x%08X)\n", UACLIENT_CERTIFICATE_LOCATION, uStatus);
		OpcUa_GotoError;
	}

	{
		OpcUa_Int iValidationCode = 0;

		uStatus = OAuth2TestClient_g_PkiProvider.ValidateCertificate(
			&OAuth2TestClient_g_PkiProvider,
			&OAuth2TestClient_g_ClientCertificate,
			hCertificateStore,
			&iValidationCode);

		if (OpcUa_IsBad(uStatus))
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_InitializePKI: Client certificate invalid!\n");
			return uStatus;
		}
	}

	/*** Get private key ***/
	uStatus = OAuth2TestClient_g_PkiProvider.LoadPrivateKeyFromFile(
		UACLIENT_PRIVATE_KEY_LOCATION,
		OpcUa_Crypto_Encoding_PEM,
		OpcUa_Null,
		&OAuth2TestClient_g_ClientPrivateKey);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_InitializePKI: Failed to load client private key \"%s\"! (0x%08X)\n", UACLIENT_PRIVATE_KEY_LOCATION, uStatus);
		OpcUa_GotoError;
	}

	/* Close Certificate Store */
	OAuth2TestClient_g_PkiProvider.CloseCertificateStore(&OAuth2TestClient_g_PkiProvider, &hCertificateStore);

#endif /* UACLIENT_USE_SECURE_COMMUNICATION */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_InitializePKI: Could not initialize client PKI.\n");

	if (hCertificateStore != OpcUa_Null)
	{
		OAuth2TestClient_g_PkiProvider.CloseCertificateStore(&OAuth2TestClient_g_PkiProvider,
			&hCertificateStore);
	}

	OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Initializes the demo application.                                                 */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_Initialize()
{
	OpcUa_StatusCode uStatus = OpcUa_Good;

	OAuth2Initialize();

	OAuth2TestClient_g_pProxyStubConfiguration.bProxyStub_Trace_Enabled = OpcUa_True;
	OAuth2TestClient_g_pProxyStubConfiguration.uProxyStub_Trace_Level = UACLIENT_TRACE_LEVEL;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxAlloc = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxStringLength = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxByteStringLength = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxArrayLength = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxMessageSize = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSerializer_MaxRecursionDepth = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.bSecureListener_ThreadPool_Enabled = OpcUa_False;
	OAuth2TestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MinThreads = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxThreads = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iSecureListener_ThreadPool_MaxJobs = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.bSecureListener_ThreadPool_BlockOnAdd = OpcUa_True;
	OAuth2TestClient_g_pProxyStubConfiguration.uSecureListener_ThreadPool_Timeout = OPCUA_INFINITE;
	OAuth2TestClient_g_pProxyStubConfiguration.iTcpListener_DefaultChunkSize = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iTcpConnection_DefaultChunkSize = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iTcpTransport_MaxMessageLength = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.iTcpTransport_MaxChunkCount = -1;
	OAuth2TestClient_g_pProxyStubConfiguration.bTcpListener_ClientThreadsEnabled = OpcUa_False;
	OAuth2TestClient_g_pProxyStubConfiguration.bTcpStream_ExpectWriteToBlock = OpcUa_True;

	uStatus = OpcUa_P_Initialize(&OAuth2TestClient_g_pPortLayerHandle);
	OpcUa_ReturnErrorIfBad(uStatus);

	uStatus = OpcUa_ProxyStub_Initialize(OAuth2TestClient_g_pPortLayerHandle, &OAuth2TestClient_g_pProxyStubConfiguration);
	OpcUa_ReturnErrorIfBad(uStatus);

	uStatus = OpcUa_String_AttachReadOnly(&OAuth2TestClient_g_pSecurityPolicy, UACLIENT_SECURITY_POLICY);
	OpcUa_ReturnErrorIfBad(uStatus);
	
	uStatus = OAuth2TestClient_InitializePKI();
	OpcUa_ReturnErrorIfBad(uStatus);

	return uStatus;
}

/*===========================================================================================*/
/** @brief Cleans up all security ressources from the demo application.                      */
/*===========================================================================================*/
OpcUa_Void OAuth2TestClient_SecurityClear(OpcUa_Void)
{
	OpcUa_String_Clear(&OAuth2TestClient_g_pSecurityPolicy);

	OpcUa_ByteString_Clear(&OAuth2TestClient_g_ClientPrivateKey);
	OpcUa_ByteString_Clear(&OAuth2TestClient_g_ClientCertificate);
	OpcUa_ByteString_Clear(&OAuth2TestClient_g_ServerCertificate);

	OpcUa_PKIProvider_Delete(&OAuth2TestClient_g_PkiProvider);
}

/*===========================================================================================*/
/** @brief Cleans up all resources from the demo application.                               */
/*===========================================================================================*/
OpcUa_Void OAuth2TestClient_Cleanup()
{
	/* clear pki and security policies */
	OAuth2TestClient_SecurityClear();

	OpcUa_ProxyStub_Clear();

	OpcUa_P_Clean(&OAuth2TestClient_g_pPortLayerHandle);

	OAuth2Cleanup();
}

/*********************************************************************************************/
/****************************     Main Service Call Chains     *******************************/
/*********************************************************************************************/

typedef struct _Session
{
	OpcUa_Channel Channel;
	OpcUa_String EndpointUrl;
	OpcUa_String ApplicationUri;
	OpcUa_NodeId SessionId;
	OpcUa_NodeId AuthenticationToken;
	OpcUa_Double RevisedSessionTimeout;
	OpcUa_ByteString ServerNonce;
	OpcUa_ByteString ServerCertificate;
	OpcUa_UserTokenPolicy IdentityTokenPolicy;
	OpcUa_ExtensionObject IdentityToken;
	OpcUa_UInt32 SubscriptionId;
	OpcUa_Int32 SequenceNumbersCount;
	OpcUa_UInt32* SequenceNumbers;
	OpcUa_Int32 MonitoredItemsCount;
	OpcUa_UInt32* MonitoredItems;
	OpcUa_DataValue* MonitoredValues;
}
Session;

void Session_Initialize(Session* pSession)
{
	OpcUa_MemSet(pSession, 0, sizeof(Session));
}

void Session_Clear(Session* pSession)
{
	OpcUa_String_Clear(&pSession->EndpointUrl);
	OpcUa_String_Clear(&pSession->ApplicationUri);
	OpcUa_NodeId_Clear(&pSession->SessionId);
	OpcUa_NodeId_Clear(&pSession->AuthenticationToken);
	OpcUa_ByteString_Clear(&pSession->ServerNonce);
	OpcUa_ByteString_Clear(&pSession->ServerCertificate);
	OpcUa_UserTokenPolicy_Clear(&pSession->IdentityTokenPolicy);
	OpcUa_ExtensionObject_Clear(&pSession->IdentityToken);
	OpcUa_ClearArray(OpcUa_UInt32, pSession->SequenceNumbers, pSession->SequenceNumbersCount);
	OpcUa_Free(pSession->MonitoredItems);
	pSession->MonitoredItems = 0;
	OpcUa_ClearArray(OpcUa_DataValue, pSession->MonitoredValues, pSession->MonitoredItemsCount);

	OpcUa_MemSet(pSession, 0, sizeof(Session));
}

/*===========================================================================================*/
/** @brief Connect to the server.                                                            */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_Connect(Session* a_pSession, OpcUa_Boolean a_bUseSecurity)
{
	OpcUa_String szSecurityPolicy;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_Connect");

	OpcUa_String_Initialize(&szSecurityPolicy);

	if (a_bUseSecurity)
	{
		uStatus = OpcUa_String_AttachReadOnly(&szSecurityPolicy, UACLIENT_SECURITY_POLICY);
		OpcUa_ReturnErrorIfBad(uStatus);

		uStatus = OpcUa_Channel_Connect(
			a_pSession->Channel,
			UACLIENT_SERVER_URL,
			OpcUa_Null,
			OpcUa_Null,
			&OAuth2TestClient_g_ClientCertificate,
			&OAuth2TestClient_g_ClientPrivateKey,
			&OAuth2TestClient_g_ServerCertificate,
			&OAuth2TestClient_g_PkiConfig,
			&szSecurityPolicy,
			OPCUA_SECURITYTOKEN_LIFETIME_MAX,
			UACLIENT_SECURITY_MODE,
			UACLIENT_TIMEOUT); /* network timeout */
	}
	else
	{
		uStatus = OpcUa_String_AttachReadOnly(&szSecurityPolicy, UACLIENT_SECURITY_POLICY_NONE);
		OpcUa_ReturnErrorIfBad(uStatus);

		uStatus = OpcUa_Channel_Connect(
			a_pSession->Channel,
			UACLIENT_SERVER_URL,
			OpcUa_Null,
			OpcUa_Null,
			&OAuth2TestClient_g_ClientCertificate,
			&OAuth2TestClient_g_ClientPrivateKey,
			OpcUa_Null,
			&OAuth2TestClient_g_PkiConfig,
			&szSecurityPolicy,
			OPCUA_SECURITYTOKEN_LIFETIME_MAX,
			OpcUa_MessageSecurityMode_None,
			UACLIENT_TIMEOUT); /* network timeout */
	}

	/* check for common errors */
	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_Connect: ERROR 0x%8X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_String_Clear(&szSecurityPolicy);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_String_Clear(&szSecurityPolicy);
	OpcUa_Channel_Disconnect(a_pSession->Channel);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Create an ExtensionObject from an EncodeableType                                  */
/*===========================================================================================*/

void* OpcUa_ExtensionObject_CreateFromType(OpcUa_ExtensionObject* a_pExtension, OpcUa_EncodeableType* a_pType)
{
	OpcUa_StatusCode uStatus = OpcUa_EncodeableObject_Create(a_pType, &a_pExtension->Body.EncodeableObject.Object);

	if (OpcUa_IsBad(uStatus))
	{
		return OpcUa_Null;
	}

	a_pExtension->TypeId.NodeId.IdentifierType = OpcUa_IdentifierType_Numeric;
	a_pExtension->TypeId.NodeId.Identifier.Numeric = a_pType->BinaryEncodingTypeId;
	a_pExtension->Encoding = OpcUa_ExtensionObjectEncoding_EncodeableObject;
	a_pExtension->Body.EncodeableObject.Type = a_pType;

	return a_pExtension->Body.EncodeableObject.Object;
}

/*===========================================================================================*/
/** @brief Select the user token policy that supports JWTs.                                  */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_SelectUserTokenPolicy(Session* a_pSession, OpcUa_EndpointDescription* a_pEndpoint)
{
	OpcUa_UserTokenPolicy* pAnonynmous = NULL;
	OpcUa_String szIssuedTokenPolicyUri;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_SelectUserTokenPolicy");

	OpcUa_String_AttachReadOnly(&szIssuedTokenPolicyUri, UACLIENT_JWT_POLICYURI);

	// need to choose a user identity token.
	OpcUa_UserTokenPolicy* pToken = NULL;

	for (int ii = 0; ii < a_pEndpoint->NoOfUserIdentityTokens; ii++)
	{
		pToken = &a_pEndpoint->UserIdentityTokens[ii];

		if (pToken->TokenType == OpcUa_UserTokenType_Anonymous)
		{
			pAnonynmous = &a_pEndpoint->UserIdentityTokens[ii];
			continue;
		}

		if (pToken->TokenType == OpcUa_UserTokenType_IssuedToken && OpcUa_String_StrnCmp(&szIssuedTokenPolicyUri, &pToken->IssuedTokenType, OPCUA_STRING_LENDONTCARE, OpcUa_False) == 0)
		{
			break;
		}

		pToken = NULL;
	}

	if (pToken == NULL)
	{
		if (pAnonynmous != NULL)
		{
			OpcUa_AnonymousIdentityToken* pBody = (OpcUa_AnonymousIdentityToken*)OpcUa_ExtensionObject_CreateFromType(&a_pSession->IdentityToken, &OpcUa_AnonymousIdentityToken_EncodeableType);
			OpcUa_GotoErrorIfNull(pBody, OpcUa_BadOutOfMemory);

			uStatus = OpcUa_String_CopyTo(&pAnonynmous->PolicyId, &pBody->PolicyId);
			OpcUa_GotoErrorIfBad(uStatus);

			pToken = pAnonynmous;
		}
	}

	if (pToken == NULL)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_SelectUserTokenPolicy: No suitable user token policy (anonymous or JWT required).\n");
	}

	if (pToken != NULL)
	{
		a_pSession->IdentityTokenPolicy.TokenType = pToken->TokenType;
		uStatus = OpcUa_String_CopyTo(&pToken->PolicyId, &a_pSession->IdentityTokenPolicy.PolicyId);
		OpcUa_GotoErrorIfBad(uStatus);
		uStatus = OpcUa_String_CopyTo(&pToken->SecurityPolicyUri, &a_pSession->IdentityTokenPolicy.SecurityPolicyUri);
		OpcUa_GotoErrorIfBad(uStatus);
		uStatus = OpcUa_String_CopyTo(&pToken->IssuedTokenType, &a_pSession->IdentityTokenPolicy.IssuedTokenType);
		OpcUa_GotoErrorIfBad(uStatus);
		uStatus = OpcUa_String_CopyTo(&pToken->IssuerEndpointUrl, &a_pSession->IdentityTokenPolicy.IssuerEndpointUrl);
		OpcUa_GotoErrorIfBad(uStatus);
	}

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Requests an access token from an authorization server.                            */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_RequestAccessToken(Session* a_pSession)
{
	OAuth2Request request;
	OAuth2Response response;
	OpcUa_IssuedIdentityToken* pToken = NULL;
	OpcUa_String szAuthorityUrl;
	OpcUa_String szScope;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_RequestAccessToken");

	OAuth2Request_Initialize(&request);
	OAuth2Response_Initialize(&response);
	OpcUa_ExtensionObject_Clear(&a_pSession->IdentityToken);
	OpcUa_String_Initialize(&szAuthorityUrl);
	OpcUa_String_Initialize(&szScope);

	/* this information should come from configuration files. */
	OpcUa_String_AttachReadOnly(&request.ClientId, UACLIENTURI);
	OpcUa_String_AttachReadOnly(&request.ClientSecret, UACLIENT_JWT_CLIENTSECRET);

	/* using the ServerUri as the resource restricts the token to resources controlled by the server. */
	/* using the predefined URI "urn:opcfoundation.org:ua:oauth2:resource:site" as the resource allows access to shared resources */
	OpcUa_String_StrnCpy(&request.Resource, &a_pSession->ApplicationUri, OPCUA_STRING_LENDONTCARE);

	/* parse the IssuerEndpointUrl to get necessary information about the OAuth2 authorization service. */
	json_object* pRoot = json_tokener_parse(OpcUa_String_GetRawString(&a_pSession->IdentityTokenPolicy.IssuerEndpointUrl));

	if (pRoot != NULL)
	{
		OpcUa_CharA szBuffer[1024];
		json_object* pTarget = NULL;
		szBuffer[0] = 0;

		json_object_object_get_ex(pRoot, "ua:authorityUrl", &pTarget);

		if (pTarget != NULL)
		{
			strcpy(szBuffer, json_object_get_string(pTarget));
		}

		json_object_object_get_ex(pRoot, "ua:tokenEndpoint", &pTarget);

		if (pTarget != NULL)
		{
			strcat(szBuffer, json_object_get_string(pTarget));
		}

		OpcUa_String_AttachCopy(&request.AuthorizationServerUrl, szBuffer);

		json_object_object_get_ex(pRoot, "ua:scopes", &pTarget);

		/* request the default scope recommended by the server and append the 'pubsub' scope. */
		szBuffer[0] = 0;

		if (pTarget != NULL && json_object_array_length(pTarget) > 0)
		{
			json_object* pElement = json_object_array_get_idx(pTarget, 0);
			strcat_s(szBuffer, 1024, json_object_get_string(pElement));
		}

		strcat_s(szBuffer, 1024, " UAPubSub");
		OpcUa_String_AttachCopy(&request.Scope, szBuffer);

		json_object_put(pRoot);
	}
	
	uStatus = OAuth2RequestTokenWithClientCredentials(&request, &response);
	OpcUa_GotoErrorIfBad(uStatus);

	if (response.ErrorOccured)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not get AccessToken response %s\n", OpcUa_String_GetRawString(&response.ErrorText));
	}

	pToken = (OpcUa_IssuedIdentityToken*)OpcUa_ExtensionObject_CreateFromType(&a_pSession->IdentityToken, &OpcUa_IssuedIdentityToken_EncodeableType);
	OpcUa_GotoErrorIfNull(pToken, OpcUa_BadOutOfMemory);

	uStatus = OpcUa_String_CopyTo(&a_pSession->IdentityTokenPolicy.PolicyId, &pToken->PolicyId);
	OpcUa_GotoErrorIfBad(uStatus);

	pToken->TokenData.Length = OpcUa_String_StrLen(&response.AccessToken);
	pToken->TokenData.Data = OpcUa_Alloc(pToken->TokenData.Length);
	OpcUa_GotoErrorIfAllocFailed(pToken->TokenData.Data);
	OpcUa_MemCpy(pToken->TokenData.Data, pToken->TokenData.Length, OpcUa_String_GetRawString(&response.AccessToken), pToken->TokenData.Length);

	OAuth2Request_Clear(&request);
	OAuth2Response_Clear(&response);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_ExtensionObject_Clear(&a_pSession->IdentityToken);
	OAuth2Request_Clear(&request);
	OAuth2Response_Clear(&response);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Get the endpoints.                                                                */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_GetEndpoints(Session* a_pSession)
{
	OpcUa_RequestHeader requestHeader;
	OpcUa_ResponseHeader responseHeader;
	OpcUa_String endpointUrl;
	OpcUa_Int32 endpointCount = 0;
	OpcUa_EndpointDescription* pEndpoints = NULL;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_GetEndpoints");

	OpcUa_RequestHeader_Initialize(&requestHeader);
	OpcUa_ResponseHeader_Initialize(&responseHeader);

	requestHeader.TimeoutHint = 60000;
	requestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	uStatus = OpcUa_String_AttachToString(UACLIENT_SERVER_URL, OPCUA_STRINGLENZEROTERMINATED, 0, OpcUa_True, OpcUa_True, &endpointUrl);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OpcUa_ClientApi_GetEndpoints(
		a_pSession->Channel,
		&requestHeader,
		&endpointUrl,
		0,
		OpcUa_Null,
		0,
		OpcUa_Null,
		&responseHeader,
		&endpointCount,
		&pEndpoints);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_GetEndpoints: ERROR 0x%8X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	for (int ii = 0; ii < endpointCount; ii++)
	{
		if (pEndpoints[ii].SecurityMode == UACLIENT_SECURITY_MODE && OpcUa_String_StrnCmp(&pEndpoints[ii].SecurityPolicyUri, &OAuth2TestClient_g_pSecurityPolicy, OPCUA_STRING_LENDONTCARE, OpcUa_False) == 0)
		{
			OpcUa_String_CopyTo(&pEndpoints[ii].EndpointUrl, &a_pSession->EndpointUrl);
			OpcUa_String_CopyTo(&pEndpoints[ii].Server.ApplicationUri, &a_pSession->ApplicationUri);
			OpcUa_ByteString_CopyTo(&pEndpoints[ii].ServerCertificate, &OAuth2TestClient_g_ServerCertificate);
			uStatus = OAuth2TestClient_SelectUserTokenPolicy(a_pSession, &pEndpoints[ii]);
			OpcUa_GotoErrorIfBad(uStatus);
			break;
		}
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OAuth2TestClient_GetEndpoints: Selecting Endpoint %s.\n", OpcUa_String_GetRawString(&a_pSession->EndpointUrl));

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_String_Clear(&endpointUrl);
	OpcUa_ClearArray(OpcUa_EndpointDescription, pEndpoints, endpointCount);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_String_Clear(&endpointUrl);
	OpcUa_ClearArray(OpcUa_EndpointDescription, pEndpoints, endpointCount);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Create a new session.                                                             */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_CreateSession(Session* a_pSession)
{
	OpcUa_RequestHeader requestHeader;
	OpcUa_ResponseHeader responseHeader;
	OpcUa_ApplicationDescription clientDescription;
	OpcUa_ByteString clientNonce;
	OpcUa_ByteString clientCertificate;
	OpcUa_Double requestedSessionTimeout = 0;
	OpcUa_UInt32 maxResponseMessageSize = 0;
	OpcUa_Int32 noOfServerEndpoints = 0;
	OpcUa_EndpointDescription* pServerEndpoints = NULL;
	OpcUa_Int32 noOfServerSoftwareCertificates = 0;
	OpcUa_SignedSoftwareCertificate* pServerSoftwareCertificates = NULL;
	OpcUa_SignatureData serverSignature;
	OpcUa_UInt32 maxRequestMessageSize = 0;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_CreateSession");

	OpcUa_RequestHeader_Initialize(&requestHeader);
	OpcUa_ResponseHeader_Initialize(&responseHeader);
	OpcUa_ApplicationDescription_Initialize(&clientDescription);
	OpcUa_ByteString_Initialize(&clientNonce);
	OpcUa_ByteString_Initialize(&clientCertificate);
	OpcUa_SignatureData_Initialize(&serverSignature);

	requestHeader.TimeoutHint = 60000;
	requestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	clientDescription.ApplicationType = OpcUa_ApplicationType_Client;

	OpcUa_String_AttachReadOnly(&clientDescription.ApplicationName.Text, UACLIENTNAME);
	OpcUa_String_AttachReadOnly(&clientDescription.ApplicationUri, UACLIENTURI);
	OpcUa_String_AttachReadOnly(&clientDescription.ProductUri, UACLIENT_PRODUCTURI);

	requestedSessionTimeout = 60000; 
	maxResponseMessageSize = 1024*1024;

	uStatus = OpcUa_ClientApi_CreateSession(
		a_pSession->Channel,
		&requestHeader,
		&clientDescription,
		&a_pSession->ApplicationUri,
		&a_pSession->EndpointUrl,
		&clientDescription.ApplicationName.Text,
		&clientNonce,
		&clientCertificate,
		requestedSessionTimeout,
		maxResponseMessageSize,
		&responseHeader,
		&a_pSession->SessionId,
		&a_pSession->AuthenticationToken,
		&a_pSession->RevisedSessionTimeout,
		&a_pSession->ServerNonce,
		&a_pSession->ServerCertificate,
		&noOfServerEndpoints,
		&pServerEndpoints,
		&noOfServerSoftwareCertificates,
		&pServerSoftwareCertificates,
		&serverSignature,
		&maxRequestMessageSize);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_CreateSession: ERROR 0x%8X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (OpcUa_IsBad(responseHeader.ServiceResult))
	{
		uStatus = responseHeader.ServiceResult;
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_CreateSession: ERROR 0x%8X.\n", responseHeader.ServiceResult);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OAuth2TestClient_CreateSession: Selecting Endpoint %s.\n", OpcUa_String_GetRawString(&a_pSession->EndpointUrl));

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_ApplicationDescription_Clear(&clientDescription);
	OpcUa_ByteString_Clear(&clientNonce);
	OpcUa_ByteString_Clear(&clientCertificate);
	OpcUa_SignatureData_Clear(&serverSignature);
	OpcUa_ClearArray(OpcUa_EndpointDescription, pServerEndpoints, noOfServerEndpoints);
	OpcUa_ClearArray(OpcUa_SignedSoftwareCertificate, pServerSoftwareCertificates, noOfServerSoftwareCertificates);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_ApplicationDescription_Clear(&clientDescription);
	OpcUa_ByteString_Clear(&clientNonce);
	OpcUa_ByteString_Clear(&clientCertificate);
	OpcUa_SignatureData_Clear(&serverSignature);
	OpcUa_ClearArray(OpcUa_EndpointDescription, pServerEndpoints, noOfServerEndpoints);
	OpcUa_ClearArray(OpcUa_SignedSoftwareCertificate, pServerSoftwareCertificates, noOfServerSoftwareCertificates);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Activate a new session.                                                           */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_ActivateSession(Session* a_pSession)
{
	OpcUa_RequestHeader requestHeader;
	OpcUa_ResponseHeader responseHeader;
	OpcUa_SignatureData clientSignature;
	OpcUa_SignatureData identityTokenSignature;
	OpcUa_Int32 nResultCount = 0;
	OpcUa_StatusCode* pResults = NULL;
	OpcUa_Int32 nDiagnosticInfoCount = 0;
	OpcUa_DiagnosticInfo* pDiagnosticInfos = NULL;
	OpcUa_ByteString revisedNonce;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_ActivateSession");

	OpcUa_RequestHeader_Initialize(&requestHeader);
	OpcUa_ResponseHeader_Initialize(&responseHeader);
	OpcUa_SignatureData_Initialize(&clientSignature);
	OpcUa_SignatureData_Initialize(&identityTokenSignature);
	OpcUa_ByteString_Initialize(&revisedNonce);

	uStatus = OpcUa_NodeId_CopyTo(&a_pSession->AuthenticationToken, &requestHeader.AuthenticationToken);
	OpcUa_GotoErrorIfBad(uStatus);

	requestHeader.TimeoutHint = 60000;
	requestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	uStatus = OpcUa_ClientApi_ActivateSession(
		a_pSession->Channel,
		&requestHeader,
		&clientSignature,
		0,
		NULL,
		0,
		NULL,
		&a_pSession->IdentityToken,
		&identityTokenSignature,
		&responseHeader,
		&revisedNonce,
		&nResultCount,
		&pResults,
		&nDiagnosticInfoCount,
		&pDiagnosticInfos);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_ActivateSession: ERROR 0x%8X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (OpcUa_IsBad(responseHeader.ServiceResult))
	{
		uStatus = responseHeader.ServiceResult;
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_ActivateSession: ERROR 0x%8X.\n", responseHeader.ServiceResult);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_ByteString_Clear(&a_pSession->ServerNonce);
	a_pSession->ServerNonce = revisedNonce;
	OpcUa_ByteString_Initialize(&revisedNonce);

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OAuth2TestClient_CreateSession: Activating Session Endpoint %s.\n", OpcUa_String_GetRawString(&a_pSession->EndpointUrl));

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_SignatureData_Clear(&clientSignature);
	OpcUa_SignatureData_Clear(&identityTokenSignature);
	OpcUa_ClearArray(OpcUa_StatusCode, pResults, nResultCount);
	OpcUa_ClearArray(OpcUa_DiagnosticInfo, pDiagnosticInfos, nDiagnosticInfoCount);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_SignatureData_Clear(&clientSignature);
	OpcUa_SignatureData_Clear(&identityTokenSignature);
	OpcUa_ClearArray(OpcUa_StatusCode, pResults, nResultCount);
	OpcUa_ClearArray(OpcUa_DiagnosticInfo, pDiagnosticInfos, nDiagnosticInfoCount);
	OpcUa_ByteString_Clear(&revisedNonce);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Close session.                                                                    */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_CloseSession(Session* a_pSession)
{
	OpcUa_RequestHeader requestHeader;
	OpcUa_ResponseHeader responseHeader;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_CloseSession");

	OpcUa_RequestHeader_Initialize(&requestHeader);
	OpcUa_ResponseHeader_Initialize(&responseHeader);

	uStatus = OpcUa_NodeId_CopyTo(&a_pSession->AuthenticationToken, &requestHeader.AuthenticationToken);
	OpcUa_GotoErrorIfBad(uStatus);

	requestHeader.TimeoutHint = 60000;
	requestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	uStatus = OpcUa_ClientApi_CloseSession(
		a_pSession->Channel,
		&requestHeader,
		OpcUa_True,
		&responseHeader);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_CloseSession: ERROR 0x%8X.\n", uStatus);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (OpcUa_IsBad(responseHeader.ServiceResult))
	{
		uStatus = responseHeader.ServiceResult;
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_CloseSession: ERROR 0x%8X.\n", responseHeader.ServiceResult);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OAuth2TestClient_CloseSession: SUCCESS\n");

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);

OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Get the security keys from the server.                                            */
/*===========================================================================================*/
OpcUa_StatusCode OAuth2TestClient_GetSecurityKeys(Session* a_pSession, OpcUa_StringA a_szGroupName)
{
	OpcUa_RequestHeader requestHeader;
	OpcUa_ResponseHeader responseHeader;
	OpcUa_Int32 nItemCount = 0;
	OpcUa_CallMethodRequest* pItems = NULL;
	OpcUa_Int32 nResultCount = 0;
	OpcUa_CallMethodResult* pResults = NULL;
	OpcUa_Int32 nDiagnosticInfoCount = 0;
	OpcUa_DiagnosticInfo* pDiagnosticInfos = NULL;

	OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2TestClient_Call");

	OpcUa_RequestHeader_Initialize(&requestHeader);
	OpcUa_ResponseHeader_Initialize(&responseHeader);

	uStatus = OpcUa_NodeId_CopyTo(&a_pSession->AuthenticationToken, &requestHeader.AuthenticationToken);
	OpcUa_GotoErrorIfBad(uStatus);

	requestHeader.TimeoutHint = 60000;
	requestHeader.Timestamp = OpcUa_DateTime_UtcNow();

	nItemCount = 1;
	pItems = (OpcUa_CallMethodRequest*)OpcUa_Alloc(sizeof(OpcUa_CallMethodRequest)*nItemCount);
	OpcUa_GotoErrorIfAllocFailed(pItems);
	OpcUa_MemSet(pItems, 0, sizeof(OpcUa_CallMethodRequest)*nItemCount);

	pItems[0].ObjectId.NamespaceIndex = 0;
	pItems[0].ObjectId.IdentifierType = OpcUa_IdentifierType_Numeric;
	pItems[0].ObjectId.Identifier.Numeric = OpcUaId_PublishSubscribe;

	pItems[0].MethodId.NamespaceIndex = 0;
	pItems[0].MethodId.IdentifierType = OpcUa_IdentifierType_Numeric;
	pItems[0].MethodId.Identifier.Numeric = OpcUaId_PublishSubscribe_GetSecurityKeys;

	pItems[0].NoOfInputArguments = 2;
	pItems[0].InputArguments = (OpcUa_Variant*)OpcUa_Alloc(sizeof(OpcUa_Variant)*pItems[0].NoOfInputArguments);
	OpcUa_GotoErrorIfAllocFailed(pItems[0].InputArguments);
	OpcUa_MemSet(pItems[0].InputArguments, 0, sizeof(OpcUa_Variant)*pItems[0].NoOfInputArguments);

	pItems[0].InputArguments[0].Datatype = OpcUaType_String;
	OpcUa_String_AttachCopy(&pItems[0].InputArguments[0].Value.String, a_szGroupName);
	pItems[0].InputArguments[1].Datatype = OpcUaType_UInt32;
	pItems[0].InputArguments[1].Value.UInt32 = 3;

	uStatus = OpcUa_ClientApi_Call(
		a_pSession->Channel,
		&requestHeader,
		nItemCount,
		pItems,
		&responseHeader,
		&nResultCount,
		&pResults,
		&nDiagnosticInfoCount,
		&pDiagnosticInfos);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_Call: Call returned ERROR 0x%8X.\n", responseHeader.ServiceResult);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	if (OpcUa_IsBad(responseHeader.ServiceResult))
	{
		uStatus = responseHeader.ServiceResult;
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2TestClient_Call: Server returned ERROR 0x%8X.\n", responseHeader.ServiceResult);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	for (int ii = 0; ii < nResultCount; ii++)
	{
		PrintCallResult(&pItems[ii], &pResults[ii]);
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "OAuth2TestClient_Call: SUCCESS\n");

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_ClearArray(OpcUa_CallMethodRequest, pItems, nItemCount);
	OpcUa_ClearArray(OpcUa_CallMethodResult, pResults, nResultCount);
	OpcUa_ClearArray(OpcUa_DiagnosticInfo, pDiagnosticInfos, nDiagnosticInfoCount);

	OpcUa_ReturnStatusCode;
	OpcUa_BeginErrorHandling;

	OpcUa_RequestHeader_Clear(&requestHeader);
	OpcUa_ResponseHeader_Clear(&responseHeader);
	OpcUa_ClearArray(OpcUa_CallMethodRequest, pItems, nItemCount);
	OpcUa_ClearArray(OpcUa_CallMethodResult, pResults, nResultCount);
	OpcUa_ClearArray(OpcUa_DiagnosticInfo, pDiagnosticInfos, nDiagnosticInfoCount);

	OpcUa_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Main entry function.                                                              */
/*===========================================================================================*/
int Main_GetSecurityKeyWithUaTcp()
{
	OpcUa_StatusCode uStatus = OpcUa_Good;
	Session session;

	Session_Initialize(&session);

	/* need to fetch the metadata from the server using an insecure channel */
	uStatus = OpcUa_Channel_Create(&session.Channel, OpcUa_Channel_SerializerType_Binary);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OAuth2TestClient_Connect(&session, OpcUa_False);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OAuth2TestClient_GetEndpoints(&session);
	OpcUa_GotoErrorIfBad(uStatus);

	/* need to request an access token from the authorization service if that option is available */
	if (session.IdentityTokenPolicy.TokenType == OpcUa_UserTokenType_IssuedToken)
	{
		uStatus = OAuth2TestClient_RequestAccessToken(&session);
		OpcUa_GotoErrorIfBad(uStatus);
	}

	OpcUa_Channel_Disconnect(session.Channel);
	OpcUa_Channel_Delete(&session.Channel);

	/* now need to connect to server using secuire with any access token */
	uStatus = OpcUa_Channel_Create(&session.Channel, OpcUa_Channel_SerializerType_Binary);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OAuth2TestClient_Connect(&session, OpcUa_True);
	OpcUa_GotoErrorIfBad(uStatus);

#ifndef UACLIENT_USE_SESSIONLESS_REQUESTS

	/* create a normal UA session before call the method. */
	uStatus = OAuth2TestClient_CreateSession(&session);
	OpcUa_GotoErrorIfBad(uStatus);

	uStatus = OAuth2TestClient_ActivateSession(&session);
	OpcUa_GotoErrorIfBad(uStatus);

#else

	/* pass the JWT token as the AuthenticationToken with creating a session. */
	session.AuthenticationToken.IdentifierType = OpcUa_IdentifierType_String;
	session.AuthenticationToken.NamespaceIndex = 0;
	OpcUa_IssuedIdentityToken* pIssuedToken = (OpcUa_IssuedIdentityToken*)session.IdentityToken.Body.EncodeableObject.Object;

	OpcUa_String_AttachToString(
		(OpcUa_StringA)pIssuedToken->TokenData.Data,
		pIssuedToken->TokenData.Length,
		0,
		OpcUa_True,
		OpcUa_True,
		&session.AuthenticationToken.Identifier.String);

#endif

	/* this group should be accessible based on the scopes specified when requesting the access token */
	uStatus = OAuth2TestClient_GetSecurityKeys(&session, "Group1");
	OpcUa_GotoErrorIfBad(uStatus);

	/* this group should NOT be accessible based on the scopes specified when requesting the access token */
	uStatus = OAuth2TestClient_GetSecurityKeys(&session, "Group2");
	OpcUa_GotoErrorIfBad(uStatus);

	/* this group does not exist */
	uStatus = OAuth2TestClient_GetSecurityKeys(&session, "Group3");
	OpcUa_GotoErrorIfBad(uStatus);

#ifndef UACLIENT_USE_SESSIONLESS_REQUESTS

	/* close the session, */
	uStatus = OAuth2TestClient_CloseSession(&session);
	OpcUa_GotoErrorIfBad(uStatus);

#endif

	OpcUa_Channel_Disconnect(session.Channel);
	OpcUa_Channel_Delete(&session.Channel);
	Session_Clear(&session);

	return 0;

Error:

	OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "**** Error during test ****\n");

	if (session.Channel != OpcUa_Null)
	{
		OpcUa_Channel_Delete(&session.Channel);
	}

	Session_Clear(&session);

	return uStatus;
}

/*********************************************************************************************/
/***********************                End Of File                   ************************/
/*********************************************************************************************/

