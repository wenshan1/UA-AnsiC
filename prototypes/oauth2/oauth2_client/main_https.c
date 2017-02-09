/*********************************************************************************************/
/*****************     A simple UA test client based on the Ansi C Stack     *****************/
/*********************************************************************************************/

#include "main.h"

/*********************************************************************************************/
/***********************               Internal Helpers               ************************/
/*********************************************************************************************/

/*===========================================================================================*/
/** @brief Wait for x to be pressed.                                                         */
/*===========================================================================================*/
extern OpcUa_Boolean OAuth2TestClient_CheckForKeypress();

/*===========================================================================================*/
/** @brief Initializes the demo application.                                                 */
/*===========================================================================================*/
extern OpcUa_StatusCode OAuth2TestClient_Initialize(OpcUa_Void);

/*===========================================================================================*/
/** @brief Cleans up all security ressources from the demo application.                      */
/*===========================================================================================*/
extern OpcUa_Void OAuth2TestClient_SecurityClear(OpcUa_Void);

/*===========================================================================================*/
/** @brief Cleans up all ressources from the demo application.                               */
/*===========================================================================================*/
extern OpcUa_Void OAuth2TestClient_Cleanup(OpcUa_Void);

/*===========================================================================================*/
/** @brief Gets the SecurityKeys using HTTPS                                                 */
/*===========================================================================================*/
int Main_GetSecurityKeyWithHttps()
{
	OpcUa_StatusCode uStatus = OpcUa_Good;
	OAuth2Request oauth2Request;
	OAuth2Response oauth2Response;
	GetSecurityKeysRequest callRequest;
	GetSecurityKeysResponse callResponse;
	OpcUa_CharA szHostName[MAX_PATH];
	OpcUa_CharA szUrl[MAX_PATH];

	OAuth2Request_Initialize(&oauth2Request);
	OAuth2Response_Initialize(&oauth2Response);
	GetSecurityKeysRequest_Initialize(&callRequest);
	GetSecurityKeysResponse_Initialize(&callResponse);

	gethostname(szHostName, MAX_PATH);
    for (int ii = 0; szHostName[ii] != 0; ii++) szHostName[ii] = tolower(szHostName[ii]);

	sprintf(szUrl, "https://%s:54333/connect/token", szHostName);
	OpcUa_String_AttachCopy(&oauth2Request.AuthorizationServerUrl, szUrl);

	OpcUa_String_AttachCopy(&oauth2Request.ClientId, UACLIENTURI);
	OpcUa_String_AttachCopy(&oauth2Request.ClientSecret, UACLIENT_JWT_CLIENTSECRET);

    sprintf(szUrl, "urn:%s:somecompany.com:GlobalDiscoveryServer", szHostName);
	OpcUa_String_AttachCopy(&oauth2Request.Resource, szUrl);

    OpcUa_String_AttachCopy(&oauth2Request.Scope, "UAPubSub");

	uStatus = OAuth2RequestTokenWithClientCredentials(&oauth2Request, &oauth2Response);
	OpcUa_GotoErrorIfBad(uStatus);

	if (oauth2Response.ErrorOccured)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not fetch ACCESS TOKEN: %s\n", OpcUa_String_GetRawString(&oauth2Response.ErrorText));
	}

    // uStatus = OAuth2ValidateToken(OpcUa_String_GetRawString(&oauth2Response.AccessToken));
    // OpcUa_GotoErrorIfBad(uStatus);

	OpcUa_String_StrnCpy(&callRequest.AccessToken, &oauth2Response.AccessToken, OPCUA_STRING_LENDONTCARE);

	sprintf(szUrl, "https://%s:58811/", szHostName);
	OpcUa_String_AttachCopy(&callRequest.ServerUrl, szUrl);

	/* this group should be accessible based on the scopes specified when requesting the access token */
	OpcUa_String_AttachCopy(&callRequest.GroupId, "Group1");
	callRequest.FutureKeyCount = 3;

	uStatus = HttpsGetSecurityKeysWithAccessToken(&callRequest, &callResponse);
	OpcUa_GotoErrorIfBad(uStatus);

	if (callResponse.ErrorOccured)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not fetch SECURITY KEYS: %s\n", OpcUa_String_GetRawString(&callResponse.ErrorText));
	}
	else
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "KEYS: %s %u %u %u\n", OpcUa_String_GetRawString(&callResponse.SecurityPolicyUri), callResponse.CurrentTokenId, callResponse.TimeToNextKey, callResponse.KeyLifetime);
	}

	GetSecurityKeysResponse_Clear(&callResponse);

	/* this group should NOT be accessible based on the scopes specified when requesting the access token */
	OpcUa_String_Clear(&callRequest.GroupId);
	OpcUa_String_AttachCopy(&callRequest.GroupId, "Group2");

	uStatus = HttpsGetSecurityKeysWithAccessToken(&callRequest, &callResponse);
	OpcUa_GotoErrorIfBad(uStatus);

	if (callResponse.ErrorOccured)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not fetch SECURITY KEYS: %s\n", OpcUa_String_GetRawString(&callResponse.ErrorText));
	}
	else
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "KEYS: %s %u %u %u\n", OpcUa_String_GetRawString(&callResponse.SecurityPolicyUri), callResponse.CurrentTokenId, callResponse.TimeToNextKey, callResponse.KeyLifetime);
	}

	GetSecurityKeysResponse_Clear(&callResponse);

	/* this group does not exist */
	OpcUa_String_Clear(&callRequest.GroupId);
	OpcUa_String_AttachCopy(&callRequest.GroupId, "Group3");

	uStatus = HttpsGetSecurityKeysWithAccessToken(&callRequest, &callResponse);
	OpcUa_GotoErrorIfBad(uStatus);

	if (callResponse.ErrorOccured)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "Could not fetch SECURITY KEYS: %s\n", OpcUa_String_GetRawString(&callResponse.ErrorText));
		OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
	}
	else
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "KEYS: %s %u %u %u\n", OpcUa_String_GetRawString(&callResponse.SecurityPolicyUri), callResponse.CurrentTokenId, callResponse.TimeToNextKey, callResponse.KeyLifetime);
	}

	OAuth2Request_Clear(&oauth2Request);
	OAuth2Response_Clear(&oauth2Response);
	GetSecurityKeysRequest_Clear(&callRequest);
	GetSecurityKeysResponse_Clear(&callResponse);

	return 0;

Error:

	OAuth2Request_Clear(&oauth2Request);
	OAuth2Response_Clear(&oauth2Response);
	GetSecurityKeysRequest_Clear(&callRequest);
	GetSecurityKeysResponse_Clear(&callResponse);

	return uStatus;
}


