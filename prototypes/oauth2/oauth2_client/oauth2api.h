
#include <opcua_clientproxy.h>

typedef struct _OAuth2Request
{
	OpcUa_String AuthorizationServerUrl;
	OpcUa_String ClientId;
	OpcUa_String ClientSecret;
	OpcUa_String Resource;
	OpcUa_String Scope;
}
OAuth2Request;

typedef struct _OAuth2Response
{
	OpcUa_Boolean ErrorOccured;
	OpcUa_String ErrorText;
	OpcUa_String AccessToken;
	OpcUa_String RefreshToken;
}
OAuth2Response;

void OAuth2Request_Initialize(OAuth2Request* pRequest);
void OAuth2Request_Clear(OAuth2Request* pRequest);

void OAuth2Response_Initialize(OAuth2Response* pResponse);
void OAuth2Response_Clear(OAuth2Response* pResponse);

OpcUa_StatusCode OAuth2RequestTokenWithClientCredentials(OAuth2Request* pRequest, OAuth2Response* pResponse);

typedef struct _GetSecurityKeysRequest
{
	OpcUa_String ServerUrl;
	OpcUa_String AccessToken;
	OpcUa_String GroupId;
	OpcUa_UInt32 FutureKeyCount;
}
GetSecurityKeysRequest;

void GetSecurityKeysRequest_Initialize(GetSecurityKeysRequest* pRequest);
void GetSecurityKeysRequest_Clear(GetSecurityKeysRequest* pRequest);

typedef struct _GetSecurityKeysResponse
{
	OpcUa_Boolean ErrorOccured;
	OpcUa_String ErrorText;
	OpcUa_String SecurityPolicyUri;
	OpcUa_UInt32 CurrentTokenId;
	OpcUa_ByteString CurrentKey;
	OpcUa_ByteString* NextKeys;
	OpcUa_UInt32 NoOfNextKeys;
	OpcUa_UInt32 TimeToNextKey;
	OpcUa_UInt32 KeyLifetime;
}
GetSecurityKeysResponse;

void GetSecurityKeysResponse_Initialize(GetSecurityKeysResponse* pResponse);
void GetSecurityKeysResponse_Clear(GetSecurityKeysResponse* pResponse);

OpcUa_StatusCode HttpsGetSecurityKeysWithAccessToken(GetSecurityKeysRequest* pRequest, GetSecurityKeysResponse* pResponse);

void OAuth2Initialize();
void OAuth2Cleanup();

