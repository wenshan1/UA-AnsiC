#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <conio.h>
#else
#include <sys/socket.h>
#endif

#include <stdio.h>
#include <ws2tcpip.h>
#include <curl\curl.h>

#include <opcua_clientproxy.h>
#include <opcua_string.h>
#include <opcua_trace.h>
#include <opcua_memory.h>
#include <opcua_base64.h>
#include "oauth2api.h"
#include "json.h"

static size_t ReadRequestCallback(char* buffer, size_t  size, size_t nitems, void* userp)
{
	size_t realsize = size * nitems;
	OpcUa_ByteString* pBuffer = (OpcUa_ByteString*)userp;

	if (pBuffer->Length < 0)
	{
		pBuffer->Length = 0;
	}

	if (pBuffer->Length < (OpcUa_Int32)realsize)
	{
		realsize = pBuffer->Length;
	}

	if (realsize > 0)
	{
		memcpy(buffer, pBuffer->Data, realsize);

		pBuffer->Data = pBuffer->Data + realsize;
		pBuffer->Length -= realsize;
	}

	return realsize;
}

static size_t WriteResponseCallback(void* contents, size_t size, size_t nitems, void* userp)
{
	size_t realsize = size * nitems;
	OpcUa_ByteString* pBuffer = (OpcUa_ByteString*)userp;

	if (pBuffer->Length < 0)
	{
		pBuffer->Length = 0;
	}

	pBuffer->Data = (OpcUa_Byte*)OpcUa_ReAlloc(pBuffer->Data, pBuffer->Length + realsize + 1);

	if (pBuffer->Data == NULL)
	{
		return 0;
	}

	memcpy(pBuffer->Data + pBuffer->Length, contents, realsize);
	pBuffer->Length += realsize;
	pBuffer->Data[pBuffer->Length] = 0;

	return realsize;
}

void OAuth2Initialize()
{
	curl_global_init(CURL_GLOBAL_ALL);
}

void OAuth2Cleanup()
{
	curl_global_cleanup();
}

static OpcUa_StatusCode HttpPost(
	const OpcUa_CharA* a_pUrl,
	const OpcUa_CharA* a_pBody,
	const OpcUa_CharA* a_pContentType,
	const OpcUa_CharA* a_pAccessCode,
	OpcUa_StringA* a_ppResponse)
{
	CURL* pContext = OpcUa_Null;
	CURLcode result = 0;
	OpcUa_ByteString input;
	OpcUa_ByteString output;
	struct curl_slist* pHeaders = NULL;
	char szHeader[4096];

OpcUa_InitializeStatus(OpcUa_Module_Client, "HttpPost");

	OpcUa_GotoErrorIfArgumentNull(a_pUrl);
	OpcUa_GotoErrorIfArgumentNull(a_pBody);
	OpcUa_GotoErrorIfArgumentNull(a_ppResponse);

	OpcUa_ByteString_Initialize(&input);
	OpcUa_ByteString_Initialize(&output);

	if (a_pContentType != NULL && *a_pContentType != 0)
	{
		szHeader[0] = 0;
		strcpy(szHeader, "Content-Type: ");
		strcat(szHeader, a_pContentType);
		pHeaders = curl_slist_append(pHeaders, szHeader);
	}

	if (a_pAccessCode != NULL && *a_pAccessCode != 0)
	{
		szHeader[0] = 0;
		strcpy(szHeader, "Authorization: Bearer ");
		strcat(szHeader, a_pAccessCode);
		pHeaders = curl_slist_append(pHeaders, szHeader);
	}
	
	*a_ppResponse = OpcUa_Null;

	input.Data = (OpcUa_Byte*)a_pBody;
	input.Length = strlen(a_pBody);
	
	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "HttpPost: Posting to URL: %s\n", a_pUrl);

	pContext = curl_easy_init();
	OpcUa_GotoErrorIfNull(pContext, OpcUa_BadUnexpectedError);

	curl_easy_setopt(pContext, CURLOPT_URL, a_pUrl);
	curl_easy_setopt(pContext, CURLOPT_POST, 1);
	curl_easy_setopt(pContext, CURLOPT_POSTFIELDSIZE, input.Length);
	curl_easy_setopt(pContext, CURLOPT_HTTPHEADER, pHeaders);
	curl_easy_setopt(pContext, CURLOPT_READFUNCTION, ReadRequestCallback);
	curl_easy_setopt(pContext, CURLOPT_READDATA, (void*)&input);
	curl_easy_setopt(pContext, CURLOPT_WRITEFUNCTION, WriteResponseCallback);
	curl_easy_setopt(pContext, CURLOPT_WRITEDATA, (void*)&output);
	curl_easy_setopt(pContext, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	/* disable SSL certificate validation for now */
	curl_easy_setopt(pContext, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(pContext, CURLOPT_SSL_VERIFYHOST, 0L);

	result = curl_easy_perform(pContext);

	if (result != CURLE_OK)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "HttpPost: HTTP Failed: %s!\n", curl_easy_strerror(result));
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
	}

	*a_ppResponse = (OpcUa_CharA*)output.Data;
	OpcUa_ByteString_Initialize(&output);

	curl_slist_free_all(pHeaders);
	curl_easy_cleanup(pContext);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pHeaders != OpcUa_Null)
	{
		curl_slist_free_all(pHeaders);
	}

	if (pContext != OpcUa_Null)
	{
		curl_easy_cleanup(pContext);
	}

	OpcUa_ByteString_Clear(&output);

OpcUa_FinishErrorHandling;
}

void OAuth2Request_Initialize(OAuth2Request* a_pRequest)
{
	if (a_pRequest != NULL)
	{
		OpcUa_MemSet(a_pRequest, 0, sizeof(OAuth2Request));
	}
}

void OAuth2Request_Clear(OAuth2Request* a_pRequest)
{
	if (a_pRequest != NULL)
	{
		OpcUa_String_Clear(&a_pRequest->AuthorizationServerUrl);
		OpcUa_String_Clear(&a_pRequest->ClientId);
		OpcUa_String_Clear(&a_pRequest->ClientSecret);
		OpcUa_String_Clear(&a_pRequest->Resource);
		OpcUa_String_Clear(&a_pRequest->Scope);
	}
}

void OAuth2Response_Initialize(OAuth2Response* a_pResponse)
{
	if (a_pResponse != NULL)
	{
		OpcUa_MemSet(a_pResponse, 0, sizeof(OAuth2Response));
	}
}

void OAuth2Response_Clear(OAuth2Response* a_pResponse)
{
	if (a_pResponse != NULL)
	{
		OpcUa_String_Clear(&a_pResponse->AccessToken);
		OpcUa_String_Clear(&a_pResponse->RefreshToken);
		OpcUa_String_Clear(&a_pResponse->ErrorText);
	}
}

#define MAX_URL_SIZE 4096

OpcUa_StatusCode OAuth2RequestTokenWithClientCredentials(OAuth2Request* a_pRequest, OAuth2Response* a_pResponse)
{
	OpcUa_CharA szUrl[MAX_URL_SIZE];
	OpcUa_CharA szInput[MAX_URL_SIZE];
	OpcUa_StringA szResponse = OpcUa_Null;
	json_object* pRoot = OpcUa_Null;
	json_object* pTarget = OpcUa_Null;
	OpcUa_CharA* pEscapedText = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Client, "OAuth2RequestTokenWithClientCredentials");

	OpcUa_GotoErrorIfArgumentNull(a_pRequest);
	OpcUa_GotoErrorIfArgumentNull(a_pResponse);

	szUrl[0] = 0;
	strcat_s(szUrl, MAX_URL_SIZE, OpcUa_String_GetRawString(&a_pRequest->AuthorizationServerUrl));

	CURL* pContext = curl_easy_init();

	szInput[0] = 0;
	strcat_s(szInput, MAX_URL_SIZE, "grant_type=client_credentials&client_id=");
	pEscapedText = curl_easy_escape(pContext, OpcUa_String_GetRawString(&a_pRequest->ClientId), 0);
	strcat_s(szInput, MAX_URL_SIZE, pEscapedText);
	curl_free(pEscapedText);

	strcat_s(szInput, MAX_URL_SIZE, "&client_secret=");
	pEscapedText = curl_easy_escape(pContext, OpcUa_String_GetRawString(&a_pRequest->ClientSecret), 0);
	strcat_s(szInput, MAX_URL_SIZE, pEscapedText);
	curl_free(pEscapedText);

	strcat_s(szInput, MAX_URL_SIZE, "&scope=");
	pEscapedText = curl_easy_escape(pContext, OpcUa_String_GetRawString(&a_pRequest->Scope), 0);
	strcat_s(szInput, MAX_URL_SIZE, pEscapedText);
	curl_free(pEscapedText);

	strcat_s(szInput, MAX_URL_SIZE, "&resource=");
	pEscapedText = curl_easy_escape(pContext, OpcUa_String_GetRawString(&a_pRequest->Resource), 0);
	strcat_s(szInput, MAX_URL_SIZE, pEscapedText);
	curl_free(pEscapedText);

	curl_easy_cleanup(pContext);
	
	uStatus = HttpPost(szUrl, szInput, NULL, NULL, &szResponse);
	OpcUa_GotoErrorIfBad(uStatus);

	pRoot = json_tokener_parse(szResponse);

	if (pRoot == NULL)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2RequestTokenWithClientCredentials: JSON Parse Failed: %s!\n", szResponse);
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
	}

	json_object_object_get_ex(pRoot, "error", &pTarget);

	if (pTarget != NULL)
	{
		OpcUa_String_AttachCopy(&a_pResponse->ErrorText, json_object_get_string(pTarget));
		a_pResponse->ErrorOccured = OpcUa_True;
	}
	else
	{
		json_object_object_get_ex(pRoot, "access_token", &pTarget);
		OpcUa_String_AttachCopy(&a_pResponse->AccessToken, json_object_get_string(pTarget));

		if (a_pResponse->AccessToken.uLength <= 0)
		{
			OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OAuth2RequestTokenWithClientCredentials: No Access Token Returned: %s!\n", szResponse);
			OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
		}

		json_object_object_get_ex(pRoot, "refresh_token", &pTarget);
		OpcUa_String_AttachCopy(&a_pResponse->RefreshToken, json_object_get_string(pTarget));
		a_pResponse->ErrorOccured = OpcUa_False;
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OAuth2RequestTokenWithClientCredentials: Response %s\n", json_object_to_json_string(pRoot));
	json_object_put(pRoot);
	OpcUa_Free(szResponse);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	OpcUa_Free(szResponse);

OpcUa_FinishErrorHandling;
}

void GetSecurityKeysRequest_Initialize(GetSecurityKeysRequest* a_pRequest)
{
	if (a_pRequest != NULL)
	{
		OpcUa_MemSet(a_pRequest, 0, sizeof(GetSecurityKeysRequest));
	}
}

void GetSecurityKeysRequest_Clear(GetSecurityKeysRequest* a_pRequest)
{
	if (a_pRequest != NULL)
	{
		OpcUa_String_Clear(&a_pRequest->ServerUrl);
		OpcUa_String_Clear(&a_pRequest->AccessToken);
		OpcUa_String_Clear(&a_pRequest->GroupId);
		OpcUa_MemSet(a_pRequest, 0, sizeof(GetSecurityKeysRequest));
	}
}

void GetSecurityKeysResponse_Initialize(GetSecurityKeysResponse* a_pResponse)
{
	if (a_pResponse != NULL)
	{
		OpcUa_MemSet(a_pResponse, 0, sizeof(GetSecurityKeysResponse));
	}
}

void GetSecurityKeysResponse_Clear(GetSecurityKeysResponse* a_pResponse)
{
	if (a_pResponse != NULL)
	{
		OpcUa_String_Clear(&a_pResponse->SecurityPolicyUri);
		OpcUa_String_Clear(&a_pResponse->ErrorText);
		OpcUa_ByteString_Clear(&a_pResponse->CurrentKey);

		for (OpcUa_UInt32 ii = 0; ii < a_pResponse->NoOfNextKeys; ii++)
		{
			OpcUa_ByteString_Clear(&a_pResponse->NextKeys[ii]);
		}

		OpcUa_Free(a_pResponse->NextKeys);
		OpcUa_MemSet(a_pResponse, 0, sizeof(GetSecurityKeysResponse));
	}
}

OpcUa_StatusCode HttpsGetSecurityKeysWithAccessToken(GetSecurityKeysRequest* a_pRequest, GetSecurityKeysResponse* a_pResponse)
{
	char* szResponse = OpcUa_Null;
	json_object* pRoot = OpcUa_Null;
	json_object* pField = OpcUa_Null;
	json_object* pBody = OpcUa_Null;
	json_object* pList = OpcUa_Null;
	json_object* pItem = OpcUa_Null;
	json_object* pArgs = OpcUa_Null;
	json_object* pValue = OpcUa_Null;

	OpcUa_InitializeStatus(OpcUa_Module_Client, "HttpsGetSecurityKeysWithAccessToken");

	OpcUa_GotoErrorIfArgumentNull(a_pRequest);
	OpcUa_GotoErrorIfArgumentNull(a_pResponse);

	pRoot = json_object_new_object();
	json_object_object_add_ex(pRoot, "ServiceId", json_object_new_int(710), 0);

	pBody = json_object_new_object();
	pList = json_object_new_array();
	pItem = json_object_new_object();

	json_object_object_add_ex(pItem, "ObjectId", json_object_new_string("i=14443"), 0);
	json_object_object_add_ex(pItem, "MethodId", json_object_new_string("i=15215"), 0);

	pArgs = json_object_new_array();
	pField = json_object_new_object();
	json_object_object_add_ex(pField, "Type", json_object_new_int(12), 0);
	json_object_object_add_ex(pField, "Body", json_object_new_string(OpcUa_String_GetRawString(&a_pRequest->GroupId)), 0);
	json_object_array_add(pArgs, pField);

	pField = json_object_new_object();
	json_object_object_add_ex(pField, "Type", json_object_new_int(7), 0);
	json_object_object_add_ex(pField, "Body", json_object_new_int(3), 0);
	json_object_array_add(pArgs, pField);

	json_object_object_add_ex(pItem, "InputArguments", pArgs, 0);
	json_object_array_add(pList, pItem);

	json_object_object_add_ex(pBody, "MethodsToCall", pList, 0);
	json_object_object_add_ex(pRoot, "Body", pBody, 0);

	uStatus = HttpPost(
		OpcUa_String_GetRawString(&a_pRequest->ServerUrl),
		json_object_to_json_string_ext(pRoot, 0),
		"application/opcua+uajson",
		OpcUa_String_GetRawString(&a_pRequest->AccessToken),
		&szResponse);

	OpcUa_GotoErrorIfBad(uStatus);

	json_object_put(pRoot);
	pRoot = json_tokener_parse(szResponse);

	if (pRoot == NULL)
	{
		OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "HttpsGetSecurityKeysWithAccessToken: JSON Parse Response Failed: %s!\n", szResponse);
		OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
	}

	json_object_object_get_ex(pRoot, "Body", &pBody);

	if (pBody != NULL)
	{
		json_object_object_get_ex(pBody, "ResponseHeader", &pItem);

		if (pItem != NULL)
		{
			json_object_object_get_ex(pItem, "ServiceResult", &pValue);

			if (pValue != NULL)
			{
				OpcUa_UInt32 code = (OpcUa_UInt32)json_object_get_int64(pValue);

				if ((code & 0x80000000) != 0)
				{
					OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "HttpsGetSecurityKeysWithAccessToken: Service Call Failed: 0x%X!\n", code);
					OpcUa_GotoErrorWithStatus(OpcUa_BadCommunicationError);
				}
			}
		}

		json_object_object_get_ex(pBody, "Results", &pList);

		if (pList != NULL)
		{
			pItem = json_object_array_get_idx(pList, 0);

			if (pItem != NULL)
			{
				json_object_object_get_ex(pItem, "StatusCode", &pField);

				if (pField != NULL)
				{
					a_pResponse->ErrorOccured = OpcUa_True;
					OpcUa_String_AttachCopy(&a_pResponse->ErrorText, json_object_get_string(pField));
				}
				else
				{
					json_object_object_get_ex(pItem, "OutputArguments", &pList);

					pItem = json_object_array_get_idx(pList, 0);

					if (pItem != NULL)
					{
						json_object_object_get_ex(pItem, "Body", &pValue);
						OpcUa_String_AttachCopy(&a_pResponse->SecurityPolicyUri, json_object_get_string(pValue));
					}

					pItem = json_object_array_get_idx(pList, 1);
					
					if (pItem != NULL)
					{
						json_object_object_get_ex(pItem, "Body", &pValue);
						a_pResponse->CurrentTokenId = (OpcUa_UInt32)json_object_get_int(pValue);
					}

					pItem = json_object_array_get_idx(pList, 2);

					if (pItem != NULL)
					{
						OpcUa_ByteString data;
						OpcUa_ByteString_Initialize(&data);

						json_object_object_get_ex(pItem, "Body", &pValue);

						uStatus = OpcUa_Base64_Decode(json_object_get_string(pValue), &data.Length, &data.Data);
						OpcUa_GotoErrorIfBad(uStatus);

						a_pResponse->CurrentKey = data;
					}

					pItem = json_object_array_get_idx(pList, 3);

					if (pItem != NULL)
					{
						int length = 0;
						int ii = 0;
						OpcUa_ByteString* pArray = NULL;

						json_object_object_get_ex(pItem, "Body", &pValue);

						if (pValue != NULL)
						{
							length = json_object_array_length(pValue);

							if (length > 0)
							{
								a_pResponse->NextKeys = pArray = (OpcUa_ByteString*)OpcUa_Alloc(length*sizeof(OpcUa_ByteString));
								OpcUa_GotoErrorIfAllocFailed(pArray);
								OpcUa_MemSet(pArray, 0, length * sizeof(OpcUa_ByteString));
								a_pResponse->NoOfNextKeys = length;

								for (ii = 0; ii < length; ii++)
								{
									OpcUa_ByteString data;
									OpcUa_ByteString_Initialize(&data);

									pItem = json_object_array_get_idx(pValue, ii);

									uStatus = OpcUa_Base64_Decode(json_object_get_string(pItem), &data.Length, &data.Data);
									OpcUa_GotoErrorIfBad(uStatus);

									pArray[ii] = data;
								}
							}
						}
					}

					pItem = json_object_array_get_idx(pList, 4);

					if (pItem != NULL)
					{
						json_object_object_get_ex(pItem, "Body", &pValue);
						a_pResponse->TimeToNextKey = (OpcUa_UInt32)json_object_get_int(pValue);
					}

					pItem = json_object_array_get_idx(pList, 5);

					if (pItem != NULL)
					{
						json_object_object_get_ex(pItem, "Body", &pValue);
						a_pResponse->KeyLifetime = (OpcUa_UInt32)json_object_get_int(pValue);
					}
				}
			}
		}
	}

	json_object_put(pRoot);
	OpcUa_Free(szResponse);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	json_object_put(pRoot);
	OpcUa_Free(szResponse);
	GetSecurityKeysResponse_Clear(a_pResponse);

OpcUa_FinishErrorHandling;
}