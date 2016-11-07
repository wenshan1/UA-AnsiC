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

/* ProxyStub */
#include <opcua_clientproxy.h>
#include <opcua_memory.h>
#include <opcua_core.h>
#include <opcua_trace.h>
#include <opcua_string.h>
#include <opcua_extensionobject.h>

void PrintInteger(OpcUa_CharA* pBuffer, OpcUa_Int64 nValue)
{
	char temp[256];
	temp[0] = 0;
	sprintf(temp, "%I64d", nValue);
	strcat(pBuffer, temp);
}

void PrintUInteger(OpcUa_CharA* pBuffer, OpcUa_UInt64 nValue)
{
	char temp[256];
	temp[0] = 0;
	sprintf(temp, "%I64u", nValue);
	strcat(pBuffer, temp);
}

void PrintDouble(OpcUa_CharA* pBuffer, OpcUa_Double nValue)
{
	char temp[256];
	temp[0] = 0;
	sprintf(temp, "%f", nValue);
	strcat(pBuffer, temp);
}

void PrintCharA(OpcUa_CharA* pBuffer, OpcUa_CharA* pValue)
{
	if (pValue != NULL)
	{
		strcat(pBuffer, pValue);
	}
}

void PrintString(OpcUa_CharA* pBuffer, OpcUa_String* pValue)
{
	if (pValue != NULL)
	{
		strcat(pBuffer, OpcUa_String_GetRawString(pValue));
	}
}
void PrintDateTime(OpcUa_CharA* pBuffer, OpcUa_DateTime* pValue)
{
	if (pValue != NULL)
	{
		SYSTEMTIME st;
		FileTimeToSystemTime((FILETIME*)pValue, &st);

		char temp[256];
		temp[0] = 0;
		sprintf(temp, "%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		strcat(pBuffer, temp);
	}
}

void PrintGuid(OpcUa_CharA* pBuffer, OpcUa_Guid* pValue)
{
	if (pValue != NULL)
	{
		char temp[256];
		temp[0] = 0;

		sprintf(temp, "%08x-", pValue->Data1);
		strcat(pBuffer, temp);
		sprintf(temp, "%04x-", pValue->Data2);
		strcat(pBuffer, temp);
		sprintf(temp, "%04x-", pValue->Data3);
		strcat(pBuffer, temp);

		for (int ii = 0; ii < 8; ii++)
		{
			sprintf(temp, "%02x", pValue->Data4[ii]);
			strcat(pBuffer, temp);
		}
	}
}

void PrintByteString(OpcUa_CharA* pBuffer, OpcUa_ByteString* pValue)
{
	if (pValue != NULL)
	{
		char temp[256];
		temp[0] = 0;

		for (int ii = 0; ii < pValue->Length; ii++)
		{
			sprintf(temp, "%02X", pValue->Data[ii]);
			strcat(pBuffer, temp);
		}
	}
}

void PrintStatusCode(OpcUa_CharA* pBuffer, OpcUa_StatusCode uStatus)
{
	OpcUa_StringA sError = OpcUa_Null;

	switch (uStatus)
	{
		case OpcUa_Good: { sError = "Good"; break; }
		case OpcUa_Bad: { sError = "Bad"; break; }
		case OpcUa_BadTimeout: { sError = "BadTimeout"; break; }
		case OpcUa_BadCommunicationError: { sError = "BadCommunicationError"; break; }
		case OpcUa_BadConnectionClosed: { sError = "BadConnectionClosed"; break; }
		case OpcUa_BadCertificateInvalid: { sError = "BadCertificateInvalid"; break; }
		case OpcUa_BadCertificateTimeInvalid: { sError = "BadCertificateTimeInvalid"; break; }
		case OpcUa_BadCertificateRevoked: { sError = "BadCertificateRevoked"; break; }
		case OpcUa_BadCertificateUntrusted: { sError = "BadCertificateUntrusted"; break; }
		case OpcUa_BadCertificateIssuerRevocationUnknown: { sError = "BadCertificateIssuerRevocationUnknown"; break; }
		case OpcUa_BadConnectionRejected: { sError = "BadConnectionRejected"; break; }
		case OpcUa_BadFileNotFound: { sError = "BadFileNotFound"; break; }
		case OpcUa_BadSecurityConfig: { sError = "BadSecurityConfig"; break; }
		case OpcUa_BadInternalError: { sError = "BadInternalError"; break; }
		case OpcUa_BadHostUnknown: { sError = "BadHostUnknown"; break; }
		case OpcUa_BadNodeIdUnknown: { sError = "BadNodeIdUnknown"; break; }
		case OpcUa_BadNodeIdInvalid: { sError = "BadNodeIdInvalid"; break; }
		case OpcUa_BadUserAccessDenied: { sError = "BadUserAccessDenied"; break; }
		case OpcUa_BadNotFound: { sError = "BadNotFound"; break; }

		default:
		{
			PrintCharA(pBuffer, "0x");
			PrintUInteger(pBuffer, (OpcUa_UInt64)uStatus);
			return;
		}
	}

	strcat(pBuffer, sError);
}

void PrintNodeId(OpcUa_CharA* pBuffer, OpcUa_NodeId* pNodeId)
{
	char temp[2048];
	temp[0] = 0;

	if (pNodeId != NULL)
	{
		if (pNodeId->NamespaceIndex > 0)
		{
			PrintCharA(temp, "ns=");
			PrintUInteger(temp, pNodeId->NamespaceIndex);
			PrintCharA(temp, ";");
		}

		switch (pNodeId->IdentifierType)
		{
			case OpcUa_IdType_Numeric:
			{
				PrintCharA(temp, "i=");
				PrintUInteger(temp, pNodeId->Identifier.Numeric);
				break;
			}

			case OpcUa_IdType_String:
			{
				PrintCharA(temp, "s=");
				PrintString(temp, &pNodeId->Identifier.String);
				break;
			}

			case OpcUa_IdType_Opaque:
			{
				PrintCharA(temp, "b=");
				PrintByteString(temp, &pNodeId->Identifier.ByteString);
				break;
			}

			case OpcUa_IdType_Guid:
			{
				PrintCharA(temp, "g=");
				PrintGuid(temp, pNodeId->Identifier.Guid);
				break;
			}

			default:
			{
				break;
			}
		}
	}

	strcat(pBuffer, temp);
}

void PrintVariant(OpcUa_CharA* pBuffer, OpcUa_Variant* pValue)
{
	if (pValue == NULL)
	{
		PrintCharA(pBuffer, "(null)");
		return;
	}

	if (pValue->ArrayType == OpcUa_VariantArrayType_Array)
	{
		for (int ii = 0; ii < pValue->Value.Array.Length; ii++)
		{
			OpcUa_Variant element;
			OpcUa_Variant_Initialize(&element);
			element.Datatype = pValue->Datatype;
			element.Value.ByteString = pValue->Value.Array.Value.ByteStringArray[ii];

			if (ii > 0)
			{
				PrintCharA(pBuffer, "|");
			}

			PrintVariant(pBuffer, &element);
		}

		return;
	}

	switch (pValue->Datatype)
	{
		case OpcUaType_Boolean:
		{
			if (pValue->Value.Boolean)
			{
				PrintCharA(pBuffer, "true");
			}
			else
			{
				PrintCharA(pBuffer, "false");
			}

			break;
		}

		case OpcUaType_SByte:
		case OpcUaType_Int16:
		case OpcUaType_Int32:
		case OpcUaType_Int64:
		{
			PrintInteger(pBuffer, pValue->Value.Int64);
			break;
		}

		case OpcUaType_Byte:
		case OpcUaType_UInt16:
		case OpcUaType_UInt32:
		case OpcUaType_UInt64:
		{
			PrintUInteger(pBuffer, pValue->Value.UInt64);
			break;
		}

		case OpcUaType_Float:
		{
			PrintDouble(pBuffer, (OpcUa_Double)pValue->Value.Float);
			break;
		}

		case OpcUaType_Double:
		{
			PrintDouble(pBuffer, pValue->Value.Double);
			break;
		}

		case OpcUaType_String:
		{
			PrintString(pBuffer, &pValue->Value.String);
			break;
		}

		case OpcUaType_ByteString:
		{
			PrintByteString(pBuffer, &pValue->Value.ByteString);
			break;
		}

		case OpcUaType_Guid:
		{
			PrintGuid(pBuffer, pValue->Value.Guid);
			break;
		}

		case OpcUaType_DateTime:
		{
			PrintDateTime(pBuffer, &pValue->Value.DateTime);
			break;
		}

		case OpcUaType_StatusCode:
		{
			PrintStatusCode(pBuffer, pValue->Value.StatusCode);
			break;
		}

		case OpcUaType_NodeId:
		{
			PrintNodeId(pBuffer, pValue->Value.NodeId);
			break;
		}

		case OpcUaType_ExtensionObject:
		{
			OpcUa_ServerStatusDataType* pServerStatus = OPCUA_EXTENSIONOBJECT_GET_ENCODEABLE(ServerStatusDataType, pValue->Value.ExtensionObject);

			if (pServerStatus != NULL)
			{
				PrintString(pBuffer, &pServerStatus->BuildInfo.ProductName);
				PrintCharA(pBuffer, ": ");
				PrintDateTime(pBuffer, &pServerStatus->CurrentTime);
			}

			break;
		}
		
		default:
		{
			break;
		}
	}
}

void PrintReadResult(OpcUa_ReadValueId* pItem, OpcUa_DataValue* pResult)
{
	char temp[2048];
	temp[0] = 0;

	PrintNodeId(temp, &pItem->NodeId);
	PrintCharA(temp, "\r\n   ");

	if (OpcUa_IsBad(pResult->StatusCode))
	{
		PrintDateTime(temp, &pResult->ServerTimestamp);
		PrintCharA(temp, ": ");
		PrintStatusCode(temp, pResult->StatusCode);
	}
	else
	{
		PrintDateTime(temp, &pResult->SourceTimestamp);
		PrintCharA(temp, ": ");
		PrintVariant(temp, &pResult->Value);
	}

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
}

void PrintWriteResult(OpcUa_WriteValue* pItem, OpcUa_StatusCode* pResult)
{
	char temp[2048];
	temp[0] = 0;

	PrintNodeId(temp, &pItem->NodeId);
	PrintCharA(temp, "\r\n   ");
	PrintStatusCode(temp, *pResult);
	PrintCharA(temp, ": ");
	PrintVariant(temp, &pItem->Value.Value);

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
}

void PrintCallResult(OpcUa_CallMethodRequest* pItem, OpcUa_CallMethodResult* pResult)
{
	char temp[4096];
	temp[0] = 0;

	PrintCharA(temp, "ObjectId: ");
	PrintNodeId(temp, &pItem->ObjectId);
	PrintCharA(temp, "\r\n");
	PrintCharA(temp, "MethodId: ");
	PrintNodeId(temp, &pItem->MethodId);
	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);

	for (int ii = 0; ii < pItem->NoOfInputArguments; ii++)
	{
		temp[0] = 0;
		PrintCharA(temp, "In[");
		PrintInteger(temp, ii);
		PrintCharA(temp, "]: ");
		PrintVariant(temp, &pItem->InputArguments[ii]);
		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
	}

	temp[0] = 0;
	PrintCharA(temp, "Result: ");
	PrintStatusCode(temp, pResult->StatusCode);
	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);

	for (int ii = 0; ii < pResult->NoOfOutputArguments; ii++)
	{
		temp[0] = 0;
		PrintCharA(temp, "Out[");
		PrintInteger(temp, ii);
		PrintCharA(temp, "]: ");
		PrintVariant(temp, &pResult->OutputArguments[ii]);
		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
	}
}

void PrintCreateMonitoredItemResult(OpcUa_MonitoredItemCreateRequest* pItem, OpcUa_MonitoredItemCreateResult* pResult)
{
	char temp[2048];
	temp[0] = 0;

	PrintCharA(temp, "NodeId: ");
	PrintNodeId(temp, &pItem->ItemToMonitor.NodeId);
	PrintCharA(temp, "\r\n");
	PrintCharA(temp, "Result: ");
	PrintStatusCode(temp, pResult->StatusCode);

	OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
}

void PrintDataChange(OpcUa_MonitoredItemNotification* pItem)
{
	if (pItem != NULL)
	{
		char temp[2048];
		temp[0] = 0;

		PrintUInteger(temp, pItem->ClientHandle);
		PrintCharA(temp, ": [");
		PrintStatusCode(temp, pItem->Value.StatusCode);
		PrintCharA(temp, "] ");
		PrintVariant(temp, &pItem->Value.Value);

		OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM, "%s\r\n", temp);
	}
}