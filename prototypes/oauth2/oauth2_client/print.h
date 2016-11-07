#pragma once

#include <opcua_clientproxy.h>

void PrintInteger(OpcUa_CharA* pBuffer, OpcUa_Int64 nValue);
void PrintUInteger(OpcUa_CharA* pBuffer, OpcUa_UInt64 nValue);
void PrintDouble(OpcUa_CharA* pBuffer, OpcUa_Double nValue);
void PrintCharA(OpcUa_CharA* pBuffer, OpcUa_CharA* pValue);
void PrintString(OpcUa_CharA* pBuffer, OpcUa_String* pValue);
void PrintDateTime(OpcUa_CharA* pBuffer, OpcUa_DateTime* pValue);
void PrintGuid(OpcUa_CharA* pBuffer, OpcUa_Guid* pValue);
void PrintByteString(OpcUa_CharA* pBuffer, OpcUa_ByteString* pValue);
void PrintStatusCode(OpcUa_CharA* pBuffer, OpcUa_StatusCode uStatus);
void PrintNodeId(OpcUa_CharA* pBuffer, OpcUa_NodeId* pNodeId);
void PrintVariant(OpcUa_CharA* pBuffer, OpcUa_Variant* pValue);
void PrintReadResult(OpcUa_ReadValueId* pItem, OpcUa_DataValue* pResult);
void PrintWriteResult(OpcUa_WriteValue* pItem, OpcUa_StatusCode* pResult);
void PrintCallResult(OpcUa_CallMethodRequest* pItem, OpcUa_CallMethodResult* pResult);
void PrintCreateMonitoredItemResult(OpcUa_MonitoredItemCreateRequest* pItem, OpcUa_MonitoredItemCreateResult* pResult);
void PrintDataChange(OpcUa_MonitoredItemNotification* pItem);