#ifndef OPCUA_AMQPMESSAGE_H
#define OPCUA_AMQPMESSAGE_H

#include "azure_uamqp_c/message.h"

#define URI_SCHEME_AMQPS "amqps"
#define URI_SCHEME_WSS   "wss"

typedef struct _OpcUa_AmqpMessageHeader
{
    char* MessageId;
    char* SubjectId;
    char* PublisherId;
    char* ContentType;
    char* DataSetWriterId;
    unsigned int SequenceNumber;
    char* DataSetClassId;
    char* MetaDataNodeName;
}
OpcUa_AmqpMessageHeader;

void OpcUa_AmqpMessageHeader_Initialize(OpcUa_AmqpMessageHeader* pHeader);
void OpcUa_AmqpMessageHeader_Clear(OpcUa_AmqpMessageHeader* pHeader);
int OpcUa_Message_SetHeader(MESSAGE_HANDLE message, OpcUa_AmqpMessageHeader* pHeader);
int OpcUa_Message_SetMessageId(MESSAGE_HANDLE message, const char* messageId, uint32_t sequenceNumber);
int OpcUa_Message_GetHeader(MESSAGE_HANDLE message, OpcUa_AmqpMessageHeader* pHeader);

typedef struct _OpcUa_AmqpMessageBody
{
    char* EventId;
    char* SourceNode;
    char* SourceName;
    char* EventType;
    char* Time;
    char* ReceiveTime;
    char* Message;
    uint16_t Severity;
}
OpcUa_AmqpMessageBody;

void OpcUa_AmqpMessageBody_Initialize(OpcUa_AmqpMessageBody* pBody);
void OpcUa_AmqpMessageBody_Clear(OpcUa_AmqpMessageBody* pBody);
int OpcUa_Message_GetBody(MESSAGE_HANDLE message, OpcUa_AmqpMessageBody* pBody);
int OpcUa_Message_SetBody(MESSAGE_HANDLE message, OpcUa_AmqpMessageBody* pBody);

typedef struct _OpcUa_ApplicationSettings
{
    char* UrlScheme;
    char* BrokerAddress;
    uint16_t Port;
    char* Username;
    char* Password;
    char* AmqpNodeName;
    int Iterations;
}
OpcUa_ApplicationSettings;

void OpcUa_ApplicationSettings_Initialize(OpcUa_ApplicationSettings* a_pSettings);
void OpcUa_ApplicationSettings_Clear(OpcUa_ApplicationSettings* a_pSettings);
int OpcUa_GetApplicationSettings(int argc, char ** argv, OpcUa_ApplicationSettings* a_pSettings);

#endif // OPCUA_AMQPMESSAGE_H


