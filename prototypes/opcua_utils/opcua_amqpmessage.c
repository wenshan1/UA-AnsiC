// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <json.h>
#include "opcua_amqpmessage.h"
#include "urldecode.h"

char* OpcUa_StrnDup(const char* pSrc, int length);
#define OpcUa_Alloc(x) malloc(x)
#define OpcUa_Free(x) if (x != NULL) { free(x); x = NULL; }
#define OpcUa_StrDup(x) OpcUa_StrnDup(x, strlen(x))
#define OpcUa_Alloc(x) malloc(x)
#define OpcUa_Free(x) if (x != NULL) { free(x); x = NULL; }
#define OpcUa_StrDup(x) OpcUa_StrnDup(x, strlen(x))

#define OPCUA_PROPERTY_PUBLISHER_ID "ua-pubid"
#define OPCUA_PROPERTY_DATASET_CLASS_ID "ua-clsid"
#define OPCUA_PROPERTY_METADATA_NODE_NAME "ua-mdata"

void OpcUa_AmqpMessageHeader_Initialize(OpcUa_AmqpMessageHeader* pHeader)
{
    memset(pHeader, 0, sizeof(OpcUa_AmqpMessageHeader));
}

void OpcUa_AmqpMessageHeader_Clear(OpcUa_AmqpMessageHeader* pHeader)
{
    if (pHeader != NULL)
    {
        OpcUa_Free(pHeader->MessageId);
        OpcUa_Free(pHeader->SubjectId);
        OpcUa_Free(pHeader->ContentType);
        OpcUa_Free(pHeader->PublisherId);
        OpcUa_Free(pHeader->DataSetWriterId);
        OpcUa_Free(pHeader->DataSetClassId);
        OpcUa_Free(pHeader->MetaDataNodeName);

        memset(pHeader, 0, sizeof(OpcUa_AmqpMessageHeader));
    }
}

int OpcUa_Message_SetHeader(MESSAGE_HANDLE message, OpcUa_AmqpMessageHeader* pHeader)
{
    int result = 0;
    PROPERTIES_HANDLE properties = NULL;
    AMQP_VALUE application_properties = NULL;

    if (message_get_properties(message, &properties) != 0)
    {
        result = __LINE__; goto error;
    }

    if (properties == NULL)
    {
        properties = properties_create();

        if (properties == NULL)
        {
            result = __LINE__; goto error;
        }
    }

    if (pHeader->MessageId != NULL)
    {
        AMQP_VALUE value = amqpvalue_create_message_id_string(pHeader->MessageId);

        if (value == NULL)
        {
            result = __LINE__; goto error;
        }

        if (properties_set_message_id(properties, value) != 0)
        {
            amqpvalue_destroy(value);
            result = __LINE__; goto error;
        }

        amqpvalue_destroy(value);
    }

    if (pHeader->SubjectId != NULL)
    {
        if (properties_set_subject(properties, pHeader->SubjectId) != 0)
        {
            result = __LINE__; goto error;
        }
    }

    if (pHeader->ContentType != NULL)
    {
        if (properties_set_content_type(properties, pHeader->ContentType) != 0)
        {
            result = __LINE__; goto error;
        }
    }

    if (pHeader->DataSetWriterId != NULL)
    {
        if (properties_set_group_id(properties, pHeader->DataSetWriterId) != 0)
        {
            result = __LINE__; goto error;
        }
    }

    if (pHeader->SequenceNumber > 0)
    {
        if (properties_set_group_sequence(properties, pHeader->SequenceNumber) != 0)
        {
            result = __LINE__; goto error;
        }
    }

    if (message_set_properties(message, properties) != 0)
    {
        result = __LINE__; goto error;
    }

    properties_destroy(properties);
    properties = NULL;

    if (pHeader->MetaDataNodeName != NULL || pHeader->DataSetClassId != NULL)
    {
        if (message_get_application_properties(message, &application_properties) != 0)
        {
            result = __LINE__; goto error;
        }

        if (application_properties == NULL)
        {
            application_properties = amqpvalue_create_map();

            if (application_properties == NULL)
            {
                result = __LINE__; goto error;
            }
        }

        if (pHeader->PublisherId != NULL)
        {
            AMQP_VALUE name = amqpvalue_create_string(OPCUA_PROPERTY_PUBLISHER_ID);

            if (name == NULL)
            {
                result = __LINE__; goto error;
            }

            AMQP_VALUE value = amqpvalue_create_string(pHeader->PublisherId);

            if (value == NULL)
            {
                amqpvalue_destroy(name);
                result = __LINE__; goto error;
            }

            if (amqpvalue_set_map_value(application_properties, name, value) != 0)
            {
                result = __LINE__; goto error;
            }

            amqpvalue_destroy(name);
            amqpvalue_destroy(value);
        }

        if (pHeader->DataSetClassId != NULL)
        {
            AMQP_VALUE name = amqpvalue_create_string(OPCUA_PROPERTY_DATASET_CLASS_ID);

            if (name == NULL)
            {
                result = __LINE__; goto error;
            }

            AMQP_VALUE value = amqpvalue_create_string(pHeader->DataSetClassId);

            if (value == NULL)
            {
                amqpvalue_destroy(name);
                result = __LINE__; goto error;
            }

            if (amqpvalue_set_map_value(application_properties, name, value) != 0)
            {
                result = __LINE__; goto error;
            }

            amqpvalue_destroy(name);
            amqpvalue_destroy(value);
        }

        if (pHeader->MetaDataNodeName != NULL)
        {
            AMQP_VALUE name = amqpvalue_create_string(OPCUA_PROPERTY_METADATA_NODE_NAME);

            if (name == NULL)
            {
                result = __LINE__; goto error;
            }

            AMQP_VALUE value = amqpvalue_create_string(pHeader->MetaDataNodeName);

            if (value == NULL)
            {
                amqpvalue_destroy(name);
                result = __LINE__; goto error;
            }

            if (amqpvalue_set_map_value(application_properties, name, value) != 0)
            {
                result = __LINE__; goto error;
            }

            amqpvalue_destroy(name);
            amqpvalue_destroy(value);
        }

        if (message_set_application_properties(message, application_properties) != 0)
        {
            result = __LINE__; goto error;
        }

        amqpvalue_destroy(application_properties);
        application_properties = NULL;
    }

    return 0;

error:

    if (properties != NULL)
    {
        properties_destroy(properties);
    }

    if (application_properties != NULL)
    {
        amqpvalue_destroy(application_properties);
    }

    return result;
}

int OpcUa_Message_SetMessageId(MESSAGE_HANDLE message, const char* messageId, uint32_t sequenceNumber)
{
    int result = 0;
    PROPERTIES_HANDLE properties = NULL;
    AMQP_VALUE application_properties = NULL;

    if (message_get_properties(message, &properties) != 0)
    {
        result = __LINE__; goto error;
    }

    if (properties == NULL)
    {
        properties = properties_create();

        if (properties == NULL)
        {
            result = __LINE__; goto error;
        }
    }

    if (messageId != NULL)
    {
        AMQP_VALUE value = amqpvalue_create_message_id_string(messageId);

        if (value == NULL)
        {
            result = __LINE__; goto error;
        }

        if (properties_set_message_id(properties, value) != 0)
        {
            amqpvalue_destroy(value);
            result = __LINE__; goto error;
        }

        amqpvalue_destroy(value);
    }

    if (sequenceNumber > 0)
    {
        if (properties_set_group_sequence(properties, sequenceNumber) != 0)
        {
            result = __LINE__; goto error;
        }
    }

    if (message_set_properties(message, properties) != 0)
    {
        result = __LINE__; goto error;
    }

    properties_destroy(properties);
    properties = NULL;

    return 0;

error:

    if (properties != NULL)
    {
        properties_destroy(properties);
    }

    if (application_properties != NULL)
    {
        amqpvalue_destroy(application_properties);
    }

    return result;
}

int OpcUa_Message_GetHeader(MESSAGE_HANDLE message, OpcUa_AmqpMessageHeader* pHeader)
{
    int result = 0;
    PROPERTIES_HANDLE properties = NULL;
    AMQP_VALUE application_properties = NULL;
    AMQP_VALUE value = NULL;
    const char* string = NULL;
    amqp_binary bytes = { 0, 0 };

    if (message_get_properties(message, &properties) != 0)
    {
        result = __LINE__; goto error;
    }

    if (properties == NULL)
    {
        result = __LINE__; goto error;
    }

    if (properties_get_message_id(properties, &value) == 0)
    {
        if (amqpvalue_get_string(value, &string) != 0)
        {
            result = __LINE__; goto error;
        }

        pHeader->MessageId = OpcUa_StrDup(string);
    }

    if (properties_get_subject(properties, &string) == 0)
    {
        pHeader->SubjectId = OpcUa_StrDup(string);
    }

    if (properties_get_content_type(properties, &string) == 0)
    {
        pHeader->ContentType = OpcUa_StrDup(string);
    }

    if (properties_get_group_id(properties, &string) == 0)
    {
        pHeader->DataSetWriterId = OpcUa_StrDup(string);

        if (properties_get_group_sequence(properties, &pHeader->SequenceNumber) != 0)
        {
            pHeader->SequenceNumber = 0;
        }
    }

    properties_destroy(properties);
    properties = NULL;

    if (message_get_application_properties(message, &application_properties) == 0)
    {
        AMQP_VALUE map = amqpvalue_get_inplace_described_value(application_properties);

        AMQP_VALUE name = amqpvalue_create_string(OPCUA_PROPERTY_PUBLISHER_ID);

        if (name == NULL)
        {
            result = __LINE__; goto error;
        }

        value = amqpvalue_get_map_value(map, name);

        if (value != NULL)
        {
            amqpvalue_destroy(name);

            if (amqpvalue_get_string(value, &string) != 0)
            {
                result = __LINE__; goto error;
            }

            pHeader->PublisherId = OpcUa_StrDup(string);
            amqpvalue_destroy(value);
        }
        
        name = amqpvalue_create_string(OPCUA_PROPERTY_DATASET_CLASS_ID);

        if (name == NULL)
        {
            result = __LINE__; goto error;
        }

        value = amqpvalue_get_map_value(map, name);

        if (value != NULL)
        {
            amqpvalue_destroy(name);

            if (amqpvalue_get_string(value, &string) != 0)
            {
                result = __LINE__; goto error;
            }

            pHeader->DataSetClassId = OpcUa_StrDup(string);
            amqpvalue_destroy(value);
        }
        
        name = amqpvalue_create_string(OPCUA_PROPERTY_METADATA_NODE_NAME);

        if (name == NULL)
        {
            result = __LINE__; goto error;
        }

        value = amqpvalue_get_map_value(map, name);

        if (value != NULL)
        {
            amqpvalue_destroy(name);

            if (amqpvalue_get_string(value, &string) != 0)
            {
                result = __LINE__; goto error;
            }

            pHeader->MetaDataNodeName = OpcUa_StrDup(string);
            amqpvalue_destroy(value);
        }

        amqpvalue_destroy(application_properties);
        application_properties = NULL;
    }

    return 0;

error:

    if (properties != NULL)
    {
        properties_destroy(properties);
    }

    if (application_properties != NULL)
    {
        amqpvalue_destroy(application_properties);
    }

    return result;
}

void OpcUa_AmqpMessageBody_Initialize(OpcUa_AmqpMessageBody* pBody)
{
    memset(pBody, 0, sizeof(OpcUa_AmqpMessageBody));
}

void OpcUa_AmqpMessageBody_Clear(OpcUa_AmqpMessageBody* pBody)
{
    if (pBody != NULL)
    {
        OpcUa_Free(pBody->EventId);
        OpcUa_Free(pBody->SourceName);
        OpcUa_Free(pBody->Time);
        OpcUa_Free(pBody->ReceiveTime);
        OpcUa_Free(pBody->Message);

        memset(pBody, 0, sizeof(OpcUa_AmqpMessageHeader));
    }
}

int OpcUa_Message_GetBody(MESSAGE_HANDLE message, OpcUa_AmqpMessageBody* pBody)
{
    int result = 0;
    BINARY_DATA body = { 0, 0 };
    char* json = NULL;
    json_object* pRoot = NULL;
    json_object* pField = NULL;
    json_object* pValue = NULL;

    if (message_get_body_amqp_data(message, 0, &body) != 0)
    {
        result = __LINE__; goto error;
    }

    json = OpcUa_Alloc(body.length + 1);
    memcpy(json, body.bytes, body.length);
    json[body.length] = 0;

    pRoot = json_tokener_parse(json);

    if (pBody != NULL)
    {
        if (json_object_object_get_ex(pRoot, "EventId", &pField))
        {
            pBody->EventId = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "EventType", &pField))
        {
            pBody->EventType = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "SourceNode", &pField))
        {
            pBody->SourceNode = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "SourceName", &pField))
        {
            pBody->SourceName = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "Time", &pField))
        {
            pBody->Time = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "ReceiveTime", &pField))
        {
            pBody->ReceiveTime = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "Message", &pField))
        {
            pBody->Message = OpcUa_StrDup(json_object_get_string(pField));
        }

        if (json_object_object_get_ex(pRoot, "Severity", &pField))
        {
            pBody->Severity = (uint16_t)json_object_get_int(pField);
        }
    }

    json_object_put(pRoot);
    OpcUa_Free(json);

    return 0;

error:

    OpcUa_Free(json);

    if (pRoot != NULL)
    {
        json_object_put(pRoot);
    }

    return result;
}

int OpcUa_Message_SetBody(MESSAGE_HANDLE message, OpcUa_AmqpMessageBody* pBody)
{
    int result = 0;
    BINARY_DATA body = { 0, 0 };
    const char* json = NULL;
    json_object* pRoot = NULL;

    pRoot = json_object_new_object();

    if (pBody->EventId != NULL)
    {
        json_object_object_add_ex(pRoot, "EventId", json_object_new_string(pBody->EventId), 0);
    }

    if (pBody->EventType != NULL)
    {
        json_object* pField = json_object_new_object();
        json_object_object_add_ex(pField, "i", json_object_new_int(atoi(pBody->EventType)), 0);
        json_object_object_add_ex(pRoot, "EventType", pField, 0);
    }

    if (pBody->SourceNode != NULL)
    {
        json_object* pField = json_object_new_object();
        json_object_object_add_ex(pField, "i", json_object_new_int(atoi(pBody->SourceNode)), 0);
        json_object_object_add_ex(pRoot, "SourceNode", pField, 0);
    }

    if (pBody->SourceName != NULL)
    {
        json_object_object_add_ex(pRoot, "SourceName", json_object_new_string(pBody->SourceName), 0);
    }

    if (pBody->Time != NULL)
    {
        json_object_object_add_ex(pRoot, "Time", json_object_new_string(pBody->Time), 0);
    }

    if (pBody->ReceiveTime != NULL)
    {
        json_object_object_add_ex(pRoot, "ReceiveTime", json_object_new_string(pBody->ReceiveTime), 0);
    }

    if (pBody->Message != NULL)
    {
        json_object_object_add_ex(pRoot, "Message", json_object_new_string(pBody->Message), 0);
    }

    if (pBody->Severity != 0)
    {
        json_object_object_add_ex(pRoot, "Severity", json_object_new_int(pBody->Severity), 0);
    }

    json = json_object_to_json_string_ext(pRoot, 0);

    body.bytes = (const unsigned char*)json;
    body.length = strlen(json);

    if (message_add_body_amqp_data(message, body) != 0)
    {
        result = __LINE__; goto error;
    }

    json_object_put(pRoot);

    return 0;

error:

    if (pRoot != NULL)
    {
        json_object_put(pRoot);
    }

    return result;
}

