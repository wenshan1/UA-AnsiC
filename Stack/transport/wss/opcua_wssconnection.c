/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.

   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else

   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/

   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2

   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

/* core */
#include <opcua.h>

#ifdef OPCUA_HAVE_CLIENTAPI

#include <opcua_mutex.h>
#include <opcua_datetime.h>
#include <opcua_socket.h>
#include <opcua_utilities.h>
#include <opcua_list.h>
#include <opcua_guid.h>
#include <opcua_timer.h>

/* types */
#include <opcua_builtintypes.h>
#include <opcua_binaryencoder.h>
#include <opcua_wssstream.h>
#include <opcua_binaryencoder.h>

/* self */
#include <opcua_wssconnection.h>
#include <opcua_cryptofactory.h>
#include <opcua_base64.h>
#include <opcua_p_openssl.h>
#include <ctype.h>

/* default value is 1, the alternative is a research implementation, which needs to be tested! */
#define OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM 1

/*============================================================================
 * OpcUa_SecureConnectionState
 *===========================================================================*/
 /** @brief The states a TcpConnection can be in. */
typedef enum _OpcUa_WssConnectionState
{
    /** @brief Error state. */
    OpcUa_WssConnectionState_Invalid,
    /** @brief Connection object connecting. */
    OpcUa_WssConnectionState_Connecting,
    /** @brief Connection is established, communication to the server is possible. */
    OpcUa_WssConnectionState_Connected,
    /** @brief The session was closed gracefully with a disconnect message. */
    OpcUa_WssConnectionState_Disconnected,
    /** @brief An error message was received and the connection is inactive. */
    OpcUa_WssConnectionState_Error
}
OpcUa_WssConnectionState;

/*============================================================================
 * OpcUa_WssConnection
 *===========================================================================*/
/** @brief Holds all data needed to manage a tcp binary connection to an ua server. */
typedef struct _OpcUa_WssConnection
{
    /** @brief Internal helper to verify instances. */
    OpcUa_UInt32                    SanityCheck;
    /** @brief The state of the connection to the server. */
    OpcUa_WssConnectionState        ConnectionState;
    /** @brief The socket holding the connection to the server. */
    OpcUa_Socket                    Socket;
    /** @brief Messaging events to the holder of this connection. */
    OpcUa_Connection_PfnOnNotify*   NotifyCallback;
    /** @brief Data to pass back with the callback. */
    OpcUa_Void*                     CallbackData;
    /** @brief Synchronizing access to this connection. */
    OpcUa_Mutex                     ReadMutex;
    /** @brief An active datastream being received (message). */
    OpcUa_InputStream*              IncomingStream;
#if !OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM
    /** @brief An active datastream being sent (message). */
    OpcUa_OutputStream*             OutgoingStream;
    OpcUa_Boolean                   bOutgoingStreamIsUsed;
#endif /* !OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM */
    /** @brief The time when the connection was established. */
    OpcUa_DateTime                  ConnectTime;
    /** @brief The time when the client disconnected. */
    OpcUa_DateTime                  DisconnectTime;
    /** @brief The buffer size for receiving data on this connection. */
    OpcUa_UInt32                    ReceiveBufferSize;
    /** @brief The buffer size for sending data over this connection. */
    OpcUa_UInt32                    SendBufferSize;
    /** @brief The maximum message size accepted by this connection. */
    OpcUa_UInt32                    MaxMessageSize;
    /** @brief The maximum number of chunks per message accepted by this connection. */
    OpcUa_UInt32                    MaxChunkCount;
    /** @brief The current number of chunks in an message. If 0, the connection is waiting for the next message. */
    OpcUa_UInt32                    uCurrentChunk;
    OpcUa_String                    sURL;
#if OPCUA_MULTITHREADED
    /*! @brief Holds the socket for this connection, the thread and is the central waiting point. */
    OpcUa_SocketManager             SocketManager;
#endif /* OPCUA_MULTITHREADED */
    /*! @brief The protocol version used for this connection. */
    OpcUa_UInt32                    uProtocolVersion;
    /** @brief The queued list of data blocks to be sent. */
    OpcUa_BufferList*               pSendQueue;
    /** @brief The state of the connection. */

    OpcUa_WssConnection_StreamState  StreamState;

    OpcUa_StringA                    sWebSocketKey;
    OpcUa_ByteString*                pClientCertificate;
    OpcUa_ByteString*                pClientPrivateKey;
    OpcUa_Void*                      pPKIConfig;
    OpcUa_Socket_CertificateCallback pfnCertificateValidation;
    OpcUa_Void*                      pCertificateValidationCallbackData;
}
OpcUa_WssConnection;

/*============================================================================
 * OpcUa_WssConnection_SanityCheck
 *===========================================================================*/
#define OpcUa_WssConnection_SanityCheck 0x4FCC07CB

/*============================================================================
 * OpcUa_ReturnErrorIfInvalidConnection
 *===========================================================================*/
#define OpcUa_ReturnErrorIfInvalidConnection(xConnection) \
if (((OpcUa_WssConnection*)(xConnection)->Handle)->SanityCheck != OpcUa_WssConnection_SanityCheck) \
{ \
    return OpcUa_BadInvalidArgument; \
}

/*============================================================================
 * Forward Declaration
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_Disconnect(                OpcUa_Connection*   a_pConnection,
                                                                OpcUa_Boolean       a_bNotifyOnComplete);

OpcUa_StatusCode OpcUa_WssConnection_BeginReceiveResponse(      OpcUa_Connection*   a_pConnection,
                                                                OpcUa_InputStream** a_ppInputStream);

OpcUa_StatusCode OpcUa_WssConnection_GetReceiveBufferSize(      OpcUa_Connection*   a_pConnection,
                                                                OpcUa_UInt32*       a_pBufferSize);

OpcUa_StatusCode OpcUa_WssConnection_AddToSendQueue(            OpcUa_Connection*   a_pConnection,
                                                                OpcUa_BufferList*   a_pBufferList,
                                                                OpcUa_UInt32        a_uFlags);

OpcUa_StatusCode OpcUa_WssConnection_CheckProtocolVersion(      OpcUa_Connection*   a_pConnection,
                                                                OpcUa_UInt32        a_uProtocolVersion);

/*============================================================================
 * OpcUa_WssListener_EventHandler Type Definition
 *===========================================================================*/
/** @brief Internal handler prototype. */
typedef OpcUa_StatusCode (*OpcUa_WssConnection_EventHandler)(   OpcUa_Connection*   a_pConnection,
                                                                OpcUa_Socket        a_pSocket);

/*============================================================================
 * OpcUa_WssRequestState
 *===========================================================================*/
/** @brief Tells about the current processing state of the request. */
typedef enum _OpcUa_WssRequestState
{
    /** @brief The server is waiting for the response. */
    OpcUa_WssRequestState_Invalid,
    /** @brief The server is waiting for the response. */
    OpcUa_WssRequestState_Open,
    /** @brief The response arrived partially. */
    OpcUa_WssRequestState_Started,
    /** @brief The response arrived completely, the request is finished. */
    OpcUa_WssRequestState_Finished,
    /** @brief Either server or client cancelled the request. */
    OpcUa_WssRequestState_Cancelled
} OpcUa_WssRequestState;

/*============================================================================
 * Handling a disconnect from the server.
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_HandleDisconnect(OpcUa_Connection* a_pConnection)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "HandleDisconnect");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_HandleDisconnect!\n");

    /* mark the connection as closed */
    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);

    if(pWssConnection->ConnectionState == OpcUa_WssConnectionState_Disconnected)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        OpcUa_ReturnStatusCode;
    }

    /* close the socket */
    OPCUA_P_SOCKET_CLOSE(pWssConnection->Socket);
    pWssConnection->Socket = OpcUa_Null;
    pWssConnection->DisconnectTime = OPCUA_P_DATETIME_UTCNOW();
    pWssConnection->ConnectionState = OpcUa_WssConnectionState_Disconnected;

    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

    /* notify upper layer about disconnect */
    if(pWssConnection->NotifyCallback != OpcUa_Null)
    {
        pWssConnection->NotifyCallback( a_pConnection,
                                        pWssConnection->CallbackData,
                                        OpcUa_ConnectionEvent_Disconnect,
                                        OpcUa_Null, /* no stream for this event */
                                        OpcUa_BadDisconnect);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
} /* OpcUa_WssConnection_HandleDisconnect */

/*============================================================================
 * OpcUa_WssConnection_ConnectionDisconnectCB
 *===========================================================================*/
/** @brief Gets called by an outstream if the connection is lost. */
static OpcUa_Void OpcUa_WssConnection_ConnectionDisconnectCB(OpcUa_Handle a_hConnection)
{
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ConnectionDisconnectCB: Connection %p is being reported as broken!\n", a_hConnection);

    OpcUa_WssConnection_HandleDisconnect((OpcUa_Connection*)a_hConnection);
}

extern OpcUa_StatusCode OpcUa_WssListener_CalculateAcceptKey(
    OpcUa_StringA  a_sKey,
    OpcUa_StringA* a_pAcceptKey);

/*============================================================================
* OpcUa_WssConnection_CalculatetKey
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_CalculateKey(
    OpcUa_Int32 a_uKeyLength, 
    OpcUa_StringA* a_pKey)
{
    OpcUa_Key key;
    OpcUa_CryptoProvider* pCryptoProvider = OpcUa_Null;
    OpcUa_StringA sKey = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "CalculatetKey");

    OpcUa_ReturnErrorIfArgumentNull(a_pKey);

    *a_pKey = OpcUa_Null;
    OpcUa_Key_Initialize(&key);

    pCryptoProvider = (OpcUa_CryptoProvider*)OpcUa_Alloc(sizeof(OpcUa_CryptoProvider));
    OpcUa_GotoErrorIfAllocFailed(pCryptoProvider);

    uStatus = OPCUA_P_CRYPTOFACTORY_CREATECRYPTOPROVIDER(OpcUa_SecurityPolicy_Basic128Rsa15, pCryptoProvider);
    OpcUa_GotoErrorIfBad(uStatus);

    key.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(a_uKeyLength);
    key.Key.Length = a_uKeyLength;

    uStatus = OpcUa_P_OpenSSL_Random_Key_Generate(pCryptoProvider, a_uKeyLength, &key);
    OpcUa_GotoErrorIfBad(uStatus);

    OPCUA_P_CRYPTOFACTORY_DELETECRYPTOPROVIDER(pCryptoProvider);
    OpcUa_Free(pCryptoProvider);
    pCryptoProvider = OpcUa_Null;

    uStatus = OpcUa_Base64_Encode(key.Key.Data, key.Key.Length, &sKey);
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_Free(key.Key.Data);
    key.Key.Data = OpcUa_Null;
    OpcUa_Key_Clear(&key);
    
    *a_pKey = sKey;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCryptoProvider != OpcUa_Null)
    {
        OPCUA_P_CRYPTOFACTORY_DELETECRYPTOPROVIDER(pCryptoProvider);
        OpcUa_Free(pCryptoProvider);
        pCryptoProvider = OpcUa_Null;
    }

    if (key.Key.Data != OpcUa_Null)
    {
        OpcUa_Free(key.Key.Data);
        key.Key.Data = OpcUa_Null;
        OpcUa_Key_Clear(&key);
    }

    if (sKey != OpcUa_Null)
    {
        OpcUa_Free(sKey);
        sKey = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssConnection_VerifyAcceptKey
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_VerifyAcceptKey(
    OpcUa_StringA a_sKey,
    OpcUa_StringA a_sAcceptKey)
{
    OpcUa_StringA sExpectedAcceptKey = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "VerifyAcceptKey");

    OpcUa_ReturnErrorIfArgumentNull(a_sKey);
    OpcUa_ReturnErrorIfArgumentNull(a_sAcceptKey);

    uStatus = OpcUa_WssListener_CalculateAcceptKey(a_sKey, &sExpectedAcceptKey);
    OpcUa_GotoErrorIfBad(uStatus);

    if (OpcUa_StrCmpA(sExpectedAcceptKey, a_sAcceptKey) != 0)
    {
        return OpcUa_BadNoMatch;
    }

    OpcUa_Free(sExpectedAcceptKey);
    sExpectedAcceptKey = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (sExpectedAcceptKey != OpcUa_Null)
    {
        OpcUa_Free(sExpectedAcceptKey);
        sExpectedAcceptKey = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssConnection_SendHttpUpgradeRequest
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_SendHttpUpgradeRequest(OpcUa_Connection* a_pConnection)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;
    OpcUa_OutputStream* pOutputStream = OpcUa_Null;
    OpcUa_WssOutputStream* pWssOutputStream = OpcUa_Null;
    OpcUa_StringA sKey = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "SendHttpUpgradeRequest");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection->Handle);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    uStatus = OpcUa_WssStream_CreateOutput(
        pWssConnection->Socket,
        OpcUa_WssStream_MessageType_HttpUpgradeRequest,
        OpcUa_Null,
        OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize, /* use initial value before handshake */
        OpcUa_WssConnection_ConnectionDisconnectCB,
        pWssConnection->MaxChunkCount,
        pWssConnection->StreamState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_WssConnection_CalculateKey(16, &sKey);
    OpcUa_GotoErrorIfBad(uStatus);
    
    pWssOutputStream = (OpcUa_WssOutputStream*)pOutputStream;

    OpcUa_SPrintfA(
        pWssOutputStream->Buffer.Data, 
        pWssOutputStream->Buffer.Size, 
        "GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: application/opcua+uatcp\r\n\r\n", 
        sKey);

    pWssConnection->sWebSocketKey = sKey;
    sKey = OpcUa_Null;

    pOutputStream->SetPosition(pOutputStream, OpcUa_StrLenA(pWssOutputStream->Buffer.Data));

    uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);

    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);

        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;
        
        if(pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }
        
        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData, Buffer.Data, Buffer.EndOfData);

        uStatus = OpcUa_Connection_AddToSendQueue(
            a_pConnection,
            pBufferList,
            0);
        
        OpcUa_Buffer_Clear(&Buffer);
    }

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Close((OpcUa_Stream*)pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (sKey != OpcUa_Null)
    {
        OpcUa_Free(sKey);
        sKey = OpcUa_Null;
    }

    if((pOutputStream != OpcUa_Null) && (pOutputStream->Delete != OpcUa_Null))
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_StatusCode OOpcUa_WssConnection_ProcessHttpUpgradeResponse
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_ProcessHttpUpgradeResponse(
    OpcUa_Connection*  a_pConnection,
    OpcUa_InputStream* a_pInputStream)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;
    OpcUa_WssInputStream* pWssInputStream = OpcUa_Null;
    OpcUa_StringA sHeader = OpcUa_Null;
    OpcUa_Int32 nHttpStatus = 0;
    OpcUa_Boolean bConnectionHeader = OpcUa_False;
    OpcUa_Boolean bUpgradeHeader = OpcUa_False;
    OpcUa_Boolean bProtocolHeader = OpcUa_False;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ProcessHttpUpgradeResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pInputStream);
    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssInputStream);

    /* the stream ensures this is a null terminated string */
    sHeader = pWssInputStream->Buffer.Data;
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "HTTP Upgrade Header: %s\n", sHeader);

    if (OpcUa_StrinCmpA("HTTP/1.1", sHeader, 8) != 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }

    sHeader += 9;
    while (isspace(*sHeader)) sHeader++;

    nHttpStatus = OpcUa_CharAToInt(sHeader);

    if (nHttpStatus != 101)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadNoCommunication);
    }

    while (*sHeader != '\n') sHeader++;

    while (*sHeader != '\0')
    {
        if (OpcUa_StrinCmpA("Connection:", sHeader, 11) == 0)
        {
            OpcUa_Boolean bConnectionUpgrade = OpcUa_False;

            sHeader += 12;
            while (isspace(*sHeader)) sHeader++;

            while (*sHeader != '\r')
            {
                if (OpcUa_StrinCmpA("Upgrade", sHeader, 7) == 0)
                {
                    bConnectionUpgrade = OpcUa_True;
                    break;
                }

                sHeader++;
            }     

            if (!bConnectionUpgrade)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
            }

            bConnectionHeader = OpcUa_True;
        }

        else if (OpcUa_StrinCmpA("Upgrade:", sHeader, 8) == 0)
        {
            sHeader += 9;
            while (isspace(*sHeader)) sHeader++;

            if (OpcUa_StrinCmpA("WebSocket", sHeader, 7) != 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
            }

            bUpgradeHeader = OpcUa_True;
        }

        else if (OpcUa_StrinCmpA("Sec-WebSocket-Accept:", sHeader, 21) == 0)
        {
            OpcUa_CharA* sAcceptKey = OpcUa_Null;
            sHeader += 22;
            while (isspace(*sHeader)) sHeader++;

            sAcceptKey = sHeader;
            while (!isspace(*sHeader)) sHeader++;
            *sHeader = '\0';

            uStatus = OpcUa_WssConnection_VerifyAcceptKey(pWssConnection->sWebSocketKey, sAcceptKey);
            OpcUa_GotoErrorIfBad(uStatus);
            sHeader++;
        }

        else if (OpcUa_StrinCmpA("Sec-WebSocket-Protocol:", sHeader, 23) == 0)
        {
            sHeader += 24;
            while (isspace(*sHeader)) sHeader++;

            if (OpcUa_StrinCmpA("application/opcua+uatcp", sHeader, 5) != 0)
            {
                OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
            }

            bProtocolHeader = OpcUa_True;
        }

        while (!isspace(*sHeader)) sHeader++;
        while (isspace(*sHeader)) sHeader++;
    }

    if (!bConnectionHeader || !bUpgradeHeader || !bProtocolHeader)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pWssConnection->NotifyCallback != OpcUa_Null)
    {
        OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
        pWssConnection->ConnectionState = OpcUa_WssConnectionState_Connected;
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

        pWssConnection->NotifyCallback( 
            a_pConnection,
            pWssConnection->CallbackData,
            OpcUa_ConnectionEvent_Connect,
            OpcUa_Null, /* no stream for this event */
            uStatus);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Send a Hello message.
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_WssConnection_SendHelloMessage(OpcUa_Connection* a_pConnection)
{
    OpcUa_WssConnection*    pWssConnection   = OpcUa_Null;
    OpcUa_OutputStream*     pOutputStream    = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "SendHelloMessage");

    OpcUa_GotoErrorIfArgumentNull(a_pConnection);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssConnection);

    uStatus = OpcUa_WssStream_CreateOutput(
        pWssConnection->Socket,
        OpcUa_WssStream_MessageType_Hello,
        OpcUa_Null,
        OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize, /* use initial value before handshake */
        OpcUa_WssConnection_ConnectionDisconnectCB,
        pWssConnection->MaxChunkCount,
        pWssConnection->ConnectionState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);


    /* encode the body of a Hello message */

    /* client protocol version */
    uStatus = OpcUa_UInt32_BinaryEncode((pWssConnection->uProtocolVersion), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* receive buffer length */
    uStatus = OpcUa_UInt32_BinaryEncode((pWssConnection->ReceiveBufferSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* send buffer length */
    uStatus = OpcUa_UInt32_BinaryEncode((pWssConnection->SendBufferSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* send max message size */
    uStatus = OpcUa_UInt32_BinaryEncode((pWssConnection->MaxMessageSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* send max chunk count */
    uStatus = OpcUa_UInt32_BinaryEncode((pWssConnection->MaxChunkCount), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* encode buffer length */
    uStatus = OpcUa_String_BinaryEncode(&(pWssConnection->sURL), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "Requesting: SB:%u RB:%u\n",   pWssConnection->SendBufferSize,
                                                                        pWssConnection->ReceiveBufferSize);

    uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);
    if(OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer      Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);
        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;
        if(pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }
        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData,
                     Buffer.Data, Buffer.EndOfData);
        uStatus = OpcUa_Connection_AddToSendQueue(
            a_pConnection,
            pBufferList,
            0);
        OpcUa_Buffer_Clear(&Buffer);
    }
    OpcUa_GotoErrorIfBad(uStatus);

    /* finish stream and delete it */
    uStatus = pOutputStream->Close((OpcUa_Stream*)pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if((pOutputStream != OpcUa_Null) && (pOutputStream->Delete != OpcUa_Null))
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
} /* OpcUa_WssConnection_SendHelloMessage */

/*============================================================================
 * Process Acknowledge Message
 *===========================================================================*/
/**
 * @brief Reads and parses a acknowledge message and passes the result up.
 */
static OpcUa_StatusCode OpcUa_WssConnection_ProcessAcknowledgeMessage(  OpcUa_Connection*   a_pConnection,
                                                                        OpcUa_InputStream*  a_pInputStream)
{
    OpcUa_WssInputStream*   pWssInputStream         = OpcUa_Null;
    OpcUa_WssConnection*    pWssConnection          = OpcUa_Null;
    OpcUa_UInt32            uRevisedProtocolVersion = 0;
    OpcUa_UInt32            uRevisedRecvBufSize     = 0;
    OpcUa_UInt32            uRevisedSendBufSize     = 0;
    OpcUa_UInt32            uRevisedMaxChunkCnt     = 0;
    OpcUa_UInt32            uRevisedMessageSize     = 0;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ProcessAcknowledgeMessage");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssConnection);

    OpcUa_ReturnErrorIfArgumentNull(a_pInputStream);
    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssInputStream);

    /* consistency check */
    if((a_pInputStream != pWssConnection->IncomingStream) ||
       (pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connecting) ||
       (pWssConnection->pSendQueue != OpcUa_Null))
    {
        return OpcUa_Bad;
    }

    /* parse the fields of an acknowledge message */
    /* The latest version of the OPC UA TCP protocol supported by the Server */
    uStatus = OpcUa_UInt32_BinaryDecode(&uRevisedProtocolVersion, a_pInputStream);
    OpcUa_GotoErrorIfBad(uStatus);
    pWssConnection->uProtocolVersion = uRevisedProtocolVersion;

    /* revised recv buffer length */
    uStatus = OpcUa_UInt32_BinaryDecode(&uRevisedRecvBufSize, a_pInputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* check the revised buffer sizes */
    /* This value shall not be larger than what the Client requested in the Hello Message */
    /* This value shall be greater than 8 192 bytes */
    if(uRevisedRecvBufSize > pWssConnection->ReceiveBufferSize ||
       uRevisedRecvBufSize <= 8192)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);
    }
    pWssConnection->ReceiveBufferSize = uRevisedRecvBufSize;

    /* revised send buffer length */
    uStatus = OpcUa_UInt32_BinaryDecode(&uRevisedSendBufSize, a_pInputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* check the revised buffer sizes */
    /* This value shall not be larger than what the Client requested in the Hello Message */
    /* This value shall be greater than 8 192 bytes */
    if(uRevisedSendBufSize > pWssConnection->SendBufferSize ||
       uRevisedSendBufSize <= 8192)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);
    }
    pWssConnection->SendBufferSize = uRevisedSendBufSize;

    /* revised max message size */
    uStatus = OpcUa_UInt32_BinaryDecode(&uRevisedMessageSize, a_pInputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* check the revised max message length */
    if(uRevisedMessageSize == 0 || uRevisedMessageSize > pWssConnection->MaxMessageSize)
    {
        /*OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);*/
        /* ignore, server accepts our size and more */
    }
    else
    {
        /* accept smaller messages */
        pWssConnection->MaxMessageSize = uRevisedMessageSize;
    }

    /* revised chunk count */
    uStatus = OpcUa_UInt32_BinaryDecode(&uRevisedMaxChunkCnt, a_pInputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* check the revised chunk count */
    if(uRevisedMaxChunkCnt == 0 || uRevisedMaxChunkCnt > pWssConnection->MaxChunkCount)
    {
        /*OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);*/
        /* ignore, server accepts our size and more */
    }
    else
    {
        /* accept less chunks */
        pWssConnection->MaxChunkCount = uRevisedMaxChunkCnt;
    }

    /** parsing finished **/
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "Set:       SB:%u RB:%u\n",
        pWssConnection->SendBufferSize,
        pWssConnection->ReceiveBufferSize);

    if(pWssConnection->NotifyCallback != OpcUa_Null)
    {
        OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
        pWssConnection->ConnectionState = OpcUa_WssConnectionState_Connected;
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        pWssConnection->NotifyCallback( a_pConnection,
                                        pWssConnection->CallbackData,
                                        OpcUa_ConnectionEvent_Connect,
                                        OpcUa_Null, /* no stream for this event */
                                        uStatus);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pWssConnection->NotifyCallback != OpcUa_Null)
    {
        OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
        pWssConnection->ConnectionState = OpcUa_WssConnectionState_Connected;
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        pWssConnection->NotifyCallback( a_pConnection,
                                        pWssConnection->CallbackData,
                                        OpcUa_ConnectionEvent_Connect,
                                        OpcUa_Null, /* no stream for this event */
                                        uStatus);
    }

OpcUa_FinishErrorHandling;
} /* OpcUa_WssConnection_ProcessAcknowledgeMessage */

/*============================================================================
 * OpcUa_WssConnection_ProcessResponse
 *===========================================================================*/
/**
* @brief Handles a message (chunk) that has to be forwarded to the securechannel layer.
*/
static OpcUa_StatusCode OpcUa_WssConnection_ProcessResponse(OpcUa_Connection*   a_pConnection,
                                                            OpcUa_InputStream*  a_pInputStream)
{
    OpcUa_WssInputStream*   pWssInputStream = OpcUa_Null;
    OpcUa_WssConnection*    pWssConnection  = OpcUa_Null;
    OpcUa_ConnectionEvent   eEvent          = OpcUa_ConnectionEvent_Invalid;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ProcessResponse");

    OpcUa_GotoErrorIfArgumentNull(a_pConnection);
    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssConnection);

    OpcUa_GotoErrorIfArgumentNull(a_pInputStream);
    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssInputStream);

    if(pWssInputStream->IsAbort != OpcUa_False)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssConnection_ProcessResponse: Message aborted after %u chunks!\n", pWssConnection->uCurrentChunk);
        eEvent = OpcUa_ConnectionEvent_ResponseAbort;
        pWssConnection->uCurrentChunk = 0;
    }
    else /* no abort message */
    {
        if(pWssInputStream->IsFinal != OpcUa_False)
        {
            /* final chunk in message, reset counter */
            eEvent = OpcUa_ConnectionEvent_Response;
            pWssConnection->uCurrentChunk = 0;
        }
        else
        {
            /* intermediary chunk, test for limit and increment */
            pWssConnection->uCurrentChunk++;
            eEvent = OpcUa_ConnectionEvent_ResponsePartial;

            if((pWssConnection->MaxChunkCount != 0) && (pWssConnection->uCurrentChunk >= pWssConnection->MaxChunkCount))
            {
                /* this message will be too large */
                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_ProcessResponse: Chunk count limit exceeded!\n");
                eEvent = OpcUa_ConnectionEvent_Response; /* message final */
                uStatus = OpcUa_BadTcpMessageTooLarge;   /* with error */
            }
        }
    }

    if(OpcUa_IsGood(uStatus))
    {
        /* dispatch based on message type */
        switch(pWssInputStream->MessageType)
        {
        case OpcUa_WssStream_MessageType_SecureChannel:
            {
                /* It is the first and only or the last chunk of a row. Message Data begins here. */
                /* Notify the upper layer of this stream. */
                if(pWssConnection->NotifyCallback != OpcUa_Null)
                {
                    /* the securechannel wants to start reading at the signature. */
                    pWssConnection->NotifyCallback( a_pConnection,
                                                    (OpcUa_Void*)pWssConnection->CallbackData,
                                                    eEvent,
                                                    (OpcUa_InputStream**)&a_pInputStream,
                                                    OpcUa_Good);
                }

                break;
            }
        case OpcUa_WssStream_MessageType_Error:
            {
                OpcUa_StatusCode    uReceivedStatusCode = OpcUa_Good;
                OpcUa_String        sReason             = OPCUA_STRING_STATICINITIALIZER;
                OpcUa_UInt32        uReasonLength;
                OpcUa_StringA       psReason;

                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_ProcessResponse: Error Message!\n");

                /* status code */
                uStatus = OpcUa_UInt32_BinaryDecode(&uReceivedStatusCode, a_pInputStream);
                OpcUa_GotoErrorIfBad(uStatus);

                uStatus = OpcUa_String_BinaryDecode(&sReason,
                                                    OpcUa_ProxyStub_g_Configuration.iSerializer_MaxStringLength,
                                                    a_pInputStream);
                OpcUa_GotoErrorIfBad(uStatus);
                OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
                pWssConnection->ConnectionState = OpcUa_WssConnectionState_Error;
                OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_ProcessResponse: Status 0x%08x!\n", uReceivedStatusCode);
                uReasonLength = OpcUa_String_StrLen(&sReason);
                psReason = OpcUa_String_GetRawString(&sReason);
                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_ProcessResponse: Reason %*.*s\n", uReasonLength, uReasonLength, psReason);
                OpcUa_String_Clear(&sReason);

                if(OpcUa_IsGood(uReceivedStatusCode))
                {
                    uReceivedStatusCode = OpcUa_Bad;
                }

                /* The message is finished at this point.*/
                if(pWssConnection->NotifyCallback != OpcUa_Null)
                {
                    pWssConnection->NotifyCallback(  a_pConnection,
                                                    (OpcUa_Void*)pWssConnection->CallbackData,
                                                    OpcUa_ConnectionEvent_UnexpectedError,
                                                    OpcUa_Null,
                                                    uReceivedStatusCode);
                }

                break;
            }
        default:
            {
                OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "ERROR: Message Type %d cannot be handled!\n", pWssInputStream->MessageType);
                uStatus = OpcUa_BadInternalError;
                break;
            }
        }
    }
    else
    {
        /* The message is finished at this point.*/
        /* Send the abort request to upper layers. */
        if(pWssConnection->NotifyCallback != OpcUa_Null)
        {
            pWssConnection->NotifyCallback( a_pConnection,
                                            (OpcUa_Void*)pWssConnection->CallbackData,
                                            eEvent,
                                            OpcUa_Null,
                                            uStatus);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
} /* OpcUa_WssConnection_ProcessResponse */

/*============================================================================
 * OpcUa_WssListener_DisconnectEventHandler
 *===========================================================================*/
/**
* @brief Gets called if the connection with the server gets broke (not the UATD -> ProcessDisconnectMessage).
*/
OpcUa_StatusCode OpcUa_WssConnection_DisconnectEventHandler(OpcUa_Connection*   a_pConnection,
                                                            OpcUa_Socket        a_pSocket)
{
OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "DisconnectEventHandler");

    OpcUa_ReferenceParameter(a_pSocket);

    /* Call the internal handler */
    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
} /* OpcUa_WssConnection_DisconnectEventHandler */

/*============================================================================
 * OpcUa_WssConnection_ExceptEventHandler
 *===========================================================================*/
/**
 * @brief Called by the socket callback when a expcept event occured on the socket.
 *
 * This may happen ie. if a connect fails because the server is not reachable.
 * The event needs to be messaged to the upper layers.
 */
OpcUa_StatusCode OpcUa_WssConnection_ExceptEventHandler(    OpcUa_Connection*   a_pConnection,
                                                            OpcUa_Socket        a_pSocket)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ExceptEventHandler");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(a_pConnection);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    OpcUa_GotoErrorIfArgumentNull(pWssConnection);

    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);

    if(pWssConnection->ConnectionState == OpcUa_WssConnectionState_Connected || pWssConnection->ConnectionState == OpcUa_WssConnectionState_Connecting)
    {
        pWssConnection->ConnectionState = OpcUa_WssConnectionState_Disconnected;
    }

    OPCUA_P_SOCKET_CLOSE(a_pSocket);
    pWssConnection->Socket = OpcUa_Null;

    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

    if(pWssConnection->NotifyCallback != OpcUa_Null)
    {
        pWssConnection->NotifyCallback(
            a_pConnection,
            pWssConnection->CallbackData,
            OpcUa_ConnectionEvent_UnexpectedError, /* TODO: See if theres a better method. Secure layer also needs to be prepared for this. */
            OpcUa_Null, /* no stream for this event */
            OpcUa_BadCommunicationError);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

extern OpcUa_StatusCode OpcUa_Socket_TlsClientStartUpgrade(
    OpcUa_Socket                     hSocket, 
    OpcUa_Void*                      pPKIConfig,
    OpcUa_Socket_CertificateCallback pfnCertificateValidation,
    OpcUa_Void*                      pCertificateValidationCallbackData);

extern OpcUa_StatusCode OpcUa_Socket_TlsClientContinueUpgrade(
    OpcUa_Socket                     a_hSocket, 
    OpcUa_Socket_CertificateCallback pfnCertificateValidation,
    OpcUa_Void*                      pCertificateValidationCallbackData);

/*============================================================================
 * OpcUa_WssConnection_ConnectEventHandler
 *===========================================================================*/
/**
 * @brief Called by the socket callback when a connect event occured.
 */
OpcUa_StatusCode OpcUa_WssConnection_ConnectEventHandler(    
    OpcUa_Connection*   a_pConnection,
    OpcUa_Socket        a_pSocket)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;
    OpcUa_Key privateKey;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ConnectEventHandler");

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(a_pConnection);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssConnection);

    OpcUa_Key_Initialize(&privateKey);

    /* first time we get the new socket, so store it. */
    pWssConnection->Socket = a_pSocket;

    privateKey.Type = OpcUa_Crypto_KeyType_Rsa_Private;
    privateKey.Key = *pWssConnection->pClientPrivateKey;
    privateKey.fpClearHandle = 0;

    uStatus = OpcUa_Socket_TlsClientStartUpgrade(
        a_pSocket, 
        pWssConnection->pPKIConfig,
        pWssConnection->pfnCertificateValidation, 
        pWssConnection->pCertificateValidationCallbackData);

    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
/*============================================================================
 * OpcUa_WssConnection_ReadEventHandler
 *===========================================================================*/
/**
* @brief Gets called if data is available on the socket. The connection instance must be locked here!
*/
OpcUa_StatusCode OpcUa_WssConnection_ReadEventHandler(
    OpcUa_Connection*   a_pConnection,
    OpcUa_Socket        a_pSocket)
{
    OpcUa_WssConnection* pWssConnection   = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_WssInputStream* pWssInputStream  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "ReadEventHandler");

    OpcUa_GotoErrorIfArgumentNull(a_pConnection);
    OpcUa_GotoErrorIfArgumentNull(a_pConnection->Handle);
    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    if (pWssConnection->StreamState == OpcUa_WssConnection_StreamState_TlsUpgrade)
    {
        uStatus = OpcUa_Socket_TlsClientContinueUpgrade(
            a_pSocket, 
            pWssConnection->pfnCertificateValidation, 
            pWssConnection->pCertificateValidationCallbackData);

        if (OpcUa_IsBad(uStatus) && OpcUa_IsNotEqual(OpcUa_GoodCallAgain))
        {                    
            OpcUa_WssConnection_HandleDisconnect(a_pConnection);
        }

        OpcUa_GotoErrorIfBad(uStatus);

        pWssConnection->StreamState = OpcUa_WssConnection_StreamState_HttpUpgrade;
        uStatus = OpcUa_WssConnection_SendHttpUpgradeRequest(a_pConnection);
        return OpcUa_Good;
    }

    /******************************************************************************************/

    /* check if a new stream needs to be created */
    if (pWssConnection->IncomingStream == OpcUa_Null)
    {
        /* create a new input stream */
        uStatus = OpcUa_WssStream_CreateInput(
            a_pSocket,
            OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize,
            pWssConnection->StreamState,
            &(pWssConnection->IncomingStream));

        OpcUa_ReturnErrorIfBad(uStatus);

        pWssInputStream = (OpcUa_WssInputStream *)pWssConnection->IncomingStream->Handle;
    }

    /******************************************************************************************/

    /* notify target stream about newly avaiable data */
    uStatus = OpcUa_WssStream_DataReady(pWssConnection->IncomingStream);

    /******************************************************************************************/

    if(OpcUa_IsEqual(OpcUa_GoodCallAgain))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: CallAgain result for stream %p on socket %p!\n", pWssConnection->IncomingStream, a_pSocket);
    }
    else
    {
        pWssInputStream = (OpcUa_WssInputStream*)pWssConnection->IncomingStream->Handle;

        if(OpcUa_IsBad(uStatus))
        {
            /* Error happened... */
            switch(uStatus)
            {
            case OpcUa_BadDecodingError:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: OpcUa_BadDecodingError for stream %p on socket %p! (Streamstate %d)\n", pWssConnection->IncomingStream, a_pSocket, pWssInputStream->State);
                    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
                    break;
                }
            case OpcUa_BadDisconnect:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: OpcUa_BadDisconnect for stream %p on socket %p! (Streamstate %d)\n", pWssConnection->IncomingStream, a_pSocket, pWssInputStream->State);
                    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
                    break;
                }
            case OpcUa_BadCommunicationError:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: OpcUa_BadCommunicationError for stream %p on socket %p! (Streamstate %d)\n", pWssConnection->IncomingStream, a_pSocket, pWssInputStream->State);
                    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
                    break;
                }
            case OpcUa_BadConnectionClosed:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: OpcUa_BadConnectionClosed for stream %p on socket %p! (Streamstate %d)\n", pWssConnection->IncomingStream, a_pSocket, pWssInputStream->State);
                    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
                    break;
                }
            default:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: Bad (%x) status for stream %p on socket %p! (Streamstate %d)\n", uStatus, pWssConnection->IncomingStream, a_pSocket, pWssInputStream->State);
                    uStatus = OpcUa_WssConnection_HandleDisconnect(a_pConnection);
                }
            }
            pWssConnection->IncomingStream->Close((OpcUa_Stream*)pWssConnection->IncomingStream);
            pWssConnection->IncomingStream->Delete((OpcUa_Stream**)&(pWssConnection->IncomingStream));
        }
        else /* Message can be processed. */
        {
            if (pWssConnection->StreamState == OpcUa_WssConnection_StreamState_HttpUpgrade)
            {
                uStatus = OpcUa_WssConnection_ProcessHttpUpgradeResponse(a_pConnection, pWssConnection->IncomingStream);
                OpcUa_GotoErrorIfBad(uStatus);
                pWssConnection->StreamState = OpcUa_WssConnection_StreamState_Open;

                /* this stream is parsed completely and can be deleted */
                pWssConnection->IncomingStream->Close((OpcUa_Stream*)(pWssConnection->IncomingStream));
                pWssConnection->IncomingStream->Delete((OpcUa_Stream**)&(pWssConnection->IncomingStream));

                uStatus = OpcUa_WssConnection_SendHelloMessage(a_pConnection);
                OpcUa_GotoErrorIfBad(uStatus);
                return OpcUa_Good;
            }

            /* process message (message types handled by the client are: ack, disconnect, requests, abort) */
            switch(pWssInputStream->MessageType)
            {
            case OpcUa_WssStream_MessageType_Acknowledge:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: MessageType ACKNOWLEDGE\n");
                    uStatus = OpcUa_WssConnection_ProcessAcknowledgeMessage(a_pConnection, pWssConnection->IncomingStream);

                    /* this stream is parsed completely and can be deleted */
                    pWssConnection->IncomingStream->Close((OpcUa_Stream*)(pWssConnection->IncomingStream));
                    pWssConnection->IncomingStream->Delete((OpcUa_Stream**)&(pWssConnection->IncomingStream));

                    break;
                }
            case OpcUa_WssStream_MessageType_Error:
            case OpcUa_WssStream_MessageType_SecureChannel:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: MessageType MESSAGE\n");

                    uStatus = OpcUa_WssConnection_ProcessResponse(a_pConnection, pWssConnection->IncomingStream);

                    pWssConnection->IncomingStream->Close((OpcUa_Stream*)pWssConnection->IncomingStream);
                    pWssConnection->IncomingStream->Delete((OpcUa_Stream**)&pWssConnection->IncomingStream);
                    break;
                }
            default:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_ReadEventHandler: Invalid MessageType (%d)\n", pWssInputStream->MessageType);

                    pWssConnection->IncomingStream->Close((OpcUa_Stream*)pWssConnection->IncomingStream);
                    pWssConnection->IncomingStream->Delete((OpcUa_Stream**)&pWssConnection->IncomingStream);
                    break;
                }
            }

        }
    }
OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_WriteEventHandler
 *===========================================================================*/
/**
* @brief Gets called if data can be written to the socket.
*/
OpcUa_StatusCode OpcUa_WssConnection_WriteEventHandler(
    OpcUa_Connection*   a_pConnection,
    OpcUa_Socket        a_pSocket)
{
    OpcUa_WssConnection*    pWssConnection   = (OpcUa_WssConnection*)a_pConnection->Handle;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "WriteEventHandler");

    OpcUa_GotoErrorIfArgumentNull(a_pConnection);
    OpcUa_GotoErrorIfArgumentNull(a_pConnection->Handle);
    OpcUa_GotoErrorIfArgumentNull(a_pSocket);

    /******************************************************************************************************/

    /* look for pending output stream */
    if(pWssConnection != OpcUa_Null)
    {
        do {
            while(pWssConnection->pSendQueue != OpcUa_Null)
            {
                OpcUa_BufferList *pCurrentBuffer = pWssConnection->pSendQueue;
                OpcUa_Int32 iDataLength = pCurrentBuffer->Buffer.EndOfData - pCurrentBuffer->Buffer.Position;
                OpcUa_Int32 iDataWritten = OPCUA_P_SOCKET_WRITE(a_pSocket,
                                                                &pCurrentBuffer->Buffer.Data[pCurrentBuffer->Buffer.Position],
                                                                iDataLength,
                                                                OpcUa_False);
                if(iDataWritten<0)
                {
                    return OpcUa_WssConnection_Disconnect(a_pConnection, OpcUa_True);
                }
                else if(iDataWritten<iDataLength)
                {
                    pCurrentBuffer->Buffer.Position += iDataWritten;
                    OpcUa_ReturnStatusCode;
                }
                else
                {
                    pWssConnection->pSendQueue = pCurrentBuffer->pNext;
                    OpcUa_Buffer_Clear(&pCurrentBuffer->Buffer);
                    OpcUa_Free(pCurrentBuffer);
                }
            } /* end while */

            if(pWssConnection->NotifyCallback != OpcUa_Null)
            {
                pWssConnection->NotifyCallback( a_pConnection,
                                                (OpcUa_Void*)pWssConnection->CallbackData,
                                                OpcUa_ConnectionEvent_RefillSendQueue,
                                                OpcUa_Null,
                                                uStatus);
            }

        } while(pWssConnection->pSendQueue != OpcUa_Null);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_SocketCallback
 *===========================================================================*/
/** @brief This function gets called if an network event occured. */
static OpcUa_StatusCode OpcUa_WssConnection_SocketCallback( OpcUa_Socket    a_pSocket,
                                                            OpcUa_UInt32    a_SocketEvent,
                                                            OpcUa_Void*     a_pUserData,
                                                            OpcUa_UInt16    a_nPortNumber,
                                                            OpcUa_Boolean   a_bIsSSL)
{
    OpcUa_WssConnection_EventHandler    fEventHandler   = OpcUa_Null;
    OpcUa_Connection*                   connection      = (OpcUa_Connection*)a_pUserData;
    OpcUa_WssConnection*                pWssConnection  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "SocketCallback");

    OpcUa_ReferenceParameter(a_nPortNumber);
    OpcUa_ReferenceParameter(a_bIsSSL);

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);
    OpcUa_GotoErrorIfArgumentNull(connection);

    pWssConnection = (OpcUa_WssConnection*)connection->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssConnection);

#if 0 /* debug code */
    {
        OpcUa_StringA                       strEvent        = OpcUa_Null;
        switch(a_SocketEvent)
        {
        case OPCUA_SOCKET_NO_EVENT:
            {
                strEvent = "OPCUA_SOCKET_NO_EVENT";
                break;
            }
        case OPCUA_SOCKET_READ_EVENT:
            {
                strEvent = "OPCUA_SOCKET_READ_EVENT";
                break;
            }
        case OPCUA_SOCKET_WRITE_EVENT:
            {
                strEvent = "OPCUA_SOCKET_WRITE_EVENT";
                break;
            }
        case OPCUA_SOCKET_EXCEPT_EVENT:
            {
                strEvent = "OPCUA_SOCKET_EXCEPT_EVENT";
                break;
            }
        case OPCUA_SOCKET_TIMEOUT_EVENT:
            {
                strEvent = "OPCUA_SOCKET_TIMEOUT_EVENT";
                break;
            }
        case OPCUA_SOCKET_CLOSE_EVENT:
            {
                strEvent = "OPCUA_SOCKET_CLOSE_EVENT";
                break;
            }
        case OPCUA_SOCKET_CONNECT_EVENT:
            {
                strEvent = "OPCUA_SOCKET_CONNECT_EVENT";
                break;
            }
        case OPCUA_SOCKET_ACCEPT_EVENT:
            {
                strEvent = "OPCUA_SOCKET_ACCEPT_EVENT";
                break;
            }
        case OPCUA_SOCKET_SHUTDOWN_EVENT:
            {
                strEvent = "OPCUA_SOCKET_SHUTDOWN_EVENT";
                break;
            }
        case OPCUA_SOCKET_NEED_BUFFER_EVENT:
            {
                strEvent = "OPCUA_SOCKET_NEED_BUFFER";
                break;
            }
        case OPCUA_SOCKET_FREE_BUFFER_EVENT:
            {
                strEvent = "OPCUA_SOCKET_FREE_BUFFER";
                break;
            }
        default:
            {
                strEvent = "ERROR DEFAULT!";
                break;
            }
        }

        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, " * OpcUa_WssConnection_SocketCallback: Socket(%x), Port(%d), Data(%d), Event(%s)\n", a_pSocket, a_nPortNumber, a_pUserData, strEvent);
    }
#endif /* debug code end */

    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
    if(    pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connected  /* wait for disconnect during error state */
        && pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connecting /* wait for disconnect during error state */
        && pWssConnection->ConnectionState != OpcUa_WssConnectionState_Error)     /* wait for disconnect during error state */
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, " * OpcUa_WssConnection_SocketCallback: Ignoring Socket(%p) Event(%u) due state %u!\n", a_pSocket, a_SocketEvent, pWssConnection->ConnectionState);
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        return OpcUa_Good;
    }
    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

    switch(a_SocketEvent)
    {
    case OPCUA_SOCKET_READ_EVENT:
        {
            /* notifies an existing stream about new data or creates a new stream */
            fEventHandler = OpcUa_WssConnection_ReadEventHandler;
            break;
        }
    case OPCUA_SOCKET_WRITE_EVENT:
        {
            fEventHandler = OpcUa_WssConnection_WriteEventHandler;
            break;
        }
    case OPCUA_SOCKET_EXCEPT_EVENT:
        {
            fEventHandler = OpcUa_WssConnection_ExceptEventHandler;
            break;
        }
    case OPCUA_SOCKET_TIMEOUT_EVENT:
        {
            break;
        }
    case OPCUA_SOCKET_CLOSE_EVENT:
        {
            break;
        }
    case OPCUA_SOCKET_CONNECT_EVENT:
        {
            fEventHandler = OpcUa_WssConnection_ConnectEventHandler;
            break;
        }
    case OPCUA_SOCKET_NO_EVENT:
        {
            break;
        }
    case OPCUA_SOCKET_SHUTDOWN_EVENT:
        {
            break;
        }
    case OPCUA_SOCKET_NEED_BUFFER_EVENT:
        {
            /* fEventHandler = OpcUa_WssConnection_NeedBufferEventHandler; */
            break;
        }
    case OPCUA_SOCKET_FREE_BUFFER_EVENT:
        {
            /* fEventHandler = OpcUa_WssConnection_FreeBufferEventHandler; */
            break;
        }
    case OPCUA_SOCKET_ACCEPT_EVENT:
    default:
        {
            /* TODO: define some errorhandling here! */
            break;
        }
    }

    /* call the internal specialized event handler */
    if(fEventHandler != OpcUa_Null)
    {
        uStatus = fEventHandler(connection, a_pSocket);
        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_SocketCallback: Handler returned error 0x%08X!\n", uStatus);
        }
    }

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, " * OpcUa_WssConnection_SocketCallback: Event Handler returned.\n");

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_Connect
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_Connect(
    struct _OpcUa_Connection*       a_pConnection,
    OpcUa_String*                   a_sUrl,
    OpcUa_ClientCredential*         a_pCredential,
    OpcUa_UInt32                    a_Timeout,
    OpcUa_Connection_PfnOnNotify*   a_pfnCallback,
    OpcUa_Void*                     a_pCallbackData)
{
    OpcUa_WssConnection* pWssConnection   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "Connect");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_sUrl);
    OpcUa_ReturnErrorIfArgumentNull(a_pfnCallback);

    OpcUa_ReferenceParameter(a_pCredential);
    OpcUa_ReferenceParameter(a_Timeout);
    OpcUa_ReferenceParameter(a_pCallbackData);

    OpcUa_ReturnErrorIfInvalidObject(OpcUa_WssConnection, a_pConnection, Connect);

    pWssConnection   = (OpcUa_WssConnection*)a_pConnection->Handle;

    pWssConnection->NotifyCallback   = a_pfnCallback;
    pWssConnection->CallbackData     = a_pCallbackData;
    pWssConnection->ConnectionState  = OpcUa_WssConnectionState_Connecting;

    OpcUa_String_StrnCpy(&pWssConnection->sURL, a_sUrl, OPCUA_STRING_LENDONTCARE);

#if OPCUA_MULTITHREADED
    uStatus = OPCUA_P_SOCKETMANAGER_CREATECLIENT(   pWssConnection->SocketManager,      /* socketmanager handle */
                                                    OpcUa_String_GetRawString(a_sUrl),  /* remote address */
                                                    0,                                  /* local port */
                                                    OpcUa_WssConnection_SocketCallback, /* callback function */
                                                    (OpcUa_Void*)a_pConnection,         /* callback data */
                                                    &(pWssConnection->Socket));         /* retreiving socket handle */
#else /* OPCUA_MULTITHREADED */
    uStatus = OPCUA_P_SOCKETMANAGER_CREATECLIENT(   OpcUa_Null,                         /* socketmanager handle */
                                                    OpcUa_String_GetRawString(a_sUrl),  /* remote address */
                                                    0,                                  /* local port */
                                                    OpcUa_WssConnection_SocketCallback, /* callback function */
                                                    (OpcUa_Void*)a_pConnection,         /* callback data */
                                                    &(pWssConnection->Socket));         /* retreiving socket handle */
#endif /* OPCUA_MULTITHREADED */
    OpcUa_GotoErrorIfBad(uStatus);

    /* tell the caller to expect a callback (only for non-blocking sockets)*/
    uStatus = OpcUa_GoodCompletesAsynchronously;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    pWssConnection->ConnectionState = OpcUa_WssConnectionState_Disconnected;

OpcUa_FinishErrorHandling;
}

/*===========================================================================
 * OpcUa_WssConnection_Disconnect
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_Disconnect(OpcUa_Connection* a_pConnection,
                                                OpcUa_Boolean     a_bNotifyOnComplete)
{
    OpcUa_WssConnection*    tcpConnection   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "Disconnect");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);

    tcpConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    OPCUA_P_MUTEX_LOCK(tcpConnection->ReadMutex);

    /* check, if the connection is in the right state for being disconnected */
    if(    tcpConnection->ConnectionState == OpcUa_WssConnectionState_Connected
        || tcpConnection->ConnectionState == OpcUa_WssConnectionState_Connecting)
    {
        /* first: set state */
        tcpConnection->ConnectionState = OpcUa_WssConnectionState_Disconnected;

        /* blind close without error checking */
        OPCUA_P_SOCKET_CLOSE(tcpConnection->Socket);
        tcpConnection->Socket = OpcUa_Null;
        OPCUA_P_MUTEX_UNLOCK(tcpConnection->ReadMutex);

        tcpConnection->DisconnectTime = OPCUA_P_DATETIME_UTCNOW();

        /* close socket and update connection handle. */
        if(a_bNotifyOnComplete)
        {
            if(tcpConnection->NotifyCallback != OpcUa_Null)
            {
                tcpConnection->NotifyCallback(
                    a_pConnection,                      /* source of event  */
                    tcpConnection->CallbackData,        /* callback data    */
                    OpcUa_ConnectionEvent_Disconnect,   /* the event type   */
                    OpcUa_Null,                         /* the stream       */
                    OpcUa_Good);                        /* the statuscode   */
            }
            else
            {
                /* Notify requested but no callback supplied. */
                uStatus = OpcUa_BadInvalidArgument;
            }
        }
    }
    else
    {
        OPCUA_P_MUTEX_UNLOCK(tcpConnection->ReadMutex);
        return OpcUa_BadInvalidState;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_BeginReceiveResponse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_BeginReceiveResponse(
    OpcUa_Connection*   a_pConnection,
    OpcUa_InputStream** a_ppInputStream)
{
    OpcUa_WssConnection*    tcpConnection   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "BeginReceiveResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_ppInputStream);
    OpcUa_ReturnErrorIfInvalidConnection(a_pConnection);

    tcpConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    /* need to reinitialize the IncomingStreamData structure as required */
    uStatus = OpcUa_WssStream_CreateInput( 
        tcpConnection->Socket,
        (tcpConnection->ReceiveBufferSize==(OpcUa_UInt32)0)?(OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize:tcpConnection->ReceiveBufferSize,
        OpcUa_WssConnection_StreamState_Created,
        a_ppInputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    tcpConnection->IncomingStream = *a_ppInputStream;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_BeginSendMessage
 *===========================================================================*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_WssConnection_BeginSendRequest(
    OpcUa_Connection*    a_pConnection,
    OpcUa_OutputStream** a_ppOutputStream)
{
    OpcUa_WssConnection* pWssConnection = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "BeginSendRequest");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_ppOutputStream);

    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);

#if OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM

    if(pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connected)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionClosed);
    }

    /* create an tcp output stream based on the tcpConnection */
    uStatus = OpcUa_WssStream_CreateOutput( 
        pWssConnection->Socket,
        OpcUa_WssStream_MessageType_SecureChannel,
        OpcUa_Null,
        pWssConnection->SendBufferSize,
        OpcUa_WssConnection_ConnectionDisconnectCB,
        pWssConnection->MaxChunkCount,
        pWssConnection->StreamState,
        a_ppOutputStream);

    if(OpcUa_IsBad(uStatus))
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        OpcUa_GotoErrorWithStatus(uStatus);
    }

#else

    if(pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connected)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionClosed);
    }

    /* reuse outgoing stream */
    if(pWssConnection->OutgoingStream == OpcUa_Null)
    {
        if(pWssConnection->bOutgoingStreamIsUsed != OpcUa_False)
        {
            OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssConnection_BeginSendRequest: Used outstream detected!\n");
            OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidState);
        }

        /* create an tcp output stream based on the tcpConnection */
        uStatus = OpcUa_WssStream_CreateOutput( pWssConnection->Socket,
                                                OpcUa_WssStream_MessageType_SecureChannel,
                                                OpcUa_Null,
                                                pWssConnection->SendBufferSize,
                                                OpcUa_WssConnection_ConnectionDisconnectCB,
                                                pWssConnection->MaxChunkCount,
                                                a_ppOutputStream);

        if(OpcUa_IsBad(uStatus))
        {
            OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
            OpcUa_GotoErrorWithStatus(uStatus);
        }

        pWssConnection->OutgoingStream = *a_ppOutputStream;
    }
    else
    {
        *a_ppOutputStream = pWssConnection->OutgoingStream;
    }

    pWssConnection->bOutgoingStreamIsUsed = OpcUa_True;

#endif

    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

#if OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM
    OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppOutputStream);
#endif

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_EndSendMessage
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_EndSendRequest(OpcUa_Connection*               a_pConnection,
                                                    OpcUa_OutputStream**            a_ppOutputStream,
                                                    OpcUa_UInt32                    a_uTimeout,
                                                    OpcUa_Connection_PfnOnResponse* a_pfnCallback,
                                                    OpcUa_Void*                     a_pCallbackData)
{
    OpcUa_WssConnection*    pWssConnection   = OpcUa_Null;
    OpcUa_WssOutputStream*  pWssOutputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "EndSendRequest");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_ppOutputStream);
    OpcUa_ReturnErrorIfArgumentNull(*a_ppOutputStream);

    OpcUa_ReturnErrorIfInvalidConnection(a_pConnection);

    /* not supported at this layer */
    OpcUa_ReferenceParameter(a_uTimeout);
    OpcUa_ReferenceParameter(a_pfnCallback);
    OpcUa_ReferenceParameter(a_pCallbackData);

    /* cast onto the backend types */
    pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssConnection);

    pWssOutputStream = (OpcUa_WssOutputStream*)(*a_ppOutputStream)->Handle;
    OpcUa_GotoErrorIfArgumentNull(pWssOutputStream);

#if OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM

    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
    if(pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connected)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

        /* clean up stream resources */
        (*a_ppOutputStream)->Delete((OpcUa_Stream**)a_ppOutputStream);

        return OpcUa_BadConnectionClosed;
    }
    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

    /* close and flush stream */
    uStatus = (*a_ppOutputStream)->Close((OpcUa_Stream*)(*a_ppOutputStream));
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssConnection_EndSendRequest: close failed! 0x%08X \n", uStatus);
    }

    /* clean up stream resources */
    (*a_ppOutputStream)->Delete((OpcUa_Stream**)a_ppOutputStream);

#else

    OPCUA_P_MUTEX_LOCK(pWssConnection->ReadMutex);
    /* check for consistency */
    if(     pWssConnection->OutgoingStream == OpcUa_Null
        ||  pWssConnection->bOutgoingStreamIsUsed == OpcUa_False)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssConnection_EndSendRequest: no outgoing stream\n");
        OpcUa_GotoError;
    }

    if(pWssConnection->ConnectionState != OpcUa_WssConnectionState_Connected)
    {
        /* mark stream as available */
        pWssConnection->bOutgoingStreamIsUsed = OpcUa_False;

        OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

        /* unlink up stream resources */
        *a_ppOutputStream = OpcUa_Null;

        return OpcUa_BadConnectionClosed;
    }

    /* close and flush stream */
    uStatus = (*a_ppOutputStream)->Flush(   (OpcUa_OutputStream*)(*a_ppOutputStream),
                                            OpcUa_True);
    if(OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssConnection_EndSendRequest: close failed! 0x%08X \n", uStatus);
    }

    /* TODO: check if it is needed to reset stream buffer state! */

    /* mark stream as available */
    pWssConnection->bOutgoingStreamIsUsed = OpcUa_False;

    /* unlink up stream resources */
    *a_ppOutputStream = OpcUa_Null;

    OPCUA_P_MUTEX_UNLOCK(pWssConnection->ReadMutex);

#endif

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_AbortSendRequest
 *===========================================================================*/
/* INFO: null streams are allowed and say that the owner of the connection
         takes care about the stream itself. Only if non null the tcp transport
         generates a abort message. this is not handled by the ua stack because
         abort messages are always secured. */
OpcUa_StatusCode OpcUa_WssConnection_AbortSendRequest(  OpcUa_Connection*    a_pConnection,
                                                        OpcUa_StatusCode     a_uStatus,
                                                        OpcUa_String*        a_psReason,
                                                        OpcUa_OutputStream** a_ppOutputStream)
{
    OpcUa_WssConnection*    tcpConnection  = OpcUa_Null;
    OpcUa_WssOutputStream*   tcpOutputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "AbortSendRequest");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfInvalidConnection(a_pConnection);

    /* cast onto the backend types */
    tcpConnection = (OpcUa_WssConnection*)a_pConnection->Handle;
    OpcUa_GotoErrorIfArgumentNull(tcpConnection);

#if OPCUA_TCPCONNECTION_DELETE_REQUEST_STREAM

    if(a_ppOutputStream != OpcUa_Null && *a_ppOutputStream != OpcUa_Null)
    {
        tcpOutputStream = (OpcUa_WssOutputStream*)(*a_ppOutputStream)->Handle;
        OpcUa_GotoErrorIfArgumentNull(tcpOutputStream);

        /* clean up */
        OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppOutputStream);
    }
    else
    {
        /* no insecure abort messages implemented and allowed! */
        OpcUa_ReferenceParameter(a_uStatus);
        OpcUa_ReferenceParameter(a_psReason);
    }

#else

    OPCUA_P_MUTEX_LOCK(tcpConnection->ReadMutex);

    /* clean outgoing stream */
    if(tcpConnection->bOutgoingStreamIsUsed != OpcUa_False)
    {
        tcpConnection->bOutgoingStreamIsUsed = OpcUa_False;
    }
    else
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssConnection_AbortSendRequest: no active stream detected!\n");
    }

    if(a_ppOutputStream != OpcUa_Null)
    {
        tcpOutputStream = (OpcUa_WssOutputStream*)(*a_ppOutputStream)->Handle;
        OpcUa_GotoErrorIfArgumentNull(tcpOutputStream);

        /* TODO: reset stream buffer state! */

        a_ppOutputStream = OpcUa_Null;
    }
    else
    {
        /* no insecure abort messages implemented and allowed! */
        OpcUa_ReferenceParameter(a_uStatus);
        OpcUa_ReferenceParameter(a_psReason);
    }

    OPCUA_P_MUTEX_UNLOCK(tcpConnection->ReadMutex);

#endif
OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 OpcUa_WssConnection_GetReceiveBufferSize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_GetReceiveBufferSize(  OpcUa_Connection*   a_pConnection,
                                                            OpcUa_UInt32*       a_pBufferSize)
{
    OpcUa_WssConnection* tcpConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "GetReceiveBufferSize");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pBufferSize);

    *a_pBufferSize = tcpConnection->ReceiveBufferSize;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_AddToSendQueue
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_AddToSendQueue(  OpcUa_Connection* a_pConnection,
                                                      OpcUa_BufferList* a_pBufferList,
                                                      OpcUa_UInt32      a_uFlags)
{
    OpcUa_WssConnection* pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "AddToSendQueue");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReferenceParameter(a_uFlags);

    if(pWssConnection->pSendQueue == OpcUa_Null)
    {
        pWssConnection->pSendQueue = a_pBufferList;
    }
    else
    {
        OpcUa_BufferList* pLastEntry = pWssConnection->pSendQueue;
        while(pLastEntry->pNext != OpcUa_Null)
        {
            pLastEntry = pLastEntry->pNext;
        }
        pLastEntry->pNext = a_pBufferList;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_CheckProtocolVersion
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_CheckProtocolVersion(OpcUa_Connection* a_pConnection,
                                                          OpcUa_UInt32      a_uProtocolVersion)
{
    OpcUa_WssConnection* pWssConnection = (OpcUa_WssConnection*)a_pConnection->Handle;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "CheckProtocolVersion");

    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);

    if(a_uProtocolVersion != pWssConnection->uProtocolVersion)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadProtocolVersionUnsupported);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssConnection_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_WssConnection_Delete(OpcUa_Connection** a_ppConnection)
{
    OpcUa_WssConnection*    tcpConnection       = OpcUa_Null;

    if(a_ppConnection == OpcUa_Null)
    {
        return;
    }

    if(*a_ppConnection == OpcUa_Null)
    {
        return;
    }

    tcpConnection = (OpcUa_WssConnection*)(*a_ppConnection)->Handle;
    if(tcpConnection == OpcUa_Null)
    {
        return;
    }

    /* this is a call potentially called in a thread outside the receive thread, lock the connection */
#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_LOCK(tcpConnection->ReadMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */
    if(tcpConnection->ConnectionState != OpcUa_WssConnectionState_Disconnected)
    {
        /* blind close without error checking */
        OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssConnection_Delete: Rude disconnect!\n");
        tcpConnection->ConnectionState = OpcUa_WssConnectionState_Disconnected;
        OPCUA_P_SOCKET_CLOSE(tcpConnection->Socket);
        tcpConnection->Socket = OpcUa_Null;
    }

#if OPCUA_MULTITHREADED

    OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssConnection_Delete: Stopping communication.\n");

#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_UNLOCK(tcpConnection->ReadMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* HINT: waits internally for receive thread to shutdown, so this call may block. */
    if(tcpConnection->SocketManager != OpcUa_Null)
    {
        OPCUA_P_SOCKETMANAGER_DELETE(&(tcpConnection->SocketManager));
    }
#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_LOCK(tcpConnection->ReadMutex);
#endif /* OPCUA_USE_SYNCHRONISATION */

    OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssConnection_Delete: Communication stopped.\n");

#endif /* OPCUA_MULTITHREADED */

    OpcUa_String_Clear(&tcpConnection->sURL);

    /* the architecture should prevent from getting here with active streams */
    if(tcpConnection->IncomingStream != OpcUa_Null)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssConnection_Delete: INVALID STATE! Active Streams! Internal Error!\n");
        tcpConnection->IncomingStream->Close((OpcUa_Stream*)tcpConnection->IncomingStream);
        tcpConnection->IncomingStream->Delete((OpcUa_Stream**)&tcpConnection->IncomingStream);
    }

    while(tcpConnection->pSendQueue != OpcUa_Null)
    {
        OpcUa_BufferList* pCurrentBuffer = tcpConnection->pSendQueue;
        tcpConnection->pSendQueue = pCurrentBuffer->pNext;
        OpcUa_Buffer_Clear(&pCurrentBuffer->Buffer);
        OpcUa_Free(pCurrentBuffer);
    }

    if (tcpConnection->sWebSocketKey != OpcUa_Null)
    {
        OpcUa_Free(tcpConnection->sWebSocketKey);
        tcpConnection->sWebSocketKey = OpcUa_Null;
    }

    /*** Free ***/
    /* clean internal ressources */
#if OPCUA_USE_SYNCHRONISATION
    OPCUA_P_MUTEX_UNLOCK(tcpConnection->ReadMutex);
    OPCUA_P_MUTEX_DELETE(&(tcpConnection->ReadMutex));
#endif /* OPCUA_USE_SYNCHRONISATION */

    /* the connection implementation */
    OpcUa_Free(tcpConnection);

    /* the wrapper element */
    OpcUa_Free(*a_ppConnection);
    *a_ppConnection = OpcUa_Null;
}

/*============================================================================
 * OpcUa_WssConnection_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssConnection_Create(
    OpcUa_ByteString*                a_pClientCertificate,
    OpcUa_ByteString*                a_pClientPrivateKey,
    OpcUa_Void*                      a_pPKIConfig, 
    OpcUa_Socket_CertificateCallback a_pfnCertificateValidation,
    OpcUa_Void*                      a_pCertificateValidationCallbackData,
    OpcUa_Connection**               a_ppConnection)
{
    OpcUa_WssConnection*    pWssConnection   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssConnection, "Create");

    OpcUa_ReturnErrorIfArgumentNull(a_ppConnection);
    *a_ppConnection = OpcUa_Null;

    /* allocate handle that stores internal state information */
    pWssConnection = (OpcUa_WssConnection*)OpcUa_Alloc(sizeof(OpcUa_WssConnection));
    OpcUa_ReturnErrorIfAllocFailed(pWssConnection);

    /* initialize with null */
    OpcUa_MemSet(pWssConnection, 0, sizeof(OpcUa_WssConnection));

    /* Todo: move from OpcUa_Connection! */
#if OPCUA_MULTITHREADED
    pWssConnection->SocketManager        = 0;
#endif /* OPCUA_MULTITHREADED */

    pWssConnection->SanityCheck          = OpcUa_WssConnection_SanityCheck;

    pWssConnection->uProtocolVersion     = 0;
    pWssConnection->SendBufferSize       = OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize;
    pWssConnection->ReceiveBufferSize    = OpcUa_ProxyStub_g_Configuration.iTcpConnection_DefaultChunkSize;
    pWssConnection->MaxMessageSize       = OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxMessageLength;
    pWssConnection->MaxChunkCount        = OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxChunkCount;
    pWssConnection->uCurrentChunk        = 0;
    pWssConnection->StreamState               = OpcUa_WssConnection_StreamState_TlsUpgrade;

    pWssConnection->pClientCertificate = a_pClientCertificate;
    pWssConnection->pClientPrivateKey = a_pClientPrivateKey;
    pWssConnection->pPKIConfig = a_pPKIConfig;
    pWssConnection->pfnCertificateValidation = a_pfnCertificateValidation;
    pWssConnection->pCertificateValidationCallbackData = a_pCertificateValidationCallbackData;

    pWssConnection->ConnectionState      = OpcUa_WssConnectionState_Disconnected;

    uStatus = OPCUA_P_MUTEX_CREATE(&(pWssConnection->ReadMutex));
    OpcUa_ReturnErrorIfBad(uStatus);

    OpcUa_String_Initialize(&pWssConnection->sURL);

    /* allocate external connection object */
    *a_ppConnection = (OpcUa_Connection*)OpcUa_Alloc(sizeof(OpcUa_Connection));
    OpcUa_GotoErrorIfAllocFailed(*a_ppConnection);
    OpcUa_MemSet(*a_ppConnection, 0, sizeof(OpcUa_Connection));

#if OPCUA_MULTITHREADED
    /* create the socket manager */
    uStatus = OPCUA_P_SOCKETMANAGER_CREATE( &(pWssConnection->SocketManager),
                                            1,
                                            OPCUA_SOCKET_NO_FLAG);

    OpcUa_GotoErrorIfBad(uStatus);
#endif /* OPCUA_MULTITHREADED */

    (*a_ppConnection)->Handle               = pWssConnection;
    (*a_ppConnection)->Connect              = OpcUa_WssConnection_Connect;
    (*a_ppConnection)->Disconnect           = OpcUa_WssConnection_Disconnect;
    (*a_ppConnection)->BeginSendRequest     = OpcUa_WssConnection_BeginSendRequest;
    (*a_ppConnection)->EndSendRequest       = OpcUa_WssConnection_EndSendRequest;
    (*a_ppConnection)->AbortSendRequest     = OpcUa_WssConnection_AbortSendRequest;
    (*a_ppConnection)->GetReceiveBufferSize = OpcUa_WssConnection_GetReceiveBufferSize;
    (*a_ppConnection)->Delete               = OpcUa_WssConnection_Delete;
    (*a_ppConnection)->AddToSendQueue       = OpcUa_WssConnection_AddToSendQueue;
    (*a_ppConnection)->CheckProtocolVersion = OpcUa_WssConnection_CheckProtocolVersion;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OPCUA_P_MUTEX_DELETE(&(pWssConnection->ReadMutex));
    OpcUa_Free(pWssConnection);

    if(a_ppConnection)
    {
        OpcUa_Free(*a_ppConnection);
        *a_ppConnection = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_CLIENTAPI */
