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

#include <opcua.h>

#ifdef OPCUA_HAVE_SERVERAPI

#include <opcua_mutex.h>
#include <opcua_string.h>
#include <opcua_datetime.h>
#include <opcua_socket.h>
#include <opcua_statuscodes.h>
#include <opcua_list.h>
#include <opcua_utilities.h>
#include <opcua_cryptofactory.h>
#include <opcua_base64.h>

#include <opcua_p_openssl.h>

#include <opcua_wssstream.h>
#include <opcua_binaryencoder.h>

#include <opcua_wsslistener.h>

typedef struct _OpcUa_WssListener OpcUa_WssListener;

#include <opcua_wsslistener_connectionmanager.h>

/* for debugging reasons */
#include <opcua_p_binary.h>
#include <opcua_memorystream.h>

#include <stdlib.h>
#include <ctype.h>
#include <openssl/ssl.h>

extern OpcUa_Guid OpcUa_Guid_Null;

/*============================================================================
 * Prototypes
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_Open(
    struct _OpcUa_Listener*         a_Listener,
    OpcUa_String*                   a_Url,
    OpcUa_Boolean                   a_bListenOnAllInterfaces,
    OpcUa_Listener_PfnOnNotify*     a_Callback,
    OpcUa_Void*                     a_CallbackData);

OpcUa_StatusCode OpcUa_WssListener_Close(
    OpcUa_Listener*                 a_Listener);

OpcUa_StatusCode OpcUa_WssListener_BeginSendResponse(
    OpcUa_Listener*                 a_Listener,
    OpcUa_Handle                    a_pConnection,
    OpcUa_InputStream**             a_istrm,
    OpcUa_OutputStream**            a_ostrm);

OpcUa_StatusCode OpcUa_WssListener_EndSendResponse(
    struct _OpcUa_Listener*         a_Listener,
    OpcUa_StatusCode                a_uStatus,
    OpcUa_OutputStream**            a_ostrm);

OpcUa_StatusCode OpcUa_WssListener_AbortSendResponse(
    struct _OpcUa_Listener*         a_Listener,
    OpcUa_StatusCode                a_uStatus,
    OpcUa_String*                   a_psReason,
    OpcUa_OutputStream**            a_ostrm);

OpcUa_StatusCode OpcUa_WssListener_CloseConnection(
    struct _OpcUa_Listener*         a_pListener,
    OpcUa_Handle                    a_hConnection,
    OpcUa_StatusCode                a_uStatus);

OpcUa_StatusCode OpcUa_WssListener_ProcessDisconnect(
    OpcUa_Listener*                 a_pListener,
    OpcUa_WssListener_Connection*   a_pWssConnection);

static OpcUa_StatusCode OpcUa_WssListener_SendErrorMessage(
    OpcUa_Listener*                 a_pListener,
    OpcUa_WssListener_Connection*   a_pWssConnection,
    OpcUa_StatusCode                a_uStatus,
    OpcUa_String*                   a_sReason);

OpcUa_StatusCode OpcUa_WssListener_GetReceiveBufferSize(
    OpcUa_Listener*                 a_pListener,
    OpcUa_Handle                    a_hConnection,
    OpcUa_UInt32*                   a_pBufferSize);

OpcUa_StatusCode OpcUa_WssListener_GetPeerInfo(
    OpcUa_Listener*                 a_pListener,
    OpcUa_Handle                    a_hConnection,
    OpcUa_String*                   a_sPeerInfo);

OpcUa_StatusCode OpcUa_WssListener_AddToSendQueue(
    OpcUa_Listener*                 a_pListener,
    OpcUa_Handle                    a_hConnection,
    OpcUa_BufferList*               a_pBufferList,
    OpcUa_UInt32                    a_uFlags);

OpcUa_StatusCode OpcUa_WssListener_CheckProtocolVersion(
    OpcUa_Listener*                 a_pListener,
    OpcUa_Handle                    a_hConnection,
    OpcUa_UInt32                    a_uProtocolVersion);

/*============================================================================
 * OpcUa_WssListener_SanityCheck
 *===========================================================================*/
#define OpcUa_WssListener_SanityCheck 0xE339EF96

/*============================================================================
 * OpcUa_WssListener
 *===========================================================================*/
 /** @brief This struct represents a listener for tcp transport. */
struct _OpcUa_WssListener
{
/* This is inherited from the OpcUa_Listener. */

    /** @brief The base class. */
    OpcUa_Listener              Base;

/* End inherited from the OpcUa_Listener. */

    /** @brief Internal control value. */
    OpcUa_UInt32                SanityCheck;
    /** @brief Synchronize access to the listener. */
    OpcUa_Mutex                 Mutex;
    /** @brief The listen socket (either part of the global or the own socket list). */
    OpcUa_Socket                Socket;
#if OPCUA_MULTITHREADED
    /** @brief In multithreaded environments, each listener manages its own list of sockets. */
    OpcUa_SocketManager         SocketManager;
#endif /* OPCUA_MULTITHREADED */
    /** @brief The function which receives notifications about listener events. */
    OpcUa_Listener_PfnOnNotify* Callback;
    /** @brief Data passed with the callback function. */
    OpcUa_Void*                 CallbackData;
    /** @brief The default message chunk size for communicating with this listener. */
    OpcUa_UInt32                DefaultChunkSize;
    /** @brief This list contains all pending requests, which are not fully received
     *  yet. Once a request is completely received, it gets dispatched to the
     *  upper layer. */
    OpcUa_List*                 PendingMessages;
    /** @brief Holds the information about connected clients and helps verifying requests. */
    OpcUa_WssListener_ConnectionManager* ConnectionManager;

    /** @brief Certificate used for SSL/TLS connections. */
    OpcUa_ByteString* pCertificate;
    /** @brief Private key used for SSL/TLS connections.*/
    OpcUa_Key* pPrivateKey;
    /** @brief PKI configuration for SSL/TLS connections. */
    OpcUa_Void* pPKIConfig;
};


/*============================================================================
 * OpcUa_WssListener_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_WssListener_Delete(OpcUa_Listener** a_ppListener)
{
    OpcUa_WssListener* pWssListener = OpcUa_Null;
    OpcUa_InputStream* pInputStream = OpcUa_Null;

    if (a_ppListener == OpcUa_Null || *a_ppListener == OpcUa_Null)
    {
        return;
    }

    pWssListener = (OpcUa_WssListener*)(*a_ppListener)->Handle;

    if (pWssListener != OpcUa_Null)
    {
        OPCUA_P_MUTEX_LOCK(pWssListener->Mutex);
        pWssListener->SanityCheck = 0;

        /* delete all pending messages */
        OpcUa_List_Enter(pWssListener->PendingMessages);
        OpcUa_List_ResetCurrent(pWssListener->PendingMessages);
        pInputStream = (OpcUa_InputStream *)OpcUa_List_GetCurrentElement(pWssListener->PendingMessages);
        while(pInputStream != OpcUa_Null)
        {
            OpcUa_List_DeleteCurrentElement(pWssListener->PendingMessages);
            pInputStream->Close((OpcUa_Stream*)pInputStream);
            pInputStream->Delete((OpcUa_Stream**)&pInputStream);
            pInputStream = (OpcUa_InputStream *)OpcUa_List_GetCurrentElement(pWssListener->PendingMessages);
        }
        OpcUa_List_Leave(pWssListener->PendingMessages);
        OpcUa_List_Delete(&(pWssListener->PendingMessages));

        OpcUa_WssListener_ConnectionManager_Delete(&(pWssListener->ConnectionManager));

        OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);
        OPCUA_P_MUTEX_DELETE(&(pWssListener->Mutex));

        OpcUa_Free(pWssListener);
    }

    *a_ppListener = OpcUa_Null;
}

/*============================================================================
 * OpcUa_WssListener_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_Create(
    OpcUa_ByteString*                           a_pServerCertificate,
    OpcUa_Key*                                  a_pServerPrivateKey,
    OpcUa_Void*                                 a_pPKIConfig,
    OpcUa_WssListener_PfnSecureChannelCallback* a_pfSecureChannelCallback,
    OpcUa_Void*                                 a_pSecureChannelCallbackData,
    OpcUa_Listener**                            a_pListener)
{
    OpcUa_WssListener*  pWssListener = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "Create");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);

    /* allocate listener object */
    *a_pListener = (OpcUa_Listener*)OpcUa_Alloc(sizeof(OpcUa_WssListener));
    OpcUa_GotoErrorIfAllocFailed(*a_pListener);
    OpcUa_MemSet(*a_pListener, 0, sizeof(OpcUa_WssListener));
    pWssListener = (OpcUa_WssListener*)*a_pListener;

    /* initialize listener pWssListener */
    pWssListener->SanityCheck = OpcUa_WssListener_SanityCheck;
    pWssListener->DefaultChunkSize = OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize;

    uStatus = OPCUA_P_MUTEX_CREATE(&(pWssListener->Mutex));
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_List_Create(&(pWssListener->PendingMessages));
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_WssListener_ConnectionManager_Create(&(pWssListener->ConnectionManager));
    OpcUa_GotoErrorIfBad(uStatus);
    pWssListener->ConnectionManager->Listener = *a_pListener;

    /* security credentials */
    pWssListener->pCertificate = a_pServerCertificate;
    pWssListener->pPrivateKey = a_pServerPrivateKey;
    pWssListener->pPKIConfig = a_pPKIConfig;

    /* HINT: socket and socket list get managed in open/close */

    /* initialize listener object */
    (*a_pListener)->Handle                  = pWssListener;
    (*a_pListener)->Open                    = OpcUa_WssListener_Open;
    (*a_pListener)->Close                   = OpcUa_WssListener_Close;
    (*a_pListener)->BeginSendResponse       = OpcUa_WssListener_BeginSendResponse;
    (*a_pListener)->EndSendResponse         = OpcUa_WssListener_EndSendResponse;
    (*a_pListener)->AbortSendResponse       = OpcUa_WssListener_AbortSendResponse;
    (*a_pListener)->CloseConnection         = OpcUa_WssListener_CloseConnection;
    (*a_pListener)->GetReceiveBufferSize    = OpcUa_WssListener_GetReceiveBufferSize;
    (*a_pListener)->Delete                  = OpcUa_WssListener_Delete;
    (*a_pListener)->AddToSendQueue          = OpcUa_WssListener_AddToSendQueue;
    (*a_pListener)->GetPeerInfo             = OpcUa_WssListener_GetPeerInfo;
    (*a_pListener)->CheckProtocolVersion    = OpcUa_WssListener_CheckProtocolVersion;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (*a_pListener != OpcUa_Null)
    {
        OpcUa_WssListener_ConnectionManager_Delete(&(pWssListener->ConnectionManager));
        OpcUa_List_Delete(&(pWssListener->PendingMessages));
        OPCUA_P_MUTEX_DELETE(&(pWssListener->Mutex));
        OpcUa_Free(*a_pListener);
        *a_pListener = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_GetReceiveBufferSize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_GetReceiveBufferSize(OpcUa_Listener*     a_pListener,
                                                        OpcUa_Handle        a_hConnection,
                                                        OpcUa_UInt32*       a_pBufferSize)
{
    OpcUa_WssListener_Connection* pWssListenerConnection = (OpcUa_WssListener_Connection*)a_hConnection;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "GetReceiveBufferSize");

    OpcUa_ReturnErrorIfArgumentNull(a_hConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pBufferSize);

    OpcUa_ReferenceParameter(a_pListener);

    *a_pBufferSize = pWssListenerConnection->ReceiveBufferSize;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_GetPeerInfo
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_GetPeerInfo(OpcUa_Listener*     a_pListener,
                                               OpcUa_Handle        a_hConnection,
                                               OpcUa_String*       a_pPeerInfo)
{
    OpcUa_WssListener_Connection* pWssListenerConnection = (OpcUa_WssListener_Connection*)a_hConnection;
    /* return peer information in format "opc.tcp://xxx.xxx.xxx.xxx:ppppp\0" => max length == 32 */
    /* return peer information in format "opc.tcp://1234:5678:1234:5678:1234:5678:1234:5678:ppppp\0" => max length == 56 */
    OpcUa_CharA pRawString[64];

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "GetPeerInfo");

    OpcUa_ReferenceParameter(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pPeerInfo);

    OpcUa_SPrintfA( pRawString,
#if OPCUA_USE_SAFE_FUNCTIONS
                    (sizeof(pRawString) / sizeof(pRawString[0])),
#endif /* OPCUA_USE_SAFE_FUNCTIONS */
#if OPCUA_P_SOCKETGETPEERINFO_V2
                    "opc.tcp://%s",
                    pWssListenerConnection->achPeerInfo);
#else
                    "opc.tcp://%u.%u.%u.%u:%u",
                    (pWssListenerConnection->PeerIp >> 24) & 0xFF,
                    (pWssListenerConnection->PeerIp >> 16) & 0xFF,
                    (pWssListenerConnection->PeerIp >> 8) & 0xFF,
                    pWssListenerConnection->PeerIp & 0xFF,
                    pWssListenerConnection->PeerPort);
#endif

    uStatus = OpcUa_String_StrnCpy( a_pPeerInfo,
                                    OpcUa_String_FromCString(pRawString),
                                    OPCUA_STRING_LENDONTCARE);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_AddToSendQueue
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_AddToSendQueue(OpcUa_Listener*   a_pListener,
                                                  OpcUa_Handle      a_hConnection,
                                                  OpcUa_BufferList* a_pBufferList,
                                                  OpcUa_UInt32      a_uFlags)
{
    OpcUa_WssListener_Connection* pWssListenerConnection = (OpcUa_WssListener_Connection*)a_hConnection;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "AddToSendQueue");

    OpcUa_ReturnErrorIfArgumentNull(a_hConnection);
    OpcUa_ReferenceParameter(a_pListener);

    if (pWssListenerConnection->pSendQueue == OpcUa_Null)
    {
        pWssListenerConnection->pSendQueue = a_pBufferList;
    }
    else
    {
        OpcUa_BufferList* pLastEntry = pWssListenerConnection->pSendQueue;
        while(pLastEntry->pNext != OpcUa_Null)
        {
            pLastEntry = pLastEntry->pNext;
        }
        pLastEntry->pNext = a_pBufferList;
    }

    if (a_uFlags & OPCUA_LISTENER_CLOSE_WHEN_DONE)
    {
        pWssListenerConnection->bCloseWhenDone = OpcUa_True;
    }

    if (a_uFlags & OPCUA_LISTENER_NO_RCV_UNTIL_DONE)
    {
        pWssListenerConnection->bNoRcvUntilDone = OpcUa_True;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_CheckProtocolVersion
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_CheckProtocolVersion(OpcUa_Listener*   a_pListener,
                                                        OpcUa_Handle      a_hConnection,
                                                        OpcUa_UInt32      a_uProtocolVersion)
{
    OpcUa_WssListener_Connection* pWssListenerConnection = (OpcUa_WssListener_Connection*)a_hConnection;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "CheckProtocolVersion");

    OpcUa_ReturnErrorIfArgumentNull(a_hConnection);
    OpcUa_ReferenceParameter(a_pListener);

    if (a_uProtocolVersion != pWssListenerConnection->uProtocolVersion)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadProtocolVersionUnsupported);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_CloseConnection
 *===========================================================================*/
/** @brief Close a particular connection of this listener. */
OpcUa_StatusCode OpcUa_WssListener_CloseConnection( OpcUa_Listener*     a_pListener,
                                                    OpcUa_Handle        a_hConnection,
                                                    OpcUa_StatusCode    a_uStatus)
{
    OpcUa_WssListener_Connection*   pWssListenerConnection  = (OpcUa_WssListener_Connection*)a_hConnection;
    OpcUa_WssListener*              pWssListener            = (OpcUa_WssListener*)a_pListener->Handle;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "CloseConnection");

    OpcUa_ReturnErrorIfArgumentNull(a_hConnection);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssListener_CloseConnection: Connection %p is being closed! 0x%08X\n", a_hConnection, a_uStatus);

    if (OpcUa_IsBad(a_uStatus) && a_uStatus != OpcUa_BadDisconnect)
    {
        uStatus = OpcUa_WssListener_SendErrorMessage(   a_pListener,
                                                        pWssListenerConnection,
                                                        a_uStatus,
                                                        OpcUa_Null);
    }

    if (pWssListenerConnection->pSendQueue != OpcUa_Null)
    {
        pWssListenerConnection->bCloseWhenDone = OpcUa_True;
        OpcUa_ReturnStatusCode;
    }

    uStatus = OpcUa_WssListener_ConnectionManager_RemoveConnection( pWssListener->ConnectionManager,
                                                                    (OpcUa_WssListener_Connection*)a_hConnection);

    if (OpcUa_IsGood(uStatus))
    {
        uStatus = OPCUA_P_SOCKET_CLOSE(pWssListenerConnection->Socket);
        OpcUa_WssListener_Connection_Delete(&pWssListenerConnection);
    }
    else
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssListener_CloseConnection: Error 0x%08X removing connection %p! \n", a_uStatus, a_hConnection);
    }


OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_ConnectionDisconnectCB
 *===========================================================================*/
/** @brief Gets called by an outstream if the connection is lost. */
static OpcUa_Void OpcUa_WssListener_ConnectionDisconnectCB(OpcUa_Handle a_hConnection)
{
    OpcUa_Listener*                 pListener               = OpcUa_Null;
    OpcUa_WssListener_Connection*   pWssListenerConnection  = (OpcUa_WssListener_Connection*)a_hConnection;

    OpcUa_ReferenceParameter(pWssListenerConnection);
    OpcUa_ReferenceParameter(pListener);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssListener_ConnectionDisconnectCB: Connection %p is being reported as disconnected!\n", a_hConnection);
}

/*============================================================================
 * OpcUa_WssListener_BeginSendResponse
 *===========================================================================*/
/* prepare a response (out) stream for a certain connection and related to   */
/* a certain request (in) stream                                             */

OpcUa_StatusCode OpcUa_WssListener_BeginSendResponse(
    OpcUa_Listener*                 a_pListener,
    OpcUa_Handle                    a_pConnection,
    OpcUa_InputStream**             a_ppTransportIStrm,
    OpcUa_OutputStream**            a_ppOstrm)
{
    OpcUa_WssListener_Connection* pWssListenerConnection  = (OpcUa_WssListener_Connection*)a_pConnection;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "BeginSendResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_ppTransportIStrm);
    OpcUa_ReturnErrorIfArgumentNull(a_ppOstrm);

    OpcUa_ReturnErrorIfArgumentNull(a_pListener->BeginSendResponse);

    /* initialize outparameter */
    *a_ppOstrm = OpcUa_Null;

    /* close and delete the incoming stream - double close is ignored (uncritical) */
    (*a_ppTransportIStrm)->Close((OpcUa_Stream*)(*a_ppTransportIStrm));
    (*a_ppTransportIStrm)->Delete((OpcUa_Stream**)a_ppTransportIStrm);

    /* create buffer for writing */
    uStatus = OpcUa_WssStream_CreateOutput(
        pWssListenerConnection->Socket,            /* create stream on that socket */
        OpcUa_WssStream_MessageType_SecureChannel, /* initialize as chunk */
        OpcUa_Null,                                /* no buffer to attach */
        pWssListenerConnection->SendBufferSize,    /* flush border size */
        OpcUa_WssListener_ConnectionDisconnectCB,  /* function to call, if stream detects disconnect */
        pWssListenerConnection->MaxChunkCount,     /* maximum number of chunks allowed */
        pWssListenerConnection->eState,
        a_ppOstrm);                                /* use that handle */

    OpcUa_ReturnErrorIfBad(uStatus);

    ((OpcUa_WssOutputStream*)((*a_ppOstrm)->Handle))->hConnection = a_pConnection;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * Send an Error message.
 *===========================================================================*/
static OpcUa_StatusCode OpcUa_WssListener_SendErrorMessage( 
    OpcUa_Listener*                 a_pListener,
    OpcUa_WssListener_Connection*   a_pWssConnection,
    OpcUa_StatusCode                a_uStatus,
    OpcUa_String*                   a_sReason)
{
    OpcUa_WssListener*      pWssListener        = OpcUa_Null;
    OpcUa_OutputStream*     pOutputStream       = OpcUa_Null;
    OpcUa_String            sReason             = OPCUA_STRING_STATICINITIALIZER;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "SendErrorMessage");

    OpcUa_GotoErrorIfArgumentNull(a_pListener);
    OpcUa_GotoErrorIfArgumentNull(a_pWssConnection);

    pWssListener = (OpcUa_WssListener*)a_pListener;

    if (a_pWssConnection->bConnected == OpcUa_False)
    {
        OpcUa_ReturnStatusCode;
    }

#if OPCUA_P_SOCKETGETPEERINFO_V2
    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM,
                "OpcUa_WssListener_SendErrorMessage: to %s (socket %p) with StatusCode 0x%08X\n",
                a_pWssConnection->achPeerInfo,
                a_pWssConnection->Socket,
                a_uStatus);
#else
    OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM,
                "OpcUa_WssListener_SendErrorMessage: to %d.%d.%d.%d:%d (socket %p) with StatusCode 0x%08X\n",
                (OpcUa_Int)(a_pWssConnection->PeerIp>>24)&0xFF,
                (OpcUa_Int)(a_pWssConnection->PeerIp>>16)&0xFF,
                (OpcUa_Int)(a_pWssConnection->PeerIp>>8) &0xFF,
                (OpcUa_Int) a_pWssConnection->PeerIp     &0xFF,
                a_pWssConnection->PeerPort,
                a_pWssConnection->Socket,
                a_uStatus);
#endif

    /* create the output stream for the errormessage */
    uStatus = OpcUa_WssStream_CreateOutput( 
        a_pWssConnection->Socket,
        OpcUa_WssStream_MessageType_Error,
        OpcUa_Null,
        pWssListener->DefaultChunkSize,
        OpcUa_WssListener_ConnectionDisconnectCB,
        a_pWssConnection->MaxChunkCount,
        a_pWssConnection->eState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    /* encode the body of an Error message */

    /* status code */
    uStatus = OpcUa_UInt32_BinaryEncode(a_uStatus, pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_String_BinaryEncode(a_sReason?a_sReason:&sReason, pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    if (a_pWssConnection->pSendQueue == OpcUa_Null)
    {
        uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);
    }

    if (a_pWssConnection->pSendQueue != OpcUa_Null || OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer      Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);
        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;
        if (pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }
        if (a_pWssConnection->pSendQueue != OpcUa_Null)
        {
            pBufferList->Buffer.EndOfData = pBufferList->Buffer.Position;
            pBufferList->Buffer.Position  = 0;
        }
        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData,
                     Buffer.Data, Buffer.EndOfData);
        uStatus = OpcUa_Listener_AddToSendQueue(
            a_pListener,
            a_pWssConnection,
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

    if ((pOutputStream != OpcUa_Null) && (pOutputStream->Delete != OpcUa_Null))
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_EndSendResponse
 *===========================================================================*/
/* a bad status means, that the operation is to be abandoned */
OpcUa_StatusCode OpcUa_WssListener_EndSendResponse(
    struct _OpcUa_Listener* a_pListener,
    OpcUa_StatusCode        a_uStatus,
    OpcUa_OutputStream**    a_ppOstrm)
{
OpcUa_InitializeStatus(OpcUa_Module_WssListener, "OpcUa_WssListener_EndSendResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_ppOstrm);
    OpcUa_ReturnErrorIfArgumentNull(*a_ppOstrm);

    OpcUa_ReturnErrorIfArgumentNull(a_pListener->EndSendResponse);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_EndSendResponse: Status 0x%08X\n", a_uStatus);

    /* trigger error message */
    if (OpcUa_IsGood(a_uStatus))
    {
        /* close stream (flushes the Content on the wire). */
        uStatus = (*a_ppOstrm)->Close((OpcUa_Stream*)*a_ppOstrm);
    }

    /* delete without flushing and decrement request count */
    OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppOstrm);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_AbortSendResponse
 *===========================================================================*/
/* a bad status means, that the operation is to be abandoned */
OpcUa_StatusCode OpcUa_WssListener_AbortSendResponse(
    struct _OpcUa_Listener* a_pListener,
    OpcUa_StatusCode        a_uStatus,
    OpcUa_String*           a_psReason,
    OpcUa_OutputStream**    a_ppOutputStream)
{
OpcUa_InitializeStatus(OpcUa_Module_WssListener, "OpcUa_WssListener_AbortSendResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);

    OpcUa_ReturnErrorIfArgumentNull(a_pListener->AbortSendResponse);

    if (a_ppOutputStream != OpcUa_Null)
    {
        /* clean up */
        OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppOutputStream);
    }
    else
    {
        /* no insecure abort messages implemented and allowed! */
        OpcUa_ReferenceParameter(a_uStatus);
        OpcUa_ReferenceParameter(a_psReason);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_LookForPendingMessage
 *===========================================================================*/
/* should be handled by the connection manager, since no interleaving is possible by design! */
OpcUa_StatusCode OpcUa_WssListener_LookForPendingMessage(   OpcUa_WssListener*  a_pWssListener,
                                                            OpcUa_Socket        a_pSocket,
                                                            OpcUa_InputStream** a_pInputStream)
{
    OpcUa_InputStream*      pInputStream    = OpcUa_Null;
    OpcUa_WssInputStream*   pWssInputStream = OpcUa_Null;

    OpcUa_DeclareErrorTraceModule(OpcUa_Module_WssListener);

    OpcUa_ReturnErrorIfArgumentNull(a_pWssListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);
    OpcUa_ReturnErrorIfArgumentNull(a_pInputStream);

    OpcUa_List_Enter(a_pWssListener->PendingMessages);

    *a_pInputStream = OpcUa_Null;

    OpcUa_List_ResetCurrent(a_pWssListener->PendingMessages);
    pInputStream = (OpcUa_InputStream*)OpcUa_List_GetCurrentElement(a_pWssListener->PendingMessages);

    while(pInputStream != OpcUa_Null)
    {
        pWssInputStream = (OpcUa_WssInputStream *)pInputStream->Handle;

        if (pWssInputStream != OpcUa_Null && pWssInputStream->Socket == a_pSocket)
        {
            /* found */
            OpcUa_List_DeleteElement(a_pWssListener->PendingMessages, (OpcUa_Void*)pInputStream);
            *a_pInputStream = pInputStream;
            OpcUa_List_Leave(a_pWssListener->PendingMessages);
            return OpcUa_Good;
        }
        else
        {
            /* get next element */
            pInputStream = (OpcUa_InputStream*)OpcUa_List_GetNextElement(a_pWssListener->PendingMessages);
        }
    }

    OpcUa_List_Leave(a_pWssListener->PendingMessages);

    return OpcUa_BadNotFound;
}

/*============================================================================
 * OpcUa_WssListener_ProcessRequest
 *===========================================================================*/
/**
* @brief Handles a UATM (Request), UATC (Request Chunk) message.
*/
OpcUa_StatusCode OpcUa_WssListener_ProcessRequest(
    OpcUa_Listener*                 a_pListener,
    OpcUa_WssListener_Connection*   a_pWssConnection,
    OpcUa_InputStream**             a_ppInputStream)
{
    OpcUa_WssListener*      pWssListener    = OpcUa_Null;
    OpcUa_WssInputStream*   pWssInputStream = OpcUa_Null;
    OpcUa_ListenerEvent     eEvent          = OpcUa_ListenerEvent_Invalid;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ProcessRequest");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_ppInputStream);
    OpcUa_ReturnErrorIfArgumentNull(*a_ppInputStream);

    pWssListener     = (OpcUa_WssListener*)a_pListener->Handle;
    pWssInputStream  = (OpcUa_WssInputStream*)(*a_ppInputStream)->Handle;

    if (pWssInputStream->IsAbort != OpcUa_False)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_INFO, "OpcUa_WssListener_ProcessRequest: Message aborted after %u received chunks while %u are allowed!\n", a_pWssConnection->uCurrentChunk, a_pWssConnection->MaxChunkCount);
        eEvent = OpcUa_ListenerEvent_RequestAbort;
        a_pWssConnection->uCurrentChunk = 0;
    }
    else
    {
        if (pWssInputStream->IsFinal != OpcUa_False)
        {
            /* last chunk in message, reset counter */
            eEvent = OpcUa_ListenerEvent_Request;
            a_pWssConnection->uCurrentChunk = 0;
        }
        else
        {
            /* intermediary chunk, test for limit and increment */
            a_pWssConnection->uCurrentChunk++;
            eEvent = OpcUa_ListenerEvent_RequestPartial;
            if ((a_pWssConnection->MaxChunkCount != 0) && (a_pWssConnection->uCurrentChunk >= a_pWssConnection->MaxChunkCount))
            {
                /* this message will be too large */
                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssListener_ProcessRequest: Chunk count limit exceeded!\n");
                eEvent = OpcUa_ListenerEvent_Request;  /* message final */
                uStatus = OpcUa_BadTcpMessageTooLarge; /* with error */
            }
        }
    }

    if (OpcUa_IsGood(uStatus))
    {
        /* send notification that request is ready to be read. */
        /* this call goes most probably to the secure channel handler. */
        if (pWssListener->Callback != OpcUa_Null)
        {
            a_pWssConnection->uNoOfRequestsTotal++;

            uStatus = pWssListener->Callback(
                a_pListener,                            /* the event source          */
                (OpcUa_Void*)pWssListener->CallbackData,/* the callback data         */
                eEvent,                                 /* the event type            */
                (OpcUa_Handle)a_pWssConnection,         /* handle for the connection */
                a_ppInputStream,                        /* the ready input stream    */
                OpcUa_Good);                            /* event status code         */
        }
        else
        {
            /* delete and close input stream */
            OpcUa_WssStream_Close((OpcUa_Stream*)(*a_ppInputStream));
            OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppInputStream);
        }
    }
    else
    {
        /* an error occured - inform the owner of this listener */

        /* delete and close input stream immediately */
        OpcUa_WssStream_Close((OpcUa_Stream*)(*a_ppInputStream));
        OpcUa_WssStream_Delete((OpcUa_Stream**)a_ppInputStream);

        if (pWssListener->Callback != OpcUa_Null)
        {
            a_pWssConnection->uNoOfRequestsTotal++;

            uStatus = pWssListener->Callback(
                a_pListener,                            /* the event source          */
                (OpcUa_Void*)pWssListener->CallbackData,/* the callback data         */
                eEvent,
                (OpcUa_Handle)a_pWssConnection,         /* handle for the connection */
                OpcUa_Null,                             /* the ready input stream    */
                uStatus);                               /* event status code         */
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
} /* OpcUa_WssListener_ProcessRequest */

/*============================================================================
 * OpcUa_WssListener_SendAcknowledgeMessage
 *===========================================================================*/
/**
* @brief Handles the response to a hello message.
*/
OpcUa_StatusCode OpcUa_WssListener_SendAcknowledgeMessage(
    OpcUa_Listener*                 a_pListener,
    OpcUa_WssListener_Connection*   a_pWssConnection)
{
    OpcUa_OutputStream*     pOutputStream    = OpcUa_Null;
    OpcUa_UInt32            uProtocolVersion = 0;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "SendAcknowledgeMessage");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pWssConnection);

    uStatus = OpcUa_WssStream_CreateOutput( 
        a_pWssConnection->Socket,
        OpcUa_WssStream_MessageType_Acknowledge,
        OpcUa_Null,
        a_pWssConnection->SendBufferSize,
        OpcUa_WssListener_ConnectionDisconnectCB,
        a_pWssConnection->MaxChunkCount,
        a_pWssConnection->eState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    /* encode acknowledge fields */

    /* The latest version of the OPC UA TCP protocol supported by the Server */
    uStatus = OpcUa_UInt32_BinaryEncode(uProtocolVersion, pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* revised receivebuffer */
    uStatus = OpcUa_UInt32_BinaryEncode((a_pWssConnection->ReceiveBufferSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* revised sendbuffer */
    uStatus = OpcUa_UInt32_BinaryEncode((a_pWssConnection->SendBufferSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* send max message size */
    uStatus = OpcUa_UInt32_BinaryEncode((a_pWssConnection->MaxMessageSize), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    /* send max chunk count */
    uStatus = OpcUa_UInt32_BinaryEncode((a_pWssConnection->MaxChunkCount), pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);
    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer      Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);
        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;
        if (pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }
        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData,
                     Buffer.Data, Buffer.EndOfData);
        uStatus = OpcUa_Listener_AddToSendQueue(
            a_pListener,
            a_pWssConnection,
            pBufferList,
            OPCUA_LISTENER_NO_RCV_UNTIL_DONE);
        OpcUa_Buffer_Clear(&Buffer);
    }
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Close((OpcUa_Stream*)pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pOutputStream != OpcUa_Null)
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssListener_SendHttpUpgradeResponse
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssListener_SendHttpUpgradeResponse(
    OpcUa_Listener*               a_pListener,
    OpcUa_WssListener_Connection* a_pWssConnection,
    OpcUa_UInt16                  a_uHttpStatus,
    OpcUa_StringA                 a_sHttpReason,
    OpcUa_StringA                 a_sHttpHeaders)
{
    OpcUa_OutputStream* pOutputStream = OpcUa_Null;
    OpcUa_WssOutputStream* pWssOutputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "SendHttpUpgradeResponse");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pWssConnection);

    uStatus = OpcUa_WssStream_CreateOutput( 
        a_pWssConnection->Socket,
        OpcUa_WssStream_MessageType_HttpUpgradeResponse,
        OpcUa_Null,
        a_pWssConnection->SendBufferSize,
        OpcUa_WssListener_ConnectionDisconnectCB,
        a_pWssConnection->MaxChunkCount,
        a_pWssConnection->eState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    pWssOutputStream = (OpcUa_WssOutputStream*)pOutputStream;

    if (a_sHttpHeaders != OpcUa_Null && *a_sHttpHeaders != '\0')
    {
        OpcUa_SPrintfA(pWssOutputStream->Buffer.Data, pWssOutputStream->Buffer.Size, "HTTP/1.1 %u %s\r\nServer: OPC-ANSI-C-WSS-API\r\nContent-Length: 0\r\n%s\r\n", a_uHttpStatus, a_sHttpReason, a_sHttpHeaders);
    }
    else
    {
        OpcUa_SPrintfA(pWssOutputStream->Buffer.Data, pWssOutputStream->Buffer.Size, "HTTP/1.1 %u %s\r\nServer: OPC-ANSI-C-WSS-API\r\nContent-Length: 0\r\n\r\n", a_uHttpStatus, a_sHttpReason);
    }

    pOutputStream->SetPosition(pOutputStream, OpcUa_StrLenA(pWssOutputStream->Buffer.Data));

    uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);

    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);
        
        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        
        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;

        if (pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }
        
        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData, Buffer.Data, Buffer.EndOfData);

        uStatus = OpcUa_Listener_AddToSendQueue(
            a_pListener,
            a_pWssConnection,
            pBufferList,
            OPCUA_LISTENER_NO_RCV_UNTIL_DONE);
        
        OpcUa_Buffer_Clear(&Buffer);
    }

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Close((OpcUa_Stream*)pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pOutputStream != OpcUa_Null)
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssListener_CalculateAcceptKey
*===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_CalculateAcceptKey(
    OpcUa_StringA  a_sKey,
    OpcUa_StringA* a_pAcceptKey)
{
    OpcUa_StringA sAcceptKey = OpcUa_Null;
    OpcUa_UInt32 uDataLength = 0;
    OpcUa_UInt32 uKeyLength = 0;
    const OpcUa_CharA* sRfcMagicNumber = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    OpcUa_Byte pDigest[20];
    OpcUa_CryptoProvider* pCryptoProvider = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "CalculateAcceptKey");

    OpcUa_ReturnErrorIfArgumentNull(a_sKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pAcceptKey);

    *a_pAcceptKey = OpcUa_Null;

    for (uKeyLength = 0; a_sKey[uKeyLength] != '\r' && a_sKey[uKeyLength] != '\0'; uKeyLength++);

    uDataLength = uKeyLength;
    uDataLength += OpcUa_StrLenA(sRfcMagicNumber);

    sAcceptKey = (OpcUa_Byte*)OpcUa_Alloc(uDataLength);
    OpcUa_GotoErrorIfAllocFailed(sAcceptKey);

    OpcUa_MemCpy(sAcceptKey, uDataLength, a_sKey, uKeyLength);
    OpcUa_MemCpy((OpcUa_Byte*)(sAcceptKey + uKeyLength), uDataLength - uKeyLength, (OpcUa_Void*)sRfcMagicNumber, OpcUa_StrLenA(sRfcMagicNumber));

    pCryptoProvider = (OpcUa_CryptoProvider*)OpcUa_Alloc(sizeof(OpcUa_CryptoProvider));
    OpcUa_GotoErrorIfAllocFailed(pCryptoProvider);

    uStatus = OPCUA_P_CRYPTOFACTORY_CREATECRYPTOPROVIDER(OpcUa_SecurityPolicy_Basic128Rsa15, pCryptoProvider);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_P_OpenSSL_SHA1_Generate(pCryptoProvider, sAcceptKey, uDataLength, pDigest);
    OpcUa_GotoErrorIfBad(uStatus);

    OPCUA_P_CRYPTOFACTORY_DELETECRYPTOPROVIDER(pCryptoProvider);
    OpcUa_Free(pCryptoProvider);
    pCryptoProvider = OpcUa_Null;

    OpcUa_Free(sAcceptKey);
    sAcceptKey = OpcUa_Null;

    uStatus = OpcUa_Base64_Encode(pDigest, 20, &sAcceptKey);
    OpcUa_GotoErrorIfBad(uStatus);

    *a_pAcceptKey = sAcceptKey;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pCryptoProvider != OpcUa_Null)
    {
        OPCUA_P_CRYPTOFACTORY_DELETECRYPTOPROVIDER(pCryptoProvider);
        OpcUa_Free(pCryptoProvider);
        pCryptoProvider = OpcUa_Null;
    }

    if (sAcceptKey != OpcUa_Null)
    {
        OpcUa_Free(sAcceptKey);
        sAcceptKey = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

#define OPCUA_HTTP_STATUSCODE_SWITCHING_PROTOCOLS 101
#define OPCUA_HTTP_REASON_SWITCHING_PROTOCOLS "Switching Protocols"

#define OPCUA_HTTP_STATUSCODE_METHOD_NOT_ALLOWED 405
#define OPCUA_HTTP_REASON_METHOD_NOT_ALLOWED "Method Not Allowed"

#define OPCUA_HTTP_STATUSCODE_BAD_REQUEST 400
#define OPCUA_HTTP_REASON_BAD_REQUEST "Bad Request"

#define OPCUA_HTTP_STATUSCODE_NOT_FOUND 404
#define OPCUA_HTTP_REASON_NOT_FOUND "Not Found"

#define HTTP_VERSION "HTTP/1.1"
#define CONNECTION_HEADER "Connection:"
#define CONNECTION_UPGRADE "Upgrade"
#define UPGRADE_HEADER "Upgrade:"
#define UPGRADE_WEBSOCKET "WebSocket"
#define WEBSOCKET_VERSION_HEADER "Sec-WebSocket-Version:"
#define WEBSOCKET_VERSION_DEFAULT "13"
#define WEBSOCKET_KEY_HEADER "Sec-WebSocket-Key:"
#define WEBSOCKET_PROTOCOL_HEADER "Sec-WebSocket-Protocol:"
#define WEBSOCKET_PROTOCOL_UATCP "opcua+uatcp"
#define ORIGIN_HEADER "Origin:"
#define ALLOW_ORIGIN_HEADER "Access-Control-Allow-Origin:"
#define MAX_HEADER_LENGTH 256

/*============================================================================
* OpcUa_StatusCode OpcUa_WssListener_ProcessHttpUpgrade
*===========================================================================*/
static OpcUa_StatusCode OpcUa_WssListener_ProcessHttpUpgrade(
    OpcUa_Listener*               a_pListener,
    OpcUa_WssListener_Connection* a_pConnection,
    OpcUa_InputStream*            a_pInputStream)
{
    OpcUa_WssListener* pWssListener = OpcUa_Null;
    OpcUa_WssInputStream* pWssInputStream = OpcUa_Null;
    OpcUa_StringA sHeader = OpcUa_Null;
    OpcUa_StringA sAcceptKey = OpcUa_Null;
    OpcUa_UInt16 uHttpStatusCode = OPCUA_HTTP_STATUSCODE_SWITCHING_PROTOCOLS;
    OpcUa_StringA sHttpReason = OPCUA_HTTP_REASON_SWITCHING_PROTOCOLS;
    OpcUa_CharA sOrigin[MAX_HEADER_LENGTH];

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ProcessHttpUpgrade");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    pWssListener = (OpcUa_WssListener*)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pConnection);
    OpcUa_ReturnErrorIfArgumentNull(a_pInputStream);
    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssInputStream);
    
    *sOrigin = 0;

    /* the stream ensures this is a null terminated string */
    sHeader = pWssInputStream->Buffer.Data;
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "HTTP Upgrade Header: %s\n", sHeader);

    if (OpcUa_StrinCmpA("GET", sHeader, 3) != 0)
    {
        uHttpStatusCode = OPCUA_HTTP_STATUSCODE_METHOD_NOT_ALLOWED;
        sHttpReason = OPCUA_HTTP_REASON_METHOD_NOT_ALLOWED;
        OpcUa_GotoErrorWithStatus(OpcUa_BadHttpMethodNotAllowed);
    }
    
    sHeader += 4;
    while (isspace(*sHeader)) sHeader++;

    if (OpcUa_StrinCmpA("/", sHeader, 1) != 0)
    {
        uHttpStatusCode = OPCUA_HTTP_STATUSCODE_NOT_FOUND;
        sHttpReason = OPCUA_HTTP_REASON_NOT_FOUND;
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotFound);
    }

    sHeader += 1;
    while (isspace(*sHeader)) sHeader++;

    if (OpcUa_StrinCmpA(HTTP_VERSION, sHeader, OpcUa_StrLenA(HTTP_VERSION)) != 0)
    {
        uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
        sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
        OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
    }

    sHeader += 9;
    while (isspace(*sHeader)) sHeader++;

    OpcUa_Boolean bConnectionHeader = OpcUa_False;
    OpcUa_Boolean bUpgradeHeader = OpcUa_False;
    OpcUa_Boolean bVersionHeader = OpcUa_False;
    OpcUa_Boolean bProtocolHeader = OpcUa_False;

    while (*sHeader != '\0')
    {
        if (OpcUa_StrinCmpA(CONNECTION_HEADER, sHeader, OpcUa_StrLenA(CONNECTION_HEADER)) == 0)
        {
            OpcUa_Boolean bConnectionUpgrade = OpcUa_False;

            sHeader += OpcUa_StrLenA(CONNECTION_HEADER);
            while (isspace(*sHeader)) sHeader++;

            while (*sHeader != '\r')
            {
                if (OpcUa_StrinCmpA(CONNECTION_UPGRADE, sHeader, OpcUa_StrLenA(CONNECTION_UPGRADE)) == 0)
                {
                    bConnectionUpgrade = OpcUa_True;
                    break;
                }

                sHeader++;
            }     

            if (!bConnectionUpgrade)
            {
                uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
                sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
                OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
            }

            bConnectionHeader = OpcUa_True;
        }

        else if (OpcUa_StrinCmpA(UPGRADE_HEADER, sHeader, OpcUa_StrLenA(UPGRADE_HEADER)) == 0)
        {
            sHeader += OpcUa_StrLenA(UPGRADE_HEADER);
            while (isspace(*sHeader)) sHeader++;

            if (OpcUa_StrinCmpA(UPGRADE_WEBSOCKET, sHeader, OpcUa_StrLenA(UPGRADE_WEBSOCKET)) != 0)
            {
                uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
                sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
                OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
            }

            bUpgradeHeader = OpcUa_True;
        }

        else if (OpcUa_StrinCmpA(WEBSOCKET_VERSION_HEADER, sHeader, OpcUa_StrLenA(WEBSOCKET_VERSION_HEADER)) == 0)
        {
            sHeader += OpcUa_StrLenA(WEBSOCKET_VERSION_HEADER);
            while (isspace(*sHeader)) sHeader++;

            if (OpcUa_StrinCmpA(WEBSOCKET_VERSION_DEFAULT, sHeader, OpcUa_StrLenA(WEBSOCKET_VERSION_DEFAULT)) != 0)
            {
                uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
                sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
                OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
            }

            bVersionHeader = OpcUa_True;
        }        

        else if (OpcUa_StrinCmpA(WEBSOCKET_KEY_HEADER, sHeader, OpcUa_StrLenA(WEBSOCKET_KEY_HEADER)) == 0)
        {
            sHeader += OpcUa_StrLenA(WEBSOCKET_KEY_HEADER);
            while (isspace(*sHeader)) sHeader++;

            uStatus = OpcUa_WssListener_CalculateAcceptKey(sHeader, &sAcceptKey);
            OpcUa_GotoErrorIfBad(uStatus);
        }

        else if (OpcUa_StrinCmpA(WEBSOCKET_PROTOCOL_HEADER, sHeader, OpcUa_StrLenA(WEBSOCKET_PROTOCOL_HEADER)) == 0)
        {
            sHeader += OpcUa_StrLenA(WEBSOCKET_PROTOCOL_HEADER)+1;
            while (isspace(*sHeader)) sHeader++;

            if (OpcUa_StrinCmpA(WEBSOCKET_PROTOCOL_UATCP, sHeader, OpcUa_StrLenA(WEBSOCKET_PROTOCOL_UATCP)) != 0)
            {
                uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
                sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
                OpcUa_GotoErrorWithStatus(OpcUa_BadNotSupported);
            }

            bProtocolHeader = OpcUa_True;
        }

        else if (OpcUa_StrinCmpA(ORIGIN_HEADER, sHeader, OpcUa_StrLenA(ORIGIN_HEADER)) == 0)
        {
            OpcUa_CharA* sStart = OpcUa_Null;
            sHeader += OpcUa_StrLenA(ORIGIN_HEADER);
            while (isspace(*sHeader)) sHeader++;
            sStart = sHeader;
            while (!isspace(*sHeader)) sHeader++;
            OpcUa_StrnCpyA(sOrigin, MAX_HEADER_LENGTH, sStart, sHeader - sStart);
        }

        while (!isspace(*sHeader)) sHeader++;
        while (isspace(*sHeader)) sHeader++;
    }

    if (!bConnectionHeader || !bVersionHeader || !bUpgradeHeader)
    {
        uHttpStatusCode = OPCUA_HTTP_STATUSCODE_BAD_REQUEST;
        sHttpReason = OPCUA_HTTP_REASON_BAD_REQUEST;
        OpcUa_GotoErrorWithStatus(OpcUa_BadDecodingError);
    }

    OpcUa_SPrintfA(pWssInputStream->Buffer.Data, pWssInputStream->Buffer.Size, "Connection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Protocol: opcua+uatcp\r\nSec-WebSocket-Accept: %s\r\n", sAcceptKey);
    
    if (*sOrigin != 0)
    {
        OpcUa_StrnCatA(pWssInputStream->Buffer.Data, pWssInputStream->Buffer.Size, ALLOW_ORIGIN_HEADER, OpcUa_StrLenA(ALLOW_ORIGIN_HEADER));
        OpcUa_StrnCatA(pWssInputStream->Buffer.Data, pWssInputStream->Buffer.Size, " ", 1);
        OpcUa_StrnCatA(pWssInputStream->Buffer.Data, pWssInputStream->Buffer.Size, sOrigin, OpcUa_StrLenA(sOrigin));
        OpcUa_StrnCatA(pWssInputStream->Buffer.Data, pWssInputStream->Buffer.Size, "\r\n", 2);
    }

    OpcUa_WssListener_SendHttpUpgradeResponse(a_pListener, a_pConnection, 101, "Switching Protocols", pWssInputStream->Buffer.Data);
    a_pConnection->eState = OpcUa_WssConnection_StreamState_Open;

    OpcUa_Free(sAcceptKey);
    sAcceptKey = OpcUa_Null;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssListener_SendHttpUpgradeResponse(a_pListener, a_pConnection, uHttpStatusCode, sHttpReason, "Connection: Closed\r\n");

    if (sAcceptKey != OpcUa_Null)
    {
        OpcUa_Free(sAcceptKey);
        sAcceptKey = OpcUa_Null;
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssListener_SendPongMessage
*===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_SendPongMessage(
    OpcUa_Listener*               a_pListener,
    OpcUa_WssListener_Connection* a_pWssConnection,
    OpcUa_InputStream*            a_pInputStream)
{
    OpcUa_OutputStream* pOutputStream = OpcUa_Null;
    OpcUa_WssInputStream* pWssInputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "SendPongMessage");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Handle);
    OpcUa_ReturnErrorIfArgumentNull(a_pWssConnection);

    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;

    uStatus = OpcUa_WssStream_CreateOutput( 
        a_pWssConnection->Socket,
        OpcUa_WssStream_MessageType_WsPong,
        OpcUa_Null,
        a_pWssConnection->SendBufferSize,
        OpcUa_WssListener_ConnectionDisconnectCB,
        a_pWssConnection->MaxChunkCount,
        a_pWssConnection->eState,
        &pOutputStream);

    OpcUa_GotoErrorIfBad(uStatus);

    /* copy input to output */
    uStatus = pOutputStream->Write(
        pOutputStream, 
        pWssInputStream->Buffer.Data + pWssInputStream->Buffer.Position, 
        pWssInputStream->Buffer.EndOfData - pWssInputStream->Buffer.Position);

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Flush(pOutputStream, OpcUa_True);

    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
    {
        OpcUa_Buffer Buffer;
        OpcUa_BufferList* pBufferList = OpcUa_Alloc(sizeof(OpcUa_BufferList));
        OpcUa_GotoErrorIfAllocFailed(pBufferList);
        uStatus = pOutputStream->DetachBuffer((OpcUa_Stream*)pOutputStream, &Buffer);
        
        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_Free(pBufferList);
            OpcUa_GotoError;
        }
        
        pBufferList->Buffer = Buffer;
        pBufferList->Buffer.Data = OpcUa_Alloc(pBufferList->Buffer.Size);
        pBufferList->Buffer.FreeBuffer = OpcUa_True;
        pBufferList->pNext = OpcUa_Null;

        if (pBufferList->Buffer.Data == OpcUa_Null)
        {
            OpcUa_Free(pBufferList);
            OpcUa_Buffer_Clear(&Buffer);
            OpcUa_GotoErrorWithStatus(OpcUa_BadOutOfMemory);
        }

        OpcUa_MemCpy(pBufferList->Buffer.Data, pBufferList->Buffer.EndOfData, Buffer.Data, Buffer.EndOfData);
        
        uStatus = OpcUa_Listener_AddToSendQueue(
            a_pListener,
            a_pWssConnection,
            pBufferList,
            OPCUA_LISTENER_NO_RCV_UNTIL_DONE);
        
        OpcUa_Buffer_Clear(&Buffer);
    }

    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = pOutputStream->Close((OpcUa_Stream*)pOutputStream);
    OpcUa_GotoErrorIfBad(uStatus);

    pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pOutputStream != OpcUa_Null)
    {
        pOutputStream->Delete((OpcUa_Stream**)&pOutputStream);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssListener_ProcessPingMessage
*===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_ProcessPingMessage(
    OpcUa_Listener*               a_pListener,
    OpcUa_WssListener_Connection* a_pConnection,
    OpcUa_InputStream*            a_pInputStream)
{
    OpcUa_WssListener* pWssListener = OpcUa_Null;
    OpcUa_WssInputStream* pWssInputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ProcessPingMessage");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    pWssListener = (OpcUa_WssListener*)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pInputStream);
    pWssInputStream = (OpcUa_WssInputStream*)a_pInputStream->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssInputStream);

    uStatus = OpcUa_WssListener_SendPongMessage(a_pListener, a_pConnection, a_pInputStream);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_ProcessHelloMessage
 *===========================================================================*/
/**
 * @brief Handles a Hello message.
 *
 * @param pListener      The listener that hosts the socket from which the message is being received.
 * @param istrm          The stream containing the UAMH.
 */
OpcUa_StatusCode OpcUa_WssListener_ProcessHelloMessage(
    OpcUa_Listener*                 a_pListener,
    OpcUa_InputStream*              a_istrm)
{
    OpcUa_WssListener*              pWssListener    = OpcUa_Null;
    OpcUa_WssInputStream*           pWssInputStream = OpcUa_Null;
    OpcUa_WssListener_Connection*   pConnection     = OpcUa_Null;
#if OPCUA_TCPLISTENER_USEEXTRAMAXCONNSOCKET
    OpcUa_UInt32                    uConnections    = 0;
#endif

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ProcessHelloMessage");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    pWssListener = (OpcUa_WssListener*)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);
    OpcUa_ReturnErrorIfArgumentNull(a_istrm);
    pWssInputStream = (OpcUa_WssInputStream*)a_istrm->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssInputStream);

    /* check, if there is already a connection with this object */
    OpcUa_WssListener_ConnectionManager_GetConnectionBySocket( 
        pWssListener->ConnectionManager,
        pWssInputStream->Socket,
        &pConnection);

    /* if no connection exists create a new one */
    if (pConnection == OpcUa_Null)
    {
        return(OpcUa_BadUnexpectedError);
    }

    /* protocol version */
    uStatus = OpcUa_UInt32_BinaryDecode(&pConnection->uProtocolVersion, a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* requested send buffer size (this is the receive buffer in the server) */
    uStatus = OpcUa_UInt32_BinaryDecode(&(pConnection->ReceiveBufferSize), a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* requested receive buffer size (this is the send buffer in the server) */
    uStatus = OpcUa_UInt32_BinaryDecode(&(pConnection->SendBufferSize), a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* requested max message size */
    uStatus = OpcUa_UInt32_BinaryDecode(&(pConnection->MaxMessageSize), a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* requested max chunk count */
    uStatus = OpcUa_UInt32_BinaryDecode(&(pConnection->MaxChunkCount), a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* requested receive buffer size (this is the send buffer in the server) */
    uStatus = OpcUa_String_BinaryDecode(&(pConnection->sURL), 4096, a_istrm);
    OpcUa_GotoErrorIfBad(uStatus);

    /* parsing finished */
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "Requested: PV:%u SB:%u RB:%u MMS:%u MCC:%u\n",
        pConnection->uProtocolVersion,
        pConnection->SendBufferSize,
        pConnection->ReceiveBufferSize,
        pConnection->MaxMessageSize,
        pConnection->MaxChunkCount);

    pConnection->SendBufferSize     = (pConnection->SendBufferSize    > (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize)?(OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize:pConnection->SendBufferSize;
    pConnection->ReceiveBufferSize  = (pConnection->ReceiveBufferSize > (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize)?(OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize:pConnection->ReceiveBufferSize;

    /* This value shall be greater than 8 192 bytes */
    if (pConnection->SendBufferSize <= 8192)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);
    }

    /* This value shall be greater than 8 192 bytes */
    if (pConnection->ReceiveBufferSize <= 8192)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadConnectionRejected);
    }

    if (     pConnection->MaxMessageSize  == 0
        ||  pConnection->MaxMessageSize  >  (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxMessageLength)
    {
        pConnection->MaxMessageSize = (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxMessageLength;
    }

    if (     pConnection->MaxChunkCount  == 0
        ||  pConnection->MaxChunkCount  >  (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxChunkCount)
    {
        pConnection->MaxChunkCount = (OpcUa_UInt32)OpcUa_ProxyStub_g_Configuration.iTcpTransport_MaxChunkCount;
    }

    OpcUa_Trace(
        OPCUA_TRACE_LEVEL_DEBUG, 
        "Set:            SB:%u RB:%u MMS:%u MCC:%u\n",
        pConnection->SendBufferSize,
        pConnection->ReceiveBufferSize,
        pConnection->MaxMessageSize,
        pConnection->MaxChunkCount);

    pConnection->bConnected = OpcUa_True;

#if OPCUA_TCPLISTENER_USEEXTRAMAXCONNSOCKET
    OpcUa_WssListener_ConnectionManager_GetConnectionCount(pWssListener->ConnectionManager,
                                                           &uConnections);

    if (uConnections >= OPCUA_TCPLISTENER_MAXCONNECTIONS)
    {
        uStatus = OpcUa_WssListener_CloseConnection(a_pListener,
                                                    pConnection,
                                                    OpcUa_BadMaxConnectionsReached);
        OpcUa_ReturnStatusCode;
    }
#endif /* OPCUA_TCPLISTENER_USEEXTRAMAXCONNSOCKET */

    /* the request is verified and an acknowledge can be sent to the new client */
    OpcUa_WssListener_SendAcknowledgeMessage(a_pListener, pConnection);

    pWssListener->Callback( a_pListener,                        /* the source of the event          */
                            pWssListener->CallbackData,         /* the callback data                */
                            OpcUa_ListenerEvent_ChannelOpened,  /* the event that occured           */
                            (OpcUa_Handle)pConnection,          /* the handle for the connection    */
                            OpcUa_Null,                         /* the non existing stream          */
                            OpcUa_Good);                        /* status                           */

    OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pConnection);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pConnection != OpcUa_Null)
    {
        /* ignore result; it doesnt matter, if it was not yet registered */
        OpcUa_WssListener_ConnectionManager_RemoveConnection(pWssListener->ConnectionManager, pConnection);
        OpcUa_WssListener_Connection_Delete(&pConnection);
    }
    else
    {
        OPCUA_P_SOCKET_CLOSE(pWssInputStream->Socket);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_EventHandler Type
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_ProcessDisconnect(   OpcUa_Listener*                 a_pListener,
                                                        OpcUa_WssListener_Connection*   a_pWssConnection)
{
    OpcUa_WssListener* pWssListener = (OpcUa_WssListener*)a_pListener;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ProcessDisconnect");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pWssConnection);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ProcessDisconnect: Connection with socket %p reported as lost!\n", a_pWssConnection->Socket);

    OPCUA_P_MUTEX_LOCK(a_pWssConnection->Mutex);

    if (a_pWssConnection->bConnected == OpcUa_False)
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ProcessDisconnect: Client connection %p with socket %p already set to disconnected!\n", a_pWssConnection, a_pWssConnection->Socket);
        uStatus = OpcUa_Good;
        OPCUA_P_MUTEX_UNLOCK(a_pWssConnection->Mutex);
        OpcUa_ReturnStatusCode;
    }

    /* now, that the upper layers are informed, we can safely remove the resources for the broken connection. */
    uStatus = OpcUa_WssListener_ConnectionManager_RemoveConnection( pWssListener->ConnectionManager,
                                                                    a_pWssConnection);

    if (OpcUa_IsBad(uStatus))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ProcessDisconnect: Client connection %p with socket %p already removed!\n", a_pWssConnection, a_pWssConnection->Socket);
        uStatus = OpcUa_Good;
        OPCUA_P_MUTEX_UNLOCK(a_pWssConnection->Mutex);
        OpcUa_ReturnStatusCode;
    }

    a_pWssConnection->bConnected = OpcUa_False;
    a_pWssConnection->DisconnectTime = OPCUA_P_DATETIME_UTCNOW();

    if (a_pWssConnection->bCloseWhenDone == OpcUa_False)
    {
        /* notify about successful closing of the listener */
        pWssListener->Callback( a_pListener,                        /* the source of the event          */
                                pWssListener->CallbackData,         /* the callback data                */
                                OpcUa_ListenerEvent_ChannelClosed,  /* the event that occured           */
                                (OpcUa_Handle)a_pWssConnection,     /* the handle for the connection    */
                                OpcUa_Null,                         /* the non existing stream          */
                                OpcUa_Good);                        /* status                           */
    }

    OPCUA_P_MUTEX_UNLOCK(a_pWssConnection->Mutex);

    OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &a_pWssConnection);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_EventHandler Type
 *===========================================================================*/
/** @brief Internal handler prototype. */
typedef OpcUa_StatusCode (*OpcUa_WssListener_EventHandler)(
    OpcUa_Listener*  a_pListener,
    OpcUa_Socket     a_pSocket);

extern OpcUa_StatusCode OpcUa_Socket_TlsServerStartUpgrade(
    OpcUa_Socket      a_hSocket,
    OpcUa_ByteString* a_pServerCertificate,
    OpcUa_Key*        a_pServerPrivateKey,
    OpcUa_Void*       a_pPKIConfig);

extern OpcUa_StatusCode OpcUa_Socket_TlsServerContinueUpgrade(OpcUa_Socket a_pSocket);

/*============================================================================
* OpcUa_WssListener_AcceptEventHandler
*===========================================================================*/
/**
* @brief Gets called if remote node has connected to this socket.
*/
OpcUa_StatusCode OpcUa_WssListener_AcceptEventHandler(
    OpcUa_Listener* a_pListener,
    OpcUa_Socket    a_hSocket)
{
    OpcUa_WssListener* pWssListener = OpcUa_Null;
    OpcUa_WssListener_Connection*  pListenerConnection = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpListener, "AcceptEventHandler");

    OpcUa_ReturnErrorIfArgumentNull(a_hSocket);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pListener->Handle);

    pWssListener = (OpcUa_WssListener *)a_pListener->Handle;

    /* check, if there is already a connection with this object */
    OpcUa_WssListener_ConnectionManager_GetConnectionBySocket(
        pWssListener->ConnectionManager,
        a_hSocket,
        &pListenerConnection);

    /* if no connection exists create a new one */
    if (pListenerConnection == OpcUa_Null)
    {
        /* create and add a new connection object for the accepted connection  */
        uStatus = OpcUa_WssListener_Connection_Create(&pListenerConnection);
        OpcUa_GotoErrorIfBad(uStatus);

        pListenerConnection->Socket = a_hSocket;
        pListenerConnection->pListenerHandle = (OpcUa_Listener*)a_pListener;
        pListenerConnection->uLastReceiveTime = OpcUa_GetTickCount();
        pListenerConnection->eState = OpcUa_WssConnection_StreamState_TlsUpgrade;

        uStatus = OPCUA_P_SOCKET_GETPEERINFO(a_hSocket, (OpcUa_CharA*)&(pListenerConnection->achPeerInfo), OPCUA_P_PEERINFO_MIN_SIZE);

        if (OpcUa_IsGood(uStatus))
        {
            /* Give some debug information. */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_SYSTEM,
                "OpcUa_WssListener_AcceptEventHandler: Transport connection %p from %s accepted on socket %p!\n",
                pListenerConnection,
                pListenerConnection->achPeerInfo,
                pListenerConnection->Socket);
        }
        else
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssListener_AcceptEventHandler: Could not retrieve connection information for socket %p!\n", pListenerConnection->Socket);
        }

        uStatus = OpcUa_WssListener_ConnectionManager_AddConnection(pWssListener->ConnectionManager, pListenerConnection);
        OpcUa_GotoErrorIfBad(uStatus);

        if (pListenerConnection->eState == OpcUa_WssConnection_StreamState_TlsUpgrade)
        {
            uStatus = OpcUa_Socket_TlsServerStartUpgrade(
                a_hSocket,
                pWssListener->pCertificate,
                pWssListener->pPrivateKey,
                pWssListener->pPKIConfig);

            OpcUa_GotoErrorIfBad(uStatus);
        }
    }

    pListenerConnection->bConnected = OpcUa_True;

    pWssListener->Callback(
        a_pListener,                            /* the source of the event       */
        pWssListener->CallbackData,             /* the callback data             */
        OpcUa_ListenerEvent_ChannelOpened,      /* the event that occured        */
        (OpcUa_Handle)pListenerConnection,      /* the handle for the connection */
        OpcUa_Null,                             /* the non existing stream       */
        OpcUa_Good);                            /* status                        */

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pListenerConnection != OpcUa_Null)
    {
        /* ignore result; it doesnt matter, if it was not yet registered */
        OpcUa_WssListener_Connection_Delete(&pListenerConnection);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_ReadEventHandler
 *===========================================================================*/
/**
* @brief Gets called if data is available on the socket.
*/
OpcUa_StatusCode OpcUa_WssListener_ReadEventHandler(
    OpcUa_Listener* a_pListener,
    OpcUa_Socket    a_pSocket)
{
    OpcUa_WssListener*              pWssListener            = OpcUa_Null;
    OpcUa_WssListener_Connection*   pWssListenerConnection  = OpcUa_Null;
    OpcUa_InputStream*              pInputStream            = OpcUa_Null;
    OpcUa_WssInputStream*           pWssInputStream         = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "ReadEventHandler");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);
    pWssListener = (OpcUa_WssListener *)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);

    /******************************************************************************************************/

    /* look if an active connection is available for the socket. */
    uStatus = OpcUa_WssListener_ConnectionManager_GetConnectionBySocket(
        pWssListener->ConnectionManager,
        a_pSocket,
        &pWssListenerConnection);
    
    if (OpcUa_IsBad(uStatus) && OpcUa_IsNotEqual(OpcUa_BadNotFound))
    {
        OpcUa_GotoError;
    }

    /******************************************************************************************************/

    /* try to find started stream either in pWssListenerConnection or in floating messages list */
    if (pWssListenerConnection != OpcUa_Null)
    {
        /* A connection object exists for this socket. (Hello message was received and validated.) */
        if (pWssListenerConnection->bNoRcvUntilDone == OpcUa_True)
        {
            pWssListenerConnection->bRcvDataPending = OpcUa_True;
            OpcUa_ReturnStatusCode;
        }
        pInputStream = pWssListenerConnection->pInputStream;
        pWssListenerConnection->pInputStream = OpcUa_Null;
    }
    else
    {
        /* no connection object is available, so this is the first message (and most probably a hello message) */
        /* look if a pending hello message for this socket exists; the connection gets created after the hello message is validated */
        uStatus = OpcUa_WssListener_LookForPendingMessage(pWssListener, a_pSocket, &pInputStream);
        if (OpcUa_IsBad(uStatus) && OpcUa_IsNotEqual(OpcUa_BadNotFound))
        {
            /* something unexpected happened */
            OpcUa_GotoError;
        }
    }

    if (pWssListenerConnection->eState == OpcUa_WssConnection_StreamState_TlsUpgrade)
    {
        uStatus = OpcUa_Socket_TlsServerContinueUpgrade(a_pSocket);
        OpcUa_GotoErrorIfBad(uStatus);

        pWssListenerConnection->eState = OpcUa_WssConnection_StreamState_HttpUpgrade;
    }

    /******************************************************************************************************/

    /* create stream if no one was found */
    if (pInputStream == OpcUa_Null)
    {
        /* set the receiving buffer size to its default size */
        if (pWssListenerConnection != OpcUa_Null)
        {
            uStatus = OpcUa_WssStream_CreateInput(  
                a_pSocket,
                pWssListenerConnection->ReceiveBufferSize,
                pWssListenerConnection->eState,
                &pInputStream);

            OpcUa_ReturnErrorIfBad(uStatus);
        }
        else
        {            
            uStatus = OpcUa_WssStream_CreateInput( 
                a_pSocket,
                OpcUa_ProxyStub_g_Configuration.iTcpListener_DefaultChunkSize,
                OpcUa_WssConnection_StreamState_Created,
                &pInputStream);

            OpcUa_ReturnErrorIfBad(uStatus);
        }
    }

    /******************************************************************************************************/

    /* now, we have a stream -> read the available data; further processing takes place in the callback */
    uStatus = OpcUa_WssStream_DataReady(pInputStream);

    /******************************************************************************************************/

    if (OpcUa_IsEqual(OpcUa_GoodCallAgain))
    {
        /* prepare to append further data later */

        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: CallAgain result for stream %p on socket %p!\n", pInputStream, a_pSocket);

        if (pWssListenerConnection != 0)
        {
            /* if we reach this point, the message cannot be a uamh */
            pWssListenerConnection->pInputStream = pInputStream;
        }
        else
        {
            /* no pWssListenerConnection to append it, so store it in our temporary list; must be uamh */
            OpcUa_List_Enter(pWssListener->PendingMessages);
            uStatus = OpcUa_List_AddElement(pWssListener->PendingMessages, pInputStream);
            OpcUa_List_Leave(pWssListener->PendingMessages);
        }
    }
    else /* process message */
    {
        pWssInputStream = (OpcUa_WssInputStream*)pInputStream->Handle;

        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_CharA* sError = OpcUa_Null;

            /* Error happened... */
            switch(uStatus)
            {
            case OpcUa_BadDecodingError:
                {
                    sError = (OpcUa_CharA*)"OpcUa_BadDecodingError";
                    break;
                }
            case OpcUa_BadCommunicationError:
                {
                    sError = (OpcUa_CharA*)"OpcUa_BadCommunicationError";
                    break;
                }
            case OpcUa_BadDisconnect:
                {
                    sError = (OpcUa_CharA*)"OpcUa_BadDisconnect";
                    break;
                }
            case OpcUa_BadConnectionClosed:
                {
                    sError = (OpcUa_CharA*)"OpcUa_BadConnectionClosed";
                    break;
                }
            default:
                {
                    sError = (OpcUa_CharA*)"unmapped";
                }
            }

            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: socket %p; status 0x%08X (%s)\n", a_pSocket, uStatus, sError);

            OPCUA_P_SOCKET_CLOSE(a_pSocket);

            OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
            OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
            pWssListenerConnection->pInputStream = OpcUa_Null;

            if (pWssListenerConnection != OpcUa_Null)
            {
                /* Notify about connection loss. */
                OpcUa_WssListener_ProcessDisconnect(a_pListener, pWssListenerConnection);
                pWssListenerConnection = OpcUa_Null;
            }
        }
        else if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_HttpUpgrade)
        {
            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: MessageType HttpUpgrade\n");
            uStatus = OpcUa_WssListener_ProcessHttpUpgrade(a_pListener, pWssListenerConnection, pInputStream);
            OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
            OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);

            if (OpcUa_IsBad(uStatus))
            {
                OpcUa_WssListener_Connection_Delete(&pWssListenerConnection);
                pWssListenerConnection = OpcUa_Null;
            }
        }
        else /* Message can be processed. */
        {
            /* process message */
            switch(pWssInputStream->MessageType)
            {
            case OpcUa_WssStream_MessageType_WsPing:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: MessageType WebSocket PING\n");
                    uStatus = OpcUa_WssListener_ProcessPingMessage(a_pListener, pWssListenerConnection, pInputStream);
                    OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                    OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                    pWssListenerConnection->pInputStream = OpcUa_Null;
                    break;
                }
            case OpcUa_WssStream_MessageType_WsPong:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: MessageType WebSocket PONG\n");
                    OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                    OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                    pWssListenerConnection->pInputStream = OpcUa_Null;
                    break;
                }
            case OpcUa_WssStream_MessageType_Hello:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: MessageType HELLO\n");
                    uStatus = OpcUa_WssListener_ProcessHelloMessage(a_pListener, pInputStream);
                    OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                    OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                    pWssListenerConnection->pInputStream = OpcUa_Null;
                    break;
                }
            case OpcUa_WssStream_MessageType_SecureChannel:
                {
                    /* This is the standard message used during communication.  */
                    /* Abort is used here to rollback the data pipe up to the seclayer. */
                    /* Maybe we will need a own handler for this. */

                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: MessageType SecureChannel Message\n");

                    if (pWssListenerConnection != OpcUa_Null)
                    {
                        uStatus = OpcUa_WssListener_ProcessRequest( a_pListener,
                                                                    pWssListenerConnection,
                                                                    &pInputStream);

                        if (pInputStream != OpcUa_Null)
                        {
                            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssListener_ReadEventHandler: InputStream wasn't correctly released! Deleting it!\n");
                            OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                            OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                        }

                        if (OpcUa_IsBad(uStatus))
                        {
                            /* this is probably intended: mask trace to make it not look like an error */
                            if (OpcUa_IsNotEqual(OpcUa_BadDisconnect))
                            {
                                OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssListener_ReadEventHandler: Process Request returned an error (0x%08X)!\n", uStatus);
                            }
                        }
                    }
                    else
                    {
                        OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssListener_ReadEventHandler: Received request for nonexisting connection!\n");
                        OPCUA_P_SOCKET_CLOSE(pWssInputStream->Socket);
                        OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                        OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                        pWssListenerConnection->pInputStream = OpcUa_Null;
                    }

                    break;
                }
            default:
                {
                    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_ReadEventHandler: Invalid MessageType (%d)\n", pWssInputStream->MessageType);
                    OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
                    OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
                    pWssListenerConnection->pInputStream = OpcUa_Null;
                    break;
                }
            }
        }
    } /* if (OpcUa_IsEqual(OpcUa_GoodCallAgain)) */

    if (pWssListenerConnection != OpcUa_Null)
    {
        OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pWssListenerConnection != OpcUa_Null)
    {
        OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_TimeoutEventHandler
 *===========================================================================*/
/**
* @brief Gets called in case of a timeout on the socket.
*/
OpcUa_StatusCode OpcUa_WssListener_TimeoutEventHandler(
    OpcUa_Listener* a_pListener,
    OpcUa_Socket    a_pSocket)
{
    OpcUa_WssListener*              pWssListener            = OpcUa_Null;
    OpcUa_WssListener_Connection*   pWssListenerConnection  = OpcUa_Null;
    OpcUa_InputStream*              pInputStream            = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "TimeoutEventHandler");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);
    pWssListener = (OpcUa_WssListener *)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);

    /******************************************************************************************************/

    /* look if an active connection is available for the socket. */
    uStatus = OpcUa_WssListener_ConnectionManager_GetConnectionBySocket(
        pWssListener->ConnectionManager,
        a_pSocket,
        &pWssListenerConnection);

    if (OpcUa_IsBad(uStatus) && OpcUa_IsNotEqual(OpcUa_BadNotFound))
    {
        OpcUa_GotoError;
    }

    /******************************************************************************************************/

    /* try to find started stream either in pWssListenerConnection or in floating messages list */
    if (pWssListenerConnection != OpcUa_Null)
    {
        /* A connection object exists for this socket. (Hello message was received and validated.) */
        pInputStream = pWssListenerConnection->pInputStream;
        pWssListenerConnection->pInputStream = OpcUa_Null;
    }
    else
    {
        /* no connection object is available, so this is the first message (and most probably a hello message) */
        /* look if a pending hello message for this socket exists; the connection gets created after the hello message is validated */
        uStatus = OpcUa_WssListener_LookForPendingMessage(pWssListener, a_pSocket, &pInputStream);
        if (OpcUa_IsBad(uStatus) && OpcUa_IsNotEqual(OpcUa_BadNotFound))
        {
            /* something unexpected happened */
            OpcUa_GotoError;
        }
    }

    /******************************************************************************************************/

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssListener_TimeoutEventHandler: socket %p\n", a_pSocket);

    OPCUA_P_SOCKET_CLOSE(a_pSocket);

    if (pInputStream != OpcUa_Null)
    {
        OpcUa_WssStream_Close((OpcUa_Stream*)pInputStream);
        OpcUa_WssStream_Delete((OpcUa_Stream**)&pInputStream);
    }

    if (pWssListenerConnection != OpcUa_Null)
    {
        /* Notify about connection loss. */
        OpcUa_WssListener_ProcessDisconnect(a_pListener, pWssListenerConnection);
        OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pWssListenerConnection != OpcUa_Null)
    {
        OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);
    }

OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssListener_WriteEventHandler
 *===========================================================================*/
/**
* @brief Gets called if data can be written to the socket.
*/
OpcUa_StatusCode OpcUa_WssListener_WriteEventHandler(
    OpcUa_Listener* a_pListener,
    OpcUa_Socket    a_pSocket)
{
    OpcUa_WssListener*              pWssListener            = OpcUa_Null;
    OpcUa_WssListener_Connection*   pWssListenerConnection  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "WriteEventHandler");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_pSocket);
    pWssListener = (OpcUa_WssListener *)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);

    /******************************************************************************************************/

    /* look if an active connection is available for the socket. */
    uStatus = OpcUa_WssListener_ConnectionManager_GetConnectionBySocket(pWssListener->ConnectionManager,
                                                                        a_pSocket,
                                                                        &pWssListenerConnection);
    if (OpcUa_IsBad(uStatus))
    {
        /* no connection available */
        OpcUa_GotoError;
    }

    /******************************************************************************************************/

    /* look for pending output stream */
    if (pWssListenerConnection != OpcUa_Null)
    {
        do {
            while(pWssListenerConnection->pSendQueue != OpcUa_Null)
            {
                OpcUa_BufferList *pCurrentBuffer = pWssListenerConnection->pSendQueue;
                OpcUa_Int32 iDataLength = pCurrentBuffer->Buffer.EndOfData - pCurrentBuffer->Buffer.Position;
                OpcUa_Int32 iDataWritten = OPCUA_P_SOCKET_WRITE(a_pSocket,
                                                                &pCurrentBuffer->Buffer.Data[pCurrentBuffer->Buffer.Position],
                                                                iDataLength,
                                                                OpcUa_False);
                if (iDataWritten<0)
                {
                    return OpcUa_WssListener_TimeoutEventHandler(a_pListener, a_pSocket);
                }
                else if (iDataWritten<iDataLength)
                {
                    pCurrentBuffer->Buffer.Position += iDataWritten;
                    if ((pWssListenerConnection->bNoRcvUntilDone == OpcUa_False) &&
                       (pWssListenerConnection->bRcvDataPending == OpcUa_True))
                    {
                        pWssListenerConnection->bRcvDataPending = OpcUa_False;
                        uStatus = OpcUa_WssListener_ReadEventHandler(a_pListener, a_pSocket);
                    }
                    OpcUa_ReturnStatusCode;
                }
                else
                {
                    pWssListenerConnection->pSendQueue = pCurrentBuffer->pNext;
                    OpcUa_Buffer_Clear(&pCurrentBuffer->Buffer);
                    OpcUa_Free(pCurrentBuffer);
                }
            } /* end while */

            if (pWssListenerConnection->bCloseWhenDone == OpcUa_True)
            {
                break;
            }
            pWssListenerConnection->bNoRcvUntilDone = OpcUa_False;
            pWssListener->Callback(
                a_pListener,                            /* the event source */
                (OpcUa_Void*)pWssListener->CallbackData,/* the callback data */
                OpcUa_ListenerEvent_RefillSendQueue,    /* the event that occured */
                pWssListenerConnection,                 /* a connection handle */
                OpcUa_Null,                             /* the input stream for the event (none in this case) */
                uStatus);                               /* a status code for the event */

        } while(pWssListenerConnection->pSendQueue != OpcUa_Null);
        if (pWssListenerConnection->bCloseWhenDone == OpcUa_True)
        {
            uStatus = OpcUa_WssListener_TimeoutEventHandler(a_pListener, a_pSocket);
        }
        else if ((pWssListenerConnection->bNoRcvUntilDone == OpcUa_False) &&
                (pWssListenerConnection->bRcvDataPending == OpcUa_True))
        {
            pWssListenerConnection->bRcvDataPending = OpcUa_False;
            uStatus = OpcUa_WssListener_ReadEventHandler(a_pListener, a_pSocket);
        }
    }

    OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if (pWssListenerConnection != OpcUa_Null)
    {
        OpcUa_WssListener_ConnectionManager_ReleaseConnection(pWssListener->ConnectionManager, &pWssListenerConnection);
    }

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_EventCallback
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_EventCallback(
    OpcUa_Socket    a_pSocket,
    OpcUa_UInt32    a_uSocketEvent,
    OpcUa_Void*     a_pUserData,
    OpcUa_UInt16    a_uPortNumber,
    OpcUa_Boolean   a_bIsSSL)
{
    OpcUa_StringA                   strEvent        = OpcUa_Null;
    OpcUa_Listener*                 listener        = (OpcUa_Listener*)a_pUserData;
    OpcUa_WssListener*              pWssListener    = (OpcUa_WssListener*)listener->Handle;
    OpcUa_WssListener_EventHandler  fEventHandler   = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "EventCallback");

    OpcUa_ReferenceParameter(a_bIsSSL);
    OpcUa_ReferenceParameter(a_uPortNumber);

    OpcUa_GotoErrorIfArgumentNull(a_pSocket);


#if 1 /* debug code */
    switch(a_uSocketEvent)
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
            strEvent = "OPCUA_SOCKET_NEED_BUFFER_EVENT";
            break;
        }
    case OPCUA_SOCKET_FREE_BUFFER_EVENT:
        {
            strEvent = "OPCUA_SOCKET_FREE_BUFFER_EVENT";
            break;
        }
    default:
        {
            strEvent = "ERROR DEFAULT!";
            break;
        }
    }
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, " * OpcUa_WssListener_EventCallback: Socket(%p), Port(%d), Data(%p), Event(%s)\n", a_pSocket, a_uPortNumber, a_pUserData, strEvent);
    /* debug code end */
#endif

    switch(a_uSocketEvent)
    {
    case OPCUA_SOCKET_READ_EVENT:
        {
            /* notifies an existing stream about new data or creates a new stream */
            fEventHandler = OpcUa_WssListener_ReadEventHandler;
            break;
        }
    case OPCUA_SOCKET_EXCEPT_EVENT:
        {
            fEventHandler = OpcUa_WssListener_TimeoutEventHandler;
            break;
        }
    case OPCUA_SOCKET_WRITE_EVENT:
        {
            fEventHandler = OpcUa_WssListener_WriteEventHandler;
            break;
        }
    case OPCUA_SOCKET_NEED_BUFFER_EVENT:
        {
            /* fEventHandler = OpcUa_WssListener_NeedBufferEventHandler; */
            break;
        }
    case OPCUA_SOCKET_FREE_BUFFER_EVENT:
        {
            /* fEventHandler = OpcUa_WssListener_FreeBufferEventHandler; */
            break;
        }
    case OPCUA_SOCKET_TIMEOUT_EVENT:
        {
            fEventHandler = OpcUa_WssListener_TimeoutEventHandler;
            break;
        }
    case OPCUA_SOCKET_CLOSE_EVENT:
        {
            fEventHandler = OpcUa_WssListener_TimeoutEventHandler;
            break;
        }
    case OPCUA_SOCKET_ACCEPT_EVENT:
        {
            fEventHandler = OpcUa_WssListener_AcceptEventHandler;
            break;
        }
    case OPCUA_SOCKET_NO_EVENT:
    case OPCUA_SOCKET_SHUTDOWN_EVENT:
        {
            break;
        }
    default:
        {
            /* unexpected error, report to upper layer. */
            pWssListener->Callback(
                listener,                               /* the event source */
                (OpcUa_Void*)pWssListener->CallbackData, /* the callback data */
                OpcUa_ListenerEvent_UnexpectedError,    /* the event that occured */
                OpcUa_Null,                             /* a connection handle */
                OpcUa_Null,                             /* the input stream for the event (none in this case) */
                uStatus);                               /* a status code for the event */

            break;
        }
    }

    /* call the internal specialized event handler */
    if (fEventHandler != OpcUa_Null)
    {
        uStatus = fEventHandler(listener, a_pSocket);
    }

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, " * OpcUa_WssListener_EventCallback: Event Handler returned.\n");

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssListener_ConnectionCloseCallback
 *===========================================================================*/
 /** @brief Callback function for the Connection Manager on connection deletion.
  *
  *  @param Listener The listener the tcp connection belongs to.
  *  @param TcpConnection The tcp connection that is being deleted.
  */
OpcUa_Void OpcUa_WssListener_ConnectionDeleteCallback(  OpcUa_Listener*                 a_pListener,
                                                        OpcUa_WssListener_Connection*   a_pWssConnection)
{
    OpcUa_ReferenceParameter(a_pListener);

#if OPCUA_P_SOCKETGETPEERINFO_V2
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG,
            "OpcUa_WssListener_ConnectionDeleteCallback: Connection to peer %s (socket %p) gets closed!!\n",
            a_pWssConnection->achPeerInfo,
            a_pWssConnection->Socket);
#else
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG,
            "OpcUa_WssListener_ConnectionDeleteCallback: Connection to peer %d.%d.%d.%d:%d (socket %p) gets closed!!\n",
            (OpcUa_Int)(a_pWssConnection->PeerIp>>24)&0xFF,
            (OpcUa_Int)(a_pWssConnection->PeerIp>>16)&0xFF,
            (OpcUa_Int)(a_pWssConnection->PeerIp>>8) &0xFF,
            (OpcUa_Int) a_pWssConnection->PeerIp     &0xFF,
            a_pWssConnection->PeerPort,
            a_pWssConnection->Socket);
#endif

    if (a_pWssConnection->Socket != OpcUa_Null)
    {
        /* OPCUA_P_SOCKET_CLOSE(a_pWssConnection->Socket); */
        a_pWssConnection->Socket = OpcUa_Null;
    }

    /* TODO: consider invoking owner callback and tell about the closing. */

    return;
}

/*============================================================================
 * OpcUa_WssListener_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_Close(OpcUa_Listener* a_pListener)
{
    OpcUa_WssListener*                      pWssListener    = OpcUa_Null;
    OpcUa_InputStream*                      pInputStream    = OpcUa_Null;

    OpcUa_DeclareErrorTraceModule(OpcUa_Module_WssListener);

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfInvalidObject(OpcUa_WssListener, a_pListener, Close);

    pWssListener     = (OpcUa_WssListener*)a_pListener->Handle;

    /* lock connection and close the socket. */
    OPCUA_P_MUTEX_LOCK(pWssListener->Mutex);

    /* check if already stopped */
    if (pWssListener->Socket != OpcUa_Null)
    {
        /* only close listening socket, which should be in the global list. */
        OPCUA_P_SOCKET_CLOSE(pWssListener->Socket);
        pWssListener->Socket = OpcUa_Null;
    }

#if OPCUA_MULTITHREADED

    OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);

    /* check if socket list handle is valid */
    if (pWssListener->SocketManager != OpcUa_Null)
    {
        /* stops the thread and closes socket */
        OPCUA_P_SOCKETMANAGER_DELETE(&(pWssListener->SocketManager));
    }

    /* lock connection and close the socket. */
    OPCUA_P_MUTEX_LOCK(pWssListener->Mutex);

#endif /* OPCUA_MULTITHREADED */

    /* cleanup all connections */
    OpcUa_WssListener_ConnectionManager_RemoveConnections(  pWssListener->ConnectionManager,
                                                            OpcUa_WssListener_ConnectionDeleteCallback);

    OpcUa_List_Enter(pWssListener->PendingMessages);
    OpcUa_List_ResetCurrent(pWssListener->PendingMessages);
    pInputStream = (OpcUa_InputStream *)OpcUa_List_GetCurrentElement(pWssListener->PendingMessages);
    while(pInputStream != OpcUa_Null)
    {
        OpcUa_List_DeleteCurrentElement(pWssListener->PendingMessages);
        pInputStream->Close((OpcUa_Stream*)pInputStream);
        pInputStream->Delete((OpcUa_Stream**)&pInputStream);
        pInputStream = (OpcUa_InputStream *)OpcUa_List_GetCurrentElement(pWssListener->PendingMessages);
    }
    OpcUa_List_Leave(pWssListener->PendingMessages);

    OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);

    /* notify about successful closing of the listener */
    pWssListener->Callback( a_pListener,                /* the source of the event          */
                            pWssListener->CallbackData, /* the callback data                */
                            OpcUa_ListenerEvent_Close,  /* the event that occured           */
                            OpcUa_Null,                 /* the handle for the connection    */
                            OpcUa_Null,                 /* the non existing stream          */
                            OpcUa_Good);                /* status                           */



    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_WssListener_Open
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssListener_Open(
    struct _OpcUa_Listener*     a_pListener,
    OpcUa_String*               a_sUrl,
    OpcUa_Boolean               a_bListenOnAllInterfaces,
    OpcUa_Listener_PfnOnNotify* a_pfnCallback,
    OpcUa_Void*                 a_pCallbackData)
{
    OpcUa_WssListener*  pWssListener        = OpcUa_Null;
    OpcUa_UInt32        uSocketManagerFlags = OPCUA_SOCKET_NO_FLAG;

OpcUa_InitializeStatus(OpcUa_Module_WssListener, "Open");

    OpcUa_ReturnErrorIfArgumentNull(a_pListener);
    OpcUa_ReturnErrorIfArgumentNull(a_sUrl);

    OpcUa_ReturnErrorIfInvalidObject(OpcUa_WssListener, a_pListener, Open);

    pWssListener = (OpcUa_WssListener*)a_pListener->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssListener);

    if (OpcUa_ProxyStub_g_Configuration.bTcpListener_ClientThreadsEnabled != OpcUa_False)
    {
        uSocketManagerFlags |= OPCUA_SOCKET_SPAWN_THREAD_ON_ACCEPT | OPCUA_SOCKET_REJECT_ON_NO_THREAD;
    }

    /********************************************************************/

    /* lock listener while thread is starting */
    OPCUA_P_MUTEX_LOCK(pWssListener->Mutex);

    /* check if thread already started */
    if (pWssListener->Socket != OpcUa_Null)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);
        return OpcUa_BadInvalidState;
    }

    pWssListener->Callback     = a_pfnCallback;
    pWssListener->CallbackData = a_pCallbackData;

    /********************************************************************/

    /* start up socket handling for this listener */
#if OPCUA_MULTITHREADED
    /* check if socket list handle not yet set */
    if (pWssListener->SocketManager != OpcUa_Null)
    {
        OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);
        return OpcUa_BadInvalidState;
    }

    uStatus = OPCUA_P_SOCKETMANAGER_CREATE( &(pWssListener->SocketManager),
                                            OPCUA_TCPLISTENER_MAXCONNECTIONS + 1, /* add one for listen socket */
                                            uSocketManagerFlags);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OPCUA_P_SOCKETMANAGER_CREATESERVER(
        pWssListener->SocketManager,
        OpcUa_String_GetRawString(a_sUrl),
        a_bListenOnAllInterfaces,
        OpcUa_WssListener_EventCallback,
        (OpcUa_Void*)a_pListener,
        &(pWssListener->Socket));

#else /* OPCUA_MULTITHREADED */

    /* single thread socket created on global socket manager */
    uStatus = OPCUA_P_SOCKETMANAGER_CREATESERVER(   OpcUa_Null,
                                                    OpcUa_String_GetRawString(a_sUrl),
                                                    a_bListenOnAllInterfaces,
                                                    OpcUa_WssListener_EventCallback,
                                                    (OpcUa_Void*)a_pListener,
                                                    &(pWssListener->Socket));

#endif /* OPCUA_MULTITHREADED */
    OpcUa_GotoErrorIfBad(uStatus);

    /********************************************************************/

    /* notify about successful opening of the listener */
    pWssListener->Callback( a_pListener,                /* the source of the event          */
                            pWssListener->CallbackData,  /* the callback data                */
                            OpcUa_ListenerEvent_Open,   /* the event that occured           */
                            OpcUa_Null,                 /* the handle for the connection    */
                            OpcUa_Null,                 /* the non existing stream          */
                            OpcUa_Good);                /* status                           */

    OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssListener_Close(a_pListener);

    OPCUA_P_MUTEX_UNLOCK(pWssListener->Mutex);

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_SERVERAPI */
