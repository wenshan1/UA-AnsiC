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

#ifndef _OpcUa_WssStream_H_
#define _OpcUa_WssStream_H_ 1

#include <opcua_stream.h>

OPCUA_BEGIN_EXTERN_C

#define OPCUA_WSSSTREAM_HTTP_REQUESTLINE_MAXLENGTH 1024
#define OPCUA_WSSSTREAM_WSS_FRAMESIZE_LENGTH 2
#define OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH 14
#define OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH  4
#define OPCUA_WSSSTREAM_TCP_MESSAGELENGTH_LENGTH sizeof(OpcUa_UInt32)
#define OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH (OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH + OPCUA_WSSSTREAM_TCP_MESSAGELENGTH_LENGTH)

/*============================================================================
 * OpcUa_WssStream_MessageType
 *===========================================================================*/
/** @brief Message signatures for protocol commands. */
#define OPCUA_WSSSTREAM_SIGNATURE_HELLO         "HELF"
#define OPCUA_WSSSTREAM_SIGNATURE_ACKNOWLEDGE   "ACKF"
#define OPCUA_WSSSTREAM_SIGNATURE_ERROR         "ERRF"

#define OPCUA_WSSSTREAM_SIGNATURE_STARTBYTES    "HAE"

/*============================================================================
 * OpcUa_WssStream_MessageType
 *===========================================================================*/
/** @brief Message signatures for securechannel messages. Those are 3 byte signatures */
#define OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_OPEN        "OPN"
#define OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_CLOSE       "CLO"
#define OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_MESSAGE     "MSG"

#define OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_STARTBYTES  "OCM"

/*============================================================================
 * OpcUa_WssStream_NotifyDisconnect
 *===========================================================================*/
/** @brief Notify the owner about a tcp disconnect event. (ie. during write) */
typedef OpcUa_Void (OpcUa_WssStream_PfnNotifyDisconnect)(OpcUa_Handle hConnection);

/*============================================================================
 * OpcUa_WssStream_MessageType
 *===========================================================================*/
/** @brief Types for binary protocol messages. */
enum _OpcUa_WssStream_MessageType
{
    /** @brief Unknown Message Type */
    OpcUa_WssStream_MessageType_Unknown,

    /** @brief Invalid Message Type */
    OpcUa_WssStream_MessageType_Invalid,

    /** @brief Requests an upgrade from an HTTP connection to a web socket. This message is only sent by the client. */
    OpcUa_WssStream_MessageType_HttpUpgradeRequest,

    /** @brief Acknowledges an upgrade from an HTTP connection to a web socket. This message is only sent by the server. */
    OpcUa_WssStream_MessageType_HttpUpgradeResponse,

    /** @brief The message was a WebSocket close. */
    OpcUa_WssStream_MessageType_WsClose,

    /** @brief The message was a WebSocket ping. */
    OpcUa_WssStream_MessageType_WsPing,

    /** @brief The message was a WebSocket pong. */
    OpcUa_WssStream_MessageType_WsPong,

    /** @brief Establishes a new connection with the server. This message is only sent by the client. */
    OpcUa_WssStream_MessageType_Hello,

    /** @brief Acknowledges a new virtual connection. This message is only sent by the server. */
    OpcUa_WssStream_MessageType_Acknowledge,

    /** @brief Tells the client, that the last message contained an error. */
    OpcUa_WssStream_MessageType_Error,

    /** @brief All messages */
    OpcUa_WssStream_MessageType_SecureChannel

};
typedef enum _OpcUa_WssStream_MessageType OpcUa_WssStream_MessageType;

/*============================================================================
 * OpcUa_WssStream_State
 *===========================================================================*/
/** @brief Types for binary protocol messages. */
enum _OpcUa_WssStream_State
{
    /** @brief Stream has no data. */
    OpcUa_WssStream_State_Empty,
    /** @brief The signature has begun but not finished. */
    OpcUa_WssStream_State_HeaderStarted,
    /** @brief All headerdata has been received. */
    OpcUa_WssStream_State_HeaderComplete,
    /** @brief The complete message has been received. */
    OpcUa_WssStream_State_MessageComplete
};

typedef enum _OpcUa_WssStream_State OpcUa_WssStream_State;

/*============================================================================
* OpcUa_WssConnection_StreamState
*===========================================================================*/
/** @brief The possible states for a connection. */
enum _OpcUa_WssConnection_StreamState
{
    /** @brief The connection has been created. */
    OpcUa_WssConnection_StreamState_Created,

    /** @brief The connection is handling a TLS upgrade. */
    OpcUa_WssConnection_StreamState_TlsUpgrade,

    /** @brief The connection is handling a HTTP upgrade. */
    OpcUa_WssConnection_StreamState_HttpUpgrade,

    /** @brief The connection is now processing messages. */
    OpcUa_WssConnection_StreamState_Open,

    /** @brief Tells the client, that the last message contained an error. */
    OpcUa_WssConnection_StreamState_Closed

};
typedef enum _OpcUa_WssConnection_StreamState OpcUa_WssConnection_StreamState;

/*============================================================================
* OpcUa_WssInputStream
*===========================================================================*/
/** @brief Private data structure for an OpcUa_Stream that allows reading from
* a socket.
*/
struct _OpcUa_WssHttpHeader
{
    OpcUa_StringA Url;
    OpcUa_Boolean IsResponse;
    OpcUa_UInt16  ResponseCode;
    OpcUa_StringA Reason;
    OpcUa_StringA Host;
    OpcUa_StringA WebSocketKey;
};
typedef struct _OpcUa_WssHttpHeader OpcUa_WssHttpHeader;

/*============================================================================
 * OpcUa_WssInputStream
 *===========================================================================*/
/** @brief Private data structure for an OpcUa_Stream that allows reading from
  * a socket.
  */
struct _OpcUa_WssInputStream
{
    /** @brief Inherited Fields from OpcUa_InputStream. @see OpcUa_InputStream */
    OpcUa_InputStream                   Base;

    /* Subclass Fields */
    /** @brief Check type of interface implementation. */
    OpcUa_UInt32                        SanityCheck;
    /** @brief Holds the type of the received message chunk. @see OpcUa_WssStream_MessageType */
    OpcUa_WssStream_MessageType         MessageType;
    /** @brief The length of the message as parsed from the message header. */
    OpcUa_UInt32                        MessageLength;
    /** @brief The communication handle with which the message was received from. */
    OpcUa_Socket                        Socket;
    /** @brief Tells wether the stream is closed for reading. */
    OpcUa_Boolean                       Closed;
    /** @brief The current state of the stream. @see OpcUa_WssStream_State */
    OpcUa_WssStream_State               State;
    /** @brief The size of the internal buffer. */
    OpcUa_UInt32                        BufferSize;
    /** @brief The internal buffer. */
    OpcUa_Buffer                        Buffer;
    /** @brief True if the stream contains the last chunk of a message. */
    OpcUa_Boolean                       IsFinal;
    /** @brief True if the stream contains an abort message. */
    OpcUa_Boolean                       IsAbort;
    /** @brief The current state of the connection. */
    OpcUa_WssConnection_StreamState     ConnectionState;
    /** @brief The length of the WebSocket frame header. */
    OpcUa_UInt32                        WssFrameHeaderLength;
};
typedef struct _OpcUa_WssInputStream OpcUa_WssInputStream;

/*============================================================================
 * OpcUa_WssOutputStream
 *===========================================================================*/
/** @brief Private data structure for an OpcUa_Stream that allows writing to
  * a socket.
  */
struct _OpcUa_WssOutputStream
{
    /** @brief Inherited Fields from OpcUa_OutputStream. @see OpcUa_OutputStream */
    OpcUa_OutputStream                  Base;

    /* Subclass (Tcp) Fields */
    /** @brief Check type of interface implementation. */
    OpcUa_UInt32                        SanityCheck;
    /** @brief Holds the type of the received message chunk. @see OpcUa_WssStream_MessageType */
    OpcUa_WssStream_MessageType         MessageType;
    /** @brief The communication handle with which the message is sent. */
    OpcUa_Socket                        Socket;
    /** @brief Tells wether the stream is closed for reading. */
    OpcUa_Boolean                       Closed;
    /** @brief Handle of the underlying connection. */
    OpcUa_Void*                         hConnection;
    /** @brief Size of the internal message buffer. */
    OpcUa_UInt32                        BufferSize;
    /** @brief The internal message buffer. */
    OpcUa_Buffer                        Buffer;
    /** @brief Number of times this stream has flushed its buffer. */
    OpcUa_UInt32                        NoOfFlushes;
    /** @brief Maximum number of times this stream may flush its buffer. */
    OpcUa_UInt32                        MaxNoOfFlushes;
    /** @brief Disconnect notification callback. */
    OpcUa_WssStream_PfnNotifyDisconnect* NotifyDisconnect;
    /** @brief The current state of the connection. */
    OpcUa_WssConnection_StreamState      ConnectionState;
};
typedef struct _OpcUa_WssOutputStream OpcUa_WssOutputStream;

/*============================================================================
 * OpcUa_WssStream_CreateInput
 *===========================================================================*/
/** @brief Allocates a new stream to read a message from a socket.
 *  @param socket [in]  The socket to read from.
 *  @param istrm  [in]  The buffer size of the stream.
 *  @param istrm  [out] The new input stream.
 */
OPCUA_EXPORT OpcUa_StatusCode OpcUa_WssStream_CreateInput(
    OpcUa_Socket                    hSocket,
    OpcUa_UInt32                    uBufferSize,
    OpcUa_WssConnection_StreamState eState,
    OpcUa_InputStream**             ppIstrm);

/*============================================================================
 * OpcUa_WssStream_CreateOutput
 *===========================================================================*/
/** @brief Allocates a new stream to write a message to a socket.
 *  @param socket         [in]  The socket to write to.
 *  @param messageType    [in]  The type of the message, used for signature.
 *  @param messageType    [in]  A buffer to use for writing.
 *  @param bufferSize     [in]  The size of the receiving buffer.
 *  @param uMaxNoOfFlushes[in]  Maximum number of flushes allowed.
 *  @param ostrm          [out] The new output stream.
 */
OPCUA_EXPORT OpcUa_StatusCode OpcUa_WssStream_CreateOutput(
    OpcUa_Socket                        socket,
    OpcUa_WssStream_MessageType         messageType,
    OpcUa_Byte**                        ppAttachBuffer,
    OpcUa_UInt32                        bufferSize,
    OpcUa_WssStream_PfnNotifyDisconnect pfnDisconnectCB,
    OpcUa_UInt32                        uMaxNoOfFlushes,
    OpcUa_WssConnection_StreamState     eState,
    OpcUa_OutputStream**                ppOstrm);

/*============================================================================
 * OpcUa_Stream_Read
 *===========================================================================*/
/** @brief Read data from the streams internal buffer. */
OpcUa_StatusCode OpcUa_WssStream_Read(
    OpcUa_InputStream*              istrm,
    OpcUa_Byte*                     buffer,
    OpcUa_UInt32*                   count);

/*============================================================================
 * OpcUa_Stream_Write
 *===========================================================================*/
/** @brief Write the given data into the stream. This operation may cause
  * one or more flushes of the buffered data to the underlying socket if
  * the given data is larger than the free buffer space or larger than
  * the buffer itself.
  */
OpcUa_StatusCode OpcUa_WssStream_Write(
    OpcUa_OutputStream* ostrm,
    OpcUa_Byte*         buffer,
    OpcUa_UInt32        count);

/*============================================================================
 * OpcUa_Stream_Flush
 *===========================================================================*/
/** @brief Send the buffered data to the socket. */
OpcUa_StatusCode OpcUa_WssStream_Flush(
    OpcUa_OutputStream* ostrm,
    OpcUa_Boolean       lastCall);

/*============================================================================
 * OpcUa_Stream_Close
 *===========================================================================*/
/** @brief Closes the stream. To be called before delete. Causes the sending
 *  of the buffered data if the parameter is an output stream.
 */
OpcUa_StatusCode OpcUa_WssStream_Close(OpcUa_Stream* strm);

/*============================================================================
 * OpcUa_Stream_Delete
 *===========================================================================*/
/** @brief Delete the stream and all associated ressources. */
OpcUa_Void OpcUa_WssStream_Delete(OpcUa_Stream** strm);

/*============================================================================
 * OpcUa_Stream_GetPosition
 *===========================================================================*/
/** @brief Get the position of the internal read/write pointer. */
OpcUa_StatusCode OpcUa_WssStream_GetPosition(
    OpcUa_Stream* strm,
    OpcUa_UInt32* position);

/*============================================================================
 * OpcUa_Stream_SetPosition
 *===========================================================================*/
/** @brief Set position of the internal read/write pointer. */
OpcUa_StatusCode OpcUa_WssStream_SetPosition(
    OpcUa_Stream* strm,
    OpcUa_UInt32 position);

/*============================================================================
 * OpcUa_WssStream_DataReady
 *===========================================================================*/
/** @brief A lower layer tells the stream, that a read operation is possible. */
OpcUa_StatusCode OpcUa_WssStream_DataReady(OpcUa_InputStream* istrm);

/*============================================================================
 * OpcUa_WssStream_DetachBuffer
 *===========================================================================*/
/** @brief Detach data from the stream object. */
OpcUa_StatusCode OpcUa_WssStream_DetachBuffer(
    OpcUa_Stream* pStream, 
    OpcUa_Buffer* pBuffer);

OPCUA_END_EXTERN_C

#endif /* _OpcUa_WssStream_H_ */
