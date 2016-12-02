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
#include <opcua_mutex.h>
#include <opcua_socket.h>
#include <opcua_list.h>
#include <opcua_binaryencoder.h>
#include <opcua_wssconnection.h>
#include <opcua_wsslistener.h>
#include <opcua_wssstream.h>

/* for debugging reasons */
#include <opcua_p_binary.h>
#include <ctype.h>
#include <stdlib.h> 

#define OpcUa_WssOutputStream_SanityCheck 0x5B5141A2
#define OpcUa_WssInputStream_SanityCheck 0x5B5141A6

/*============================================================================
* OpcUa_ReturnErrorIfInvalidStream
*===========================================================================*/
/** @brief check instance */
#define OpcUa_ReturnErrorIfInvalidStream(xStrm, xMethod) \
if (((((OpcUa_WssInputStream*)(xStrm->Handle))->SanityCheck != OpcUa_WssInputStream_SanityCheck) && (((OpcUa_WssOutputStream*)(xStrm->Handle))->SanityCheck != OpcUa_WssOutputStream_SanityCheck)) || xStrm->xMethod != OpcUa_WssStream_##xMethod) \
{ \
    return OpcUa_BadInvalidArgument; \
}

/*============================================================================
 * OpcUa_WssStream_DetachBuffer
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_DetachBuffer(  OpcUa_Stream*   a_pStream,
                                                OpcUa_Buffer*   a_pBuffer)
{
    OpcUa_UInt32 ii = 0;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "DetachBuffer");

    OpcUa_GotoErrorIfArgumentNull(a_pStream);
    OpcUa_GotoErrorIfArgumentNull(a_pBuffer);

    switch(a_pStream->Type)
    {
    case OpcUa_StreamType_Output:
        {
            OpcUa_WssOutputStream* pWssOutputStream = (OpcUa_WssOutputStream*)(a_pStream->Handle);

            *a_pBuffer = pWssOutputStream->Buffer;
            pWssOutputStream->Buffer.Data = OpcUa_Null;
            OpcUa_Buffer_Clear(&pWssOutputStream->Buffer);

            break;
        }
    case OpcUa_StreamType_Input:
        {
            OpcUa_WssInputStream* pWssInputStream = (OpcUa_WssInputStream*)a_pStream;

            /* move data to remove frame header - again not ideal. */
            if (pWssInputStream->WssFrameHeaderLength > 0)
            {
                for (ii = 0; ii < pWssInputStream->Buffer.EndOfData-pWssInputStream->WssFrameHeaderLength; ii++)
                {
                    pWssInputStream->Buffer.Data[ii] = pWssInputStream->Buffer.Data[ii+pWssInputStream->WssFrameHeaderLength];
                }

                pWssInputStream->Buffer.Position -= pWssInputStream->WssFrameHeaderLength;
                pWssInputStream->Buffer.EndOfData -= pWssInputStream->WssFrameHeaderLength;
            }

            *a_pBuffer = pWssInputStream->Buffer;
            pWssInputStream->Buffer.Data = OpcUa_Null;
            OpcUa_Buffer_Clear(&pWssInputStream->Buffer);

            pWssInputStream->State = OpcUa_WssStream_State_Empty;
            pWssInputStream->Base.Close((OpcUa_Stream*)pWssInputStream);

            break;
        }
    default:
        {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoError;
        }
    }


OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_AttachBuffer
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_AttachBuffer(  OpcUa_Stream*   a_pStream,
                                                OpcUa_Buffer*   a_pBuffer)
{
    OpcUa_Int32 ii = 0;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "AttachBuffer");

    OpcUa_ReturnErrorIfArgumentNull(a_pStream);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);
    OpcUa_ReturnErrorIfArgumentNull(a_pStream->Handle);

    switch(a_pStream->Type)
    {
    case OpcUa_StreamType_Output:
        {
            OpcUa_WssOutputStream*  pWssOutputStream    = (OpcUa_WssOutputStream*)(a_pStream->Handle);
            OpcUa_Buffer            OldBuffer           = pWssOutputStream->Buffer;

            pWssOutputStream->Buffer = *a_pBuffer;

            /* this is a hack that needs to be fixed by ensuring the created buffers always have extra space for the the frame header */
            if (pWssOutputStream->Buffer.Size - pWssOutputStream->Buffer.EndOfData  < OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH)
            {
                pWssOutputStream->Buffer.Data = OpcUa_ReAlloc(pWssOutputStream->Buffer.Data, pWssOutputStream->Buffer.EndOfData + OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH);
                OpcUa_GotoErrorIfAllocFailed(pWssOutputStream->Buffer.Data);
                pWssOutputStream->Buffer.Size = pWssOutputStream->Buffer.EndOfData + OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH;
            }

            /* move data to make space for frame header - again not ideal. */
            for (ii = pWssOutputStream->Buffer.EndOfData-1; ii >= 0; ii--)
            {
                pWssOutputStream->Buffer.Data[ii+OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH] = pWssOutputStream->Buffer.Data[ii];
            }

            OpcUa_MemSet(pWssOutputStream->Buffer.Data, 0, OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH);
            pWssOutputStream->Buffer.EndOfData += OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH;

            /* set a binary frame */
            pWssOutputStream->Buffer.Data[0] = 0x82;

            /* create same state as data would have been written into the stream */
            uStatus = OpcUa_Buffer_SetPosition(&pWssOutputStream->Buffer, OpcUa_BufferPosition_End);

            if (OpcUa_IsBad(uStatus))
            {
                /* restore old buffer */
                pWssOutputStream->Buffer = OldBuffer;
            }

            a_pBuffer->Data = OpcUa_Null;
            OpcUa_Buffer_Clear(a_pBuffer);

            break;
        }
    case OpcUa_StreamType_Input:
        {
            OpcUa_WssInputStream* pWssInputStream = (OpcUa_WssInputStream*)(a_pStream->Handle);

            OpcUa_ReferenceParameter(pWssInputStream);

            uStatus = OpcUa_BadNotSupported;

            break;
        }
    default:
        {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoError;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_GetChunkLength
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_GetChunkLength(    OpcUa_Stream* a_pStream,
                                                    OpcUa_UInt32* a_puLength)
{
OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "GetChunkLength");

    OpcUa_ReturnErrorIfArgumentNull(a_pStream);
    OpcUa_ReturnErrorIfArgumentNull(a_puLength);

    switch(a_pStream->Type)
    {
    case OpcUa_StreamType_Input:
        {
            OpcUa_WssInputStream* istrm = (OpcUa_WssInputStream*)(a_pStream->Handle);
            *a_puLength = istrm->BufferSize;
            break;
        }
    case OpcUa_StreamType_Output:
        {
            OpcUa_WssOutputStream* ostrm = (OpcUa_WssOutputStream*)(a_pStream->Handle);
            *a_puLength = ostrm->BufferSize;
            break;
        }
    default:
        {
            uStatus = OpcUa_BadInvalidArgument;
            OpcUa_GotoError;
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_Read
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_Read(
    OpcUa_InputStream*             a_pIstrm,            /* Stream with TcpStream handle */
    OpcUa_Byte*                    a_pTargetBuffer,     /* The destination buffer. */
    OpcUa_UInt32*                  a_puCount)           /* How many bytes should be delivered. */
{
    OpcUa_WssInputStream* pWssInputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "Read");

    OpcUa_ReturnErrorIfArgumentNull(a_pIstrm);
    OpcUa_ReturnErrorIfArgumentNull(a_pTargetBuffer);
    OpcUa_ReturnErrorIfArgumentNull(a_puCount);
    OpcUa_ReturnErrorIfInvalidStream(a_pIstrm, Read);

    /* HINTS: we dont want to trigger a socket recv for every element, so the
              data gets buffered internally in the stream to read "as much as
              possible" (well, not really, trying to predict message borders
              implicitly through buffer sizes.) in one api call for performance
              reasons.

              A read looks, if the requested amount of data is available in
              the internal buffer and copies it into the target. The caller
              must swap into the right byte order afterwards.
              */

    /* resolve stream handle to tcp stream */
    pWssInputStream  = (OpcUa_WssInputStream*)(a_pIstrm->Handle);

    /* check for end of stream */
    uStatus = OpcUa_Buffer_Read(&(pWssInputStream->Buffer), a_pTargetBuffer, a_puCount);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}


/*============================================================================
 * OpcUa_WssStream_Write
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_Write(
    OpcUa_OutputStream* a_pOstrm,           /* the stream to write the value into */
    OpcUa_Byte*         a_pInBuffer,        /* the value to write */
    OpcUa_UInt32        a_uInBufferSize)    /* the size of the value to write */
{
    OpcUa_WssOutputStream*  pWssOutputStream = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "Write");

    OpcUa_ReturnErrorIfArgumentNull(a_pOstrm);
    OpcUa_ReturnErrorIfArgumentNull(a_pInBuffer);

    pWssOutputStream = (OpcUa_WssOutputStream*)a_pOstrm->Handle;

    OpcUa_ReturnErrorIfInvalidStream(a_pOstrm, Write);

    if (pWssOutputStream->Closed)
    {
        return OpcUa_BadInvalidState;
    }

    /* write data to output buffer - flush to network as required */
    if ((pWssOutputStream->Buffer.Position + a_uInBufferSize) > pWssOutputStream->Buffer.Size)
    {
        if (pWssOutputStream->MessageType == OpcUa_WssStream_MessageType_SecureChannel)
        {
            /* The secure channel should never trigger automatic flushing. */
            /* At this point something went wrong. */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "ERROR: automatic flush in secure channel message should not happen!");
            OpcUa_GotoErrorWithStatus(OpcUa_BadEndOfStream);
        }

        /* data wouldnt fit into the buffer -> flush to network. */
        /* curser will be reset by flush. */
        uStatus = OpcUa_WssStream_Flush(    a_pOstrm,
                                            OpcUa_False);
        OpcUa_ReturnErrorIfBad(uStatus);

        /* HINT: This should never happen by the secure channel layer. */
        /*       It will alway know, when to flush by itself. */
        /*       To be safe, check the current position after a write. */
    }

    uStatus = OpcUa_Buffer_Write(&(pWssOutputStream->Buffer), a_pInBuffer, a_uInBufferSize);
    OpcUa_ReturnErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_Flush
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_Flush(
    OpcUa_OutputStream* a_pOstrm,
    OpcUa_Boolean       a_bLastCall)
{
    OpcUa_WssOutputStream*  pWssOutputStream = OpcUa_Null;
    OpcUa_UInt32 tempDataLength = 0;
    OpcUa_UInt32 uStartOfData = 0;
    OpcUa_UInt32 frameHeaderLength = 0;
    OpcUa_Int32 iDataWritten = 0;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "Flush");

    OpcUa_ReturnErrorIfArgumentNull(a_pOstrm);
    OpcUa_ReturnErrorIfInvalidStream(a_pOstrm, Flush);

    pWssOutputStream = (OpcUa_WssOutputStream*)a_pOstrm->Handle;
    OpcUa_ReturnErrorIfArgumentNull(pWssOutputStream);

    OpcUa_GotoErrorIfTrue((pWssOutputStream->Closed), OpcUa_BadInvalidState);

    if (pWssOutputStream->MaxNoOfFlushes != 0 && ((pWssOutputStream->NoOfFlushes + 1) >= pWssOutputStream->MaxNoOfFlushes) && (a_bLastCall == OpcUa_False))
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssStream_Flush: Flush no. %u with %u max flushes and final flag %u -> Too many chunks!\n", (pWssOutputStream->NoOfFlushes + 1), pWssOutputStream->MaxNoOfFlushes, a_bLastCall);
        return OpcUa_BadTcpMessageTooLarge;
    }
    else
    {
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_Flush: Flush no. %u with %u max flushes and final flag %u!\n", (pWssOutputStream->NoOfFlushes + 1), pWssOutputStream->MaxNoOfFlushes, a_bLastCall);
    }

#if 1
    if (!OpcUa_Buffer_IsEmpty(&pWssOutputStream->Buffer))
    {
#endif
    tempDataLength = pWssOutputStream->Buffer.Position;
    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_Flush: Messagelength is %d!%s\n", tempDataLength, a_bLastCall?" Last Call!":"");

    /* update header only for own messages; securechannel headers don't get touched */
    if (pWssOutputStream->ConnectionState != OpcUa_WssConnection_StreamState_HttpUpgrade)
    {
        tempDataLength -= OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH;

        /* slide header over to be contiguous with the payload*/
        if (tempDataLength < 126)
        {
            uStartOfData = OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH - 2;
            pWssOutputStream->Buffer.Data[uStartOfData+1] = tempDataLength;
        }
        else if (tempDataLength < USHRT_MAX)
        {
            uStartOfData = OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH - 4;
            pWssOutputStream->Buffer.Data[uStartOfData+1] = 126;
            pWssOutputStream->Buffer.Data[uStartOfData+2] = ((tempDataLength >> 8) & 0xFF);
            pWssOutputStream->Buffer.Data[uStartOfData+3] = (tempDataLength & 0xFF);
        }
        else
        {
            uStartOfData = OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH - 10;
            pWssOutputStream->Buffer.Data[uStartOfData+1] = 127;
            pWssOutputStream->Buffer.Data[uStartOfData+2] = 0;
            pWssOutputStream->Buffer.Data[uStartOfData+3] = 0;
            pWssOutputStream->Buffer.Data[uStartOfData+4] = 0;
            pWssOutputStream->Buffer.Data[uStartOfData+5] = 0;
            pWssOutputStream->Buffer.Data[uStartOfData+6] = ((tempDataLength >> 24) & 0xFF);
            pWssOutputStream->Buffer.Data[uStartOfData+7] = ((tempDataLength >> 16) & 0xFF);
            pWssOutputStream->Buffer.Data[uStartOfData+8] = ((tempDataLength >> 8) & 0xFF);
            pWssOutputStream->Buffer.Data[uStartOfData+9] = (tempDataLength & 0xFF);
        }

        pWssOutputStream->Buffer.Data[uStartOfData] = pWssOutputStream->Buffer.Data[0];

        if (pWssOutputStream->MessageType != OpcUa_WssStream_MessageType_WsPong && pWssOutputStream->MessageType != OpcUa_WssStream_MessageType_SecureChannel)
        {
            /* update chunk flag */
            if (a_bLastCall != OpcUa_False)
            {
                /* change signature to message complete */
                pWssOutputStream->Buffer.Data[OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH + 3] = 'F';
            }

            /* update size */
            pWssOutputStream->Buffer.Position = OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH + 4;

            uStatus = OpcUa_UInt32_BinaryEncode(tempDataLength, a_pOstrm);
            OpcUa_GotoErrorIfBad(uStatus);
        }

        tempDataLength += OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH;
        tempDataLength -= uStartOfData;
    }

    pWssOutputStream->Buffer.Position = uStartOfData;

    /* send to network */
    iDataWritten = OPCUA_P_SOCKET_WRITE(
        pWssOutputStream->Socket,
        &pWssOutputStream->Buffer.Data[pWssOutputStream->Buffer.Position],
        tempDataLength,
        #if OPCUA_WSSSTREAM_BLOCKINGWRITE
        OpcUa_True);
        #else /* OPCUA_WSSSTREAM_BLOCKINGWRITE */
        OpcUa_False);
        #endif /* OPCUA_WSSSTREAM_BLOCKINGWRITE */

    pWssOutputStream->NoOfFlushes++;

    if (iDataWritten < (OpcUa_Int32)tempDataLength)
    {
        if (iDataWritten < (OpcUa_Int32)0)
        {
            uStatus = OPCUA_P_SOCKET_GETLASTERROR(pWssOutputStream->Socket);
            OpcUa_Trace(OPCUA_TRACE_LEVEL_WARNING, "OpcUa_WssStream_Flush: Error writing to socket: 0x%08X!\n", uStatus);

            /* Notify connection! */
            if ((pWssOutputStream->NotifyDisconnect != OpcUa_Null) && (pWssOutputStream->hConnection != OpcUa_Null))
            {
                pWssOutputStream->NotifyDisconnect(pWssOutputStream->hConnection);
            }

            OpcUa_GotoErrorWithStatus(OpcUa_BadDisconnect);
        }
        else
        {
            /* keep as outgoing stream */
            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_Flush: Only %u bytes of %u written!\n", iDataWritten, tempDataLength);
            /* store position */
            pWssOutputStream->Buffer.Position = (OpcUa_UInt32)(iDataWritten + uStartOfData);
            pWssOutputStream->Buffer.EndOfData = tempDataLength + uStartOfData;
            OpcUa_GotoErrorWithStatus(OpcUa_BadWouldBlock);
        }
    }

    /* prepare new flags */
    if (a_bLastCall == OpcUa_False)
    {
        /* Stream will be used again. Reset position. */
        uStatus = OpcUa_Buffer_SetPosition(&pWssOutputStream->Buffer, OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH);
        OpcUa_GotoErrorIfBad(uStatus);

        if (pWssOutputStream->ConnectionState != OpcUa_WssConnection_StreamState_HttpUpgrade)
        {
            if (pWssOutputStream->MessageType != OpcUa_WssStream_MessageType_SecureChannel)
            {
                uStatus = OpcUa_Buffer_Write(&pWssOutputStream->Buffer, (OpcUa_Byte*)"F", 1);
                OpcUa_GotoErrorIfBad(uStatus);
                uStatus = OpcUa_Buffer_SetPosition(&pWssOutputStream->Buffer, OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH + 8);
                OpcUa_GotoErrorIfBad(uStatus);
            }
        }
    }
    else
    {
        /* this was the last call -> stream is doomed! */
        OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_Flush: Buffer emptied!\n");
        OpcUa_Buffer_SetEmpty(&pWssOutputStream->Buffer);
    }
#if 1
    }
    else
    {
        /*OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_Flush: Empty tcp stream flush ignored.\n");*/
    }
#endif

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_Close
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_Close(OpcUa_Stream* a_pStrm)
{
OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "Close");

    OpcUa_GotoErrorIfArgumentNull(a_pStrm);
    OpcUa_ReturnErrorIfInvalidStream(a_pStrm, Close);

    if (a_pStrm->Type == OpcUa_StreamType_Output)
    {
        if (((OpcUa_WssOutputStream*)(a_pStrm->Handle))->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        /* flush buffer if data is available. */
        if (!OpcUa_Buffer_IsEmpty(&(((OpcUa_WssOutputStream*)a_pStrm->Handle))->Buffer))
        {
            OpcUa_WssStream_Flush((OpcUa_OutputStream*)a_pStrm, OpcUa_True);
        }

        ((OpcUa_WssOutputStream*)(a_pStrm->Handle))->Closed = OpcUa_True;
    }
    else if (a_pStrm->Type == OpcUa_StreamType_Input)
    {
        if (((OpcUa_WssInputStream*)(a_pStrm->Handle))->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        /* TODO: closing a stream before the end of the message could screw things up.
           Need to read rest of message from stream before closing. Thats complex,
           because the rest of the message may be delayed, so we would have to block here,
           what we don't want. Handle this stream like before, but mark it as abandoned!
           If the stream is complete, it will not be handled but deleted immediately.
           Intermediary read events are not further processed. */

        ((OpcUa_WssInputStream*)(a_pStrm->Handle))->Closed = OpcUa_True;
    }
    else
    {
        return OpcUa_BadInvalidState;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_WssStream_Delete(OpcUa_Stream** a_ppStrm)
{
    if (a_ppStrm == OpcUa_Null)
    {
        /* Errorcondition - should not happen. */
        return;
    }

    if ((*a_ppStrm) == OpcUa_Null)
    {
        /* Errorcondition - should not happen. */
        return;
    }


    if ((*a_ppStrm)->Type == OpcUa_StreamType_Output)
    {
        OpcUa_WssOutputStream* ostrm = (OpcUa_WssOutputStream*)((*a_ppStrm)->Handle);

        OpcUa_Buffer_Clear(&(ostrm->Buffer));

        OpcUa_Free(*a_ppStrm);
        *a_ppStrm = OpcUa_Null;
    }
    else if ((*a_ppStrm)->Type == OpcUa_StreamType_Input)
    {
        OpcUa_WssInputStream* istrm = (OpcUa_WssInputStream*)((*a_ppStrm)->Handle);

        if (!istrm->Closed)
        {
            /* Errorcondition - should not happen. */
            return;
        }

        /* clear buffer */
        /* Delete ignores OpcUa_Null, so if the buffer got detached by the upper layer, this works, too. */
        OpcUa_Buffer_Clear(&(istrm->Buffer));

        /* OpcUa_Free(istrm);*/
        OpcUa_Free(*a_ppStrm);
        *a_ppStrm = OpcUa_Null;
    }
    else
    {
        /* Errorcondition - should not happen. */
        return;
    }
}

/*============================================================================
 * OpcUa_WssStream_GetPosition
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_GetPosition(
    OpcUa_Stream* a_pStrm,
    OpcUa_UInt32* a_pPosition)
{
OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "GetPosition");

    OpcUa_ReturnErrorIfArgumentNull(a_pStrm);
    OpcUa_ReturnErrorIfInvalidStream(a_pStrm, GetPosition);
    OpcUa_ReferenceParameter(a_pPosition);

    if (a_pStrm->Type == OpcUa_StreamType_Output)
    {
        OpcUa_WssOutputStream* tcpStream = (OpcUa_WssOutputStream*)(a_pStrm->Handle);

        if (tcpStream->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        *a_pPosition = tcpStream->Buffer.Position;
    }
    else if (a_pStrm->Type == OpcUa_StreamType_Input)
    {
        OpcUa_WssInputStream* tcpStream = (OpcUa_WssInputStream*)(a_pStrm->Handle);

        if (tcpStream->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        *a_pPosition = tcpStream->Buffer.Position;
    }
    else
    {
        uStatus = OpcUa_BadInvalidArgument;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_Stream_SetPosition
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_SetPosition(
    OpcUa_Stream* a_pStrm,
    OpcUa_UInt32  a_uPosition)
{
OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "SetPosition");

    OpcUa_ReturnErrorIfArgumentNull(a_pStrm);
    OpcUa_ReturnErrorIfInvalidStream(a_pStrm, SetPosition);

    if (a_pStrm->Type == OpcUa_StreamType_Output)
    {
        OpcUa_WssOutputStream* tcpStream = (OpcUa_WssOutputStream*)(a_pStrm->Handle);

        if (tcpStream->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        /* set the position */
        uStatus = OpcUa_Buffer_SetPosition(&(tcpStream->Buffer), a_uPosition);
    }
    else if (a_pStrm->Type == OpcUa_StreamType_Input)
    {
        OpcUa_WssInputStream* tcpStream = (OpcUa_WssInputStream*)(a_pStrm->Handle);

        if (tcpStream->Closed)
        {
            return OpcUa_BadInvalidState;
        }

        uStatus = OpcUa_Buffer_SetPosition(&tcpStream->Buffer, a_uPosition);
    }
    else
    {
        uStatus = OpcUa_BadInvalidArgument;
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_CreateInput
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_CreateInput(  
    OpcUa_Socket                      a_hSocket,
    OpcUa_UInt32                      a_uBufferSize,
    OpcUa_WssConnection_StreamState   a_eState,
    OpcUa_InputStream**               a_ppIstrm)
{
    OpcUa_WssInputStream*   pWssInputStream  = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "CreateInput");

    OpcUa_ReturnErrorIfArgumentNull(a_ppIstrm);

    *a_ppIstrm = OpcUa_Null;

    pWssInputStream = (OpcUa_WssInputStream*)OpcUa_Alloc(sizeof(OpcUa_WssInputStream));
    OpcUa_GotoErrorIfAllocFailed(pWssInputStream);
    OpcUa_MemSet(pWssInputStream, 0, sizeof(OpcUa_WssInputStream));

    pWssInputStream->SanityCheck     = OpcUa_WssInputStream_SanityCheck;
    pWssInputStream->Closed          = OpcUa_False;
    pWssInputStream->Socket          = a_hSocket;
    pWssInputStream->MessageLength   = 0;
    pWssInputStream->State           = OpcUa_WssStream_State_Empty;
    pWssInputStream->ConnectionState = a_eState;
    pWssInputStream->IsFinal         = OpcUa_False;
    pWssInputStream->BufferSize      = a_uBufferSize;

    *a_ppIstrm = (OpcUa_InputStream*)pWssInputStream;

    (*a_ppIstrm)->Type              = OpcUa_StreamType_Input;
    (*a_ppIstrm)->Handle            = pWssInputStream;
    (*a_ppIstrm)->GetPosition       = OpcUa_WssStream_GetPosition;
    (*a_ppIstrm)->SetPosition       = OpcUa_WssStream_SetPosition;
    (*a_ppIstrm)->GetChunkLength    = OpcUa_WssStream_GetChunkLength;
    (*a_ppIstrm)->DetachBuffer      = OpcUa_WssStream_DetachBuffer;
    (*a_ppIstrm)->AttachBuffer      = OpcUa_WssStream_AttachBuffer;
    (*a_ppIstrm)->Close             = OpcUa_WssStream_Close;
    (*a_ppIstrm)->Delete            = OpcUa_WssStream_Delete;
    (*a_ppIstrm)->Read              = OpcUa_WssStream_Read;


OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_Free(pWssInputStream);
    OpcUa_Free(*a_ppIstrm);

    *a_ppIstrm = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStream_CreateOutput
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStream_CreateOutput(  
    OpcUa_Socket                        a_hSocket,
    OpcUa_WssStream_MessageType         a_eMessageType,
    OpcUa_Byte**                        a_ppAttachBuffer,
    OpcUa_UInt32                        a_uBufferSize,
    OpcUa_WssStream_PfnNotifyDisconnect a_pfnDisconnectCB,
    OpcUa_UInt32                        a_uMaxNoOfFlushes,
    OpcUa_WssConnection_StreamState     a_eState,
    OpcUa_OutputStream**                a_ppOstrm)
{
    OpcUa_WssOutputStream*  pWssOutputStream = OpcUa_Null;
    OpcUa_Byte*             pData            = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "CreateOutput");

    OpcUa_ReturnErrorIfArgumentNull(a_ppOstrm);
    *a_ppOstrm = OpcUa_Null;

    if (a_ppAttachBuffer != OpcUa_Null)
    {
        /* if the caller wants the stream to be attached, dont alloc it */
        OpcUa_ReturnErrorIfArgumentNull(*a_ppAttachBuffer);

        /* allocate tcp out stream */
        pWssOutputStream = (OpcUa_WssOutputStream*)OpcUa_Alloc(sizeof(OpcUa_WssOutputStream));
        OpcUa_GotoErrorIfAllocFailed(pWssOutputStream);
        OpcUa_MemSet(pWssOutputStream, 0, sizeof(OpcUa_WssOutputStream));

        /* set data pointer to external buffer */
        pData = *a_ppAttachBuffer;
    }
    else if (a_eMessageType == OpcUa_WssStream_MessageType_SecureChannel)
    {
        /* allocate tcp out stream */
        pWssOutputStream = (OpcUa_WssOutputStream*)OpcUa_Alloc(sizeof(OpcUa_WssOutputStream));
        OpcUa_GotoErrorIfAllocFailed(pWssOutputStream);
        OpcUa_MemSet(pWssOutputStream, 0, sizeof(OpcUa_WssOutputStream));
    }
    else
    {
        /* allocate the stream and buffer in one go */
        OpcUa_UInt32 uAllocSize = (sizeof(OpcUa_WssOutputStream) + a_uBufferSize);

        /* allocate tcp out stream */
        pWssOutputStream = (OpcUa_WssOutputStream*)OpcUa_Alloc(uAllocSize);
        OpcUa_GotoErrorIfAllocFailed(pWssOutputStream);
        OpcUa_MemSet(pWssOutputStream, 0, sizeof(OpcUa_WssOutputStream));

        /* set datapointer to datasegment in stream */
        pData = (OpcUa_Byte*)((OpcUa_Byte*)pWssOutputStream + sizeof(OpcUa_WssOutputStream));
    }

    pWssOutputStream->SanityCheck        = OpcUa_WssOutputStream_SanityCheck;
    pWssOutputStream->MessageType        = a_eMessageType;
    pWssOutputStream->Closed             = OpcUa_False;
    pWssOutputStream->Socket             = a_hSocket;
    pWssOutputStream->BufferSize         = a_uBufferSize;
    pWssOutputStream->NotifyDisconnect   = a_pfnDisconnectCB;
    pWssOutputStream->MaxNoOfFlushes     = a_uMaxNoOfFlushes;
    pWssOutputStream->ConnectionState    = a_eState;

    /* create internal buffer with fixed buffersize. */
    uStatus = OpcUa_Buffer_Initialize( 
        &(pWssOutputStream->Buffer), /* instance           */
        pData,                      /* bufferdata         */
        a_uBufferSize,              /* buffersize         */
        a_uBufferSize,              /* blocksize          */
        a_uBufferSize,              /* maxsize            */
        OpcUa_False);               /* do not free buffer */

    OpcUa_GotoErrorIfBad(uStatus);

    if (a_eState != OpcUa_WssConnection_StreamState_HttpUpgrade && a_eMessageType != OpcUa_WssStream_MessageType_SecureChannel)
    {
        /* move the position to step over the WebSocket frame header*/
        pWssOutputStream->Buffer.Position = OPCUA_WSSSTREAM_WSS_FRAMEHEADER_MAXLENGTH;
        pWssOutputStream->Buffer.Data[0] = 0x82;

        /* set the websockets message type. */
        if (a_eMessageType == OpcUa_WssStream_MessageType_WsPing)
        {
            pWssOutputStream->Buffer.Data[0] = 0x89;
        }
        else if (a_eMessageType == OpcUa_WssStream_MessageType_WsPong)
        {
            pWssOutputStream->Buffer.Data[0] = 0x8A;
        }
        else if (a_eMessageType == OpcUa_WssStream_MessageType_WsClose)
        {
            pWssOutputStream->Buffer.Data[0] = 0x88;
        }
        else if (a_eMessageType == OpcUa_WssStream_MessageType_Hello)
        {
            OpcUa_MemCpy(
                &pWssOutputStream->Buffer.Data[pWssOutputStream->Buffer.Position],
                pWssOutputStream->Buffer.Size,
                OPCUA_WSSSTREAM_SIGNATURE_HELLO,
                OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH);

            pWssOutputStream->Buffer.Position += OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH;
        }
        else if (a_eMessageType == OpcUa_WssStream_MessageType_Acknowledge)
        {
            OpcUa_MemCpy(
                &pWssOutputStream->Buffer.Data[pWssOutputStream->Buffer.Position],
                pWssOutputStream->Buffer.Size,
                OPCUA_WSSSTREAM_SIGNATURE_ACKNOWLEDGE,
                OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH);

            pWssOutputStream->Buffer.Position += OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH;
        }
        else if (a_eMessageType == OpcUa_WssStream_MessageType_Error)
        {
            OpcUa_MemCpy(
                &pWssOutputStream->Buffer.Data[pWssOutputStream->Buffer.Position],
                pWssOutputStream->Buffer.Size,
                OPCUA_WSSSTREAM_SIGNATURE_ERROR,
                OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH);

            pWssOutputStream->Buffer.Position += OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH;
        }
    }

    /* now initialize superclass members */
    *a_ppOstrm = (OpcUa_OutputStream*)pWssOutputStream;

    (*a_ppOstrm)->Type              = OpcUa_StreamType_Output;
    (*a_ppOstrm)->Handle            = pWssOutputStream;
    (*a_ppOstrm)->GetPosition       = OpcUa_WssStream_GetPosition;
    (*a_ppOstrm)->SetPosition       = OpcUa_WssStream_SetPosition;
    (*a_ppOstrm)->GetChunkLength    = OpcUa_WssStream_GetChunkLength;
    (*a_ppOstrm)->DetachBuffer      = OpcUa_WssStream_DetachBuffer;
    (*a_ppOstrm)->AttachBuffer      = OpcUa_WssStream_AttachBuffer;
    (*a_ppOstrm)->Close             = OpcUa_WssStream_Close;
    (*a_ppOstrm)->Delete            = OpcUa_WssStream_Delete;
    (*a_ppOstrm)->Write             = OpcUa_WssStream_Write;
    (*a_ppOstrm)->Flush             = OpcUa_WssStream_Flush;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssStream_Delete((OpcUa_Stream**)&pWssOutputStream);

    *a_ppOstrm = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
* OpcUa_WssStream_CheckHeader
*===========================================================================*/
/** @brief Parses the message header. */
static OpcUa_StatusCode OpcUa_WssStream_CheckHeader(OpcUa_InputStream* a_InputStream)
{
    OpcUa_StatusCode        uStatus         = OpcUa_Good;
    OpcUa_WssInputStream*   pWssInputStream = OpcUa_Null;
    OpcUa_UInt32            nTempPosition   = 0;
    OpcUa_CharA             chTemp          = 'x';
    OpcUa_UInt32            ii              = 0;
    OpcUa_UInt32            jj              = 0;

    pWssInputStream = (OpcUa_WssInputStream*)(a_InputStream->Handle);

    if (pWssInputStream->Buffer.EndOfData > 0)
    {
        pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Unknown;
        pWssInputStream->State = OpcUa_WssStream_State_HeaderStarted;
    }

    /* check if reading an HTTP message. */
    if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_HttpUpgrade)
    {
        OpcUa_Boolean bHeaderComplete = OpcUa_False;

        for (ii = pWssInputStream->Buffer.EndOfData-1; ii > 2; ii--)
        {
            if (pWssInputStream->Buffer.Data[ii] == '\n' && pWssInputStream->Buffer.Data[ii-2] == '\n')
            {
                bHeaderComplete = OpcUa_True;
                pWssInputStream->Buffer.Data[ii-1] = '\0';
                break;
            }
        }

        if (!bHeaderComplete)
        {
            return OpcUa_GoodCallAgain;
        }

        return OpcUa_Good;
    }

    else if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_Open)
    {
        if (pWssInputStream->Buffer.EndOfData < OPCUA_WSSSTREAM_WSS_FRAMESIZE_LENGTH)
        {
            return OpcUa_GoodCallAgain;
        }

        OpcUa_Byte masked = (0x80 & pWssInputStream->Buffer.Data[1]) != 0;
        OpcUa_UInt64 length = (0x7F & pWssInputStream->Buffer.Data[1]);

        OpcUa_Byte uHeaderSize = OPCUA_WSSSTREAM_WSS_FRAMESIZE_LENGTH;

        if (masked)
        {
            uHeaderSize += 4;
        }

        if (length >= 126)
        {
            uHeaderSize += 2;
        }

        if (length >= 127)
        {
            uHeaderSize += 6;
        }

        pWssInputStream->MessageLength = uHeaderSize;

        if (pWssInputStream->Buffer.EndOfData < pWssInputStream->MessageLength)
        {
            return OpcUa_GoodCallAgain;
        }
        
        if (length == 126)
        {
            length = 0;

            for (ii = 2; ii < 4; ii++)
            {
                length <<= 8;
                length += pWssInputStream->Buffer.Data[ii];
            }
        }
        else if (length == 127)
        {
            length = 0;

            for (ii = 2; ii < 10; ii++)
            {
                length <<= 8;
                length += pWssInputStream->Buffer.Data[ii];
            }
        }

        if (length > pWssInputStream->Buffer.Size)
        {
            return OpcUa_BadEncodingError;
        }

        pWssInputStream->WssFrameHeaderLength = uHeaderSize;
        pWssInputStream->MessageLength = (OpcUa_UInt32)length + uHeaderSize;

        if (pWssInputStream->Buffer.EndOfData < pWssInputStream->MessageLength)
        {
            return OpcUa_GoodCallAgain;
        }
        
        /* extract the opcode. */
        switch (pWssInputStream->Buffer.Data[0] & 0x0F)
        {
            case 0x08:
            {
                pWssInputStream->MessageType = OpcUa_WssStream_MessageType_WsClose;
                break;
            }

            case 0x09:
            {
                pWssInputStream->MessageType = OpcUa_WssStream_MessageType_WsPing;
                break;
            }

            case 0x0A:
            {
                pWssInputStream->MessageType = OpcUa_WssStream_MessageType_WsPong;
                break;
            }

            case 0x02:
            {
                pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Unknown;
                break;
            }

            default:
            {
                return OpcUa_BadEncodingError;
            }
        }

        /* unmask the data in the buffer */
        if (masked)
        {
            for (ii = uHeaderSize; ii < pWssInputStream->Buffer.EndOfData; ii++)
            {
                pWssInputStream->Buffer.Data[ii] =  pWssInputStream->Buffer.Data[ii] ^ pWssInputStream->Buffer.Data[uHeaderSize + ((ii-uHeaderSize)%4) - 4];
            } 
        }

        /* check the tcp message header. */
        if (pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Unknown)
        {
            if (pWssInputStream->Buffer.EndOfData < uHeaderSize + OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH)
            {
                return OpcUa_GoodCallAgain;
            }

            nTempPosition = pWssInputStream->Buffer.Position = uHeaderSize;
            chTemp = pWssInputStream->Buffer.Data[uHeaderSize];

            switch(chTemp)
            {
                case 'H': /* Hello HELF */
                {
                    OpcUa_Int res = OpcUa_MemCmp(
                        (OpcUa_Void*)&pWssInputStream->Buffer.Data[nTempPosition],
                        (OpcUa_Void*)OPCUA_WSSSTREAM_SIGNATURE_HELLO,
                        OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH);

                    /* will be processed directly in the host */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Hello;

                    if (res != 0)
                    {
                        return OpcUa_BadEncodingError;
                    }

                    nTempPosition += 3;
                    break;
                }
                case 'A': /* Acknowledge ACKF */
                {
                    OpcUa_Int res = OpcUa_MemCmp(
                        (OpcUa_Void*)&pWssInputStream->Buffer.Data[nTempPosition],
                        (OpcUa_Void*)OPCUA_WSSSTREAM_SIGNATURE_ACKNOWLEDGE,
                        OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH);

                    /* will be processed directly in the host */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Acknowledge;

                    if (res != 0)
                    {
                        return OpcUa_BadEncodingError;
                    }

                    nTempPosition += 3;
                    break;
                }
                case 'E': /* Error ERRF */
                {
                    /* will be processed directly in the host */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Error;
                    pWssInputStream->Buffer.Position += 3;
                    break;
                }
                case 'O': /* OpenSecureChannel  OPNF */
                {
                    OpcUa_Int res = OpcUa_MemCmp(
                        (OpcUa_Void*)&pWssInputStream->Buffer.Data[nTempPosition],
                        (OpcUa_Void*)OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_OPEN,
                        OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH - 1);

                    /* will be forwarded to securechannel */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_SecureChannel;

                    if (res != 0)
                    {
                        return OpcUa_BadEncodingError;
                    }

                    nTempPosition += 3;
                    break;
                }
                case 'C': /* CloseSecureChannel CLOF */
                {
                    OpcUa_Int res = OpcUa_MemCmp
                        ((OpcUa_Void*)&pWssInputStream->Buffer.Data[nTempPosition],
                        (OpcUa_Void*)OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_CLOSE,
                        OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH - 1);

                    /* will be forwarded to securechannel */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_SecureChannel;

                    if (res != 0)
                    {
                        return OpcUa_BadEncodingError;
                    }

                    nTempPosition += 3;
                    break;
                }
                case 'M': /* Message            MSG? */
                {
                    OpcUa_Int res = OpcUa_MemCmp(
                        (OpcUa_Void*)&pWssInputStream->Buffer.Data[nTempPosition],
                        (OpcUa_Void*)OPCUA_WSSSTREAM_SIGNATURE_SECURECHANNEL_MESSAGE,
                        OPCUA_WSSSTREAM_TCP_SIGNATURE_LENGTH - 1);

                    /* will be forwarded to securechannel */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_SecureChannel;

                    if (res != 0)
                    {
                        return OpcUa_BadEncodingError;
                    }

                    nTempPosition += 3;
                    break;
                }
                default:
                {
                    /* invalid signature */
                    pWssInputStream->MessageType = OpcUa_WssStream_MessageType_Invalid;
                    break;
                }
            }

            if (   pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Unknown
                || pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Invalid)
            {
                /* enough data was available, but the first bytes did not match the defined signatures */
                return OpcUa_BadDecodingError;
            }

            chTemp = pWssInputStream->Buffer.Data[nTempPosition];

            if (    pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Error
                ||  pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Hello
                ||  pWssInputStream->MessageType == OpcUa_WssStream_MessageType_Acknowledge)
            {
                /* ignore this field and treat this message as final */
                pWssInputStream->IsFinal = OpcUa_True;
                pWssInputStream->IsAbort = OpcUa_False;
            }
            else
            {
                /* check if message is last in chain */
                if (chTemp == 'F')
                {
                    pWssInputStream->IsFinal = OpcUa_True;
                    pWssInputStream->IsAbort = OpcUa_False;
                }
                else if (chTemp == 'C')
                {
                    pWssInputStream->IsFinal = OpcUa_False;
                    pWssInputStream->IsAbort = OpcUa_False;
                }
                else if (chTemp == 'A')
                {
                    /* no more chunks for this message */
                    pWssInputStream->IsFinal = OpcUa_True;
                    pWssInputStream->IsAbort = OpcUa_True;
                }
                else
                {
                    return OpcUa_BadDecodingError;
                }
            }

            /* signature done */
            nTempPosition++;
            /*OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_CheckHeader: Signature parsed!\n");*/

            /* parse length field */
            if (   pWssInputStream->MessageType != OpcUa_WssStream_MessageType_Unknown
                && pWssInputStream->MessageType != OpcUa_WssStream_MessageType_Invalid)
            {
                OpcUa_UInt32 uMessageLength = 0;

                /* from here, we read through the stream interface; update the state variables */
                pWssInputStream->Buffer.Position = nTempPosition;

                /* since the data is available for sure, no blocking can happen in the following call */
                uStatus = OpcUa_UInt32_BinaryDecode(&uMessageLength, a_InputStream);
                OpcUa_ReturnErrorIfBad(uStatus);
                /* OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_CheckHeader: Messagelength is %d!\n", pWssInputStream->MessageLength); */

                /* message length must match the payload length*/
                if (uMessageLength != pWssInputStream->MessageLength - uHeaderSize)
                {
                    return OpcUa_BadDecodingError;
                }

                pWssInputStream->MessageLength = uMessageLength;
            }

            /* secure channel needs the TCP message headers */
            if (pWssInputStream->MessageType == OpcUa_WssStream_MessageType_SecureChannel)
            {
                pWssInputStream->Buffer.Position -= OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH;
            }
        }
    }

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_WssStream_DataReady
 *===========================================================================*/
/** @brief Called if data is available for reading on a socket attached to a stream.
  *
  * This is kind of a read event handler of the pWssInputStream. The Listener
  * calls this function, if new data is available on the socket. Dependend of
  * the stream state, it starts handling the tcpstream relevant data and
  * gives feedback to the listener, which takes further action, ie. calls
  * the handler.
  *
  * @param a_pIstrm [ in] The stream for which data is ready to be received.
  *
  * @return StatusCode
  */
OpcUa_StatusCode OpcUa_WssStream_DataReady(OpcUa_InputStream* a_pIstrm)
{
    OpcUa_WssInputStream*   pWssInputStream  = OpcUa_Null;
    OpcUa_UInt32            nLength         = 0;

OpcUa_InitializeStatus(OpcUa_Module_TcpStream, "DataReady");

    OpcUa_ReturnErrorIfArgumentNull(a_pIstrm);
    OpcUa_ReturnErrorIfArgumentNull(a_pIstrm->Handle);

    pWssInputStream = (OpcUa_WssInputStream*)a_pIstrm->Handle;

    /************************************************************************************/
    /* prepare the stream to read from socket */

    if (pWssInputStream->State == OpcUa_WssStream_State_Empty)
    {
        /* This is a new stream and a new message. */
        OpcUa_Byte* pData = (OpcUa_Byte*)OpcUa_Alloc(pWssInputStream->BufferSize);
        OpcUa_ReturnErrorIfAllocFailed(pData);

        uStatus = OpcUa_Buffer_Initialize(  &pWssInputStream->Buffer,
                                            pData,
                                            0,
                                            pWssInputStream->BufferSize,
                                            pWssInputStream->BufferSize,
                                            OpcUa_True);

        if (OpcUa_IsBad(uStatus))
        {
            OpcUa_Buffer_Clear(&pWssInputStream->Buffer);
            OpcUa_ReturnStatusCode;
        }

        /* set amount to read from socket */
        if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_HttpUpgrade)
        {
            nLength = OPCUA_WSSSTREAM_HTTP_REQUESTLINE_MAXLENGTH;
        }
        else
        {
            nLength = OPCUA_WSSSTREAM_WSS_FRAMESIZE_LENGTH;
        }
    }
    else /* data has already been received into the stream buffer */
    {
        /* Calculate length of data to read */
        if (pWssInputStream->MessageLength == 0)
        {
            if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_HttpUpgrade)
            {
                nLength = OPCUA_WSSSTREAM_HTTP_REQUESTLINE_MAXLENGTH;
            }
            else
            {
                nLength = pWssInputStream->MessageLength;
            }

            /* read until end of header */
            if (nLength > pWssInputStream->Buffer.Position)
            {
                nLength -= pWssInputStream->Buffer.Position;
            }
        }
        else
        {
            /* header was received and message length is known, receive remaining body data */
            nLength = pWssInputStream->MessageLength - pWssInputStream->Buffer.Position;
        }
    }

    /************************************************************************************/
    /* based on the current stream state, read and do further processing */

    switch(pWssInputStream->State)
    {
    case OpcUa_WssStream_State_Empty:
    case OpcUa_WssStream_State_HeaderStarted: /* header not yet completed */
        {
            /* security check for length exceeds buffersize (which would be an error) */
            if (nLength + pWssInputStream->Buffer.Position > pWssInputStream->BufferSize)
            {
               uStatus = OpcUa_BadInvalidArgument; /* message is too large */
               OpcUa_GotoError;
            }

            do
            {
                /* Read! */
                /*OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_DataReady: (Empty|HeaderStarted) Trying to read %d bytes...\n", nLength);*/
                uStatus = OPCUA_P_SOCKET_READ(  
                    pWssInputStream->Socket,
                    &(pWssInputStream->Buffer.Data[pWssInputStream->Buffer.Position]),
                    nLength,
                    &nLength);

                if (OpcUa_IsBad(uStatus))
                {
                    #ifdef _WIN32
                    /* HA: 23.02.2010 CPU Q9550 (Intel Core 2 Quad 2.83 GHz Prozessor) returned during a stressful
                     * test a OpcUa_BadWouldBlock and a message length of 0.
                     * Without the handling of that return the connection broke down
                     */
                    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
                    {
                        pWssInputStream->State = OpcUa_WssStream_State_HeaderStarted;
                        return OpcUa_GoodCallAgain;
                    }
                    #endif
                    return uStatus;
                }

                /* Update stream markers. Current Position is the new end of data. */
                pWssInputStream->Buffer.EndOfData   = pWssInputStream->Buffer.EndOfData + nLength;
                pWssInputStream->Buffer.Position    = pWssInputStream->Buffer.EndOfData;

                if (uStatus == OpcUa_GoodCallAgain)
                {
                    return OpcUa_GoodCallAgain;
                }

                /*OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_DataReady: %d bytes received\n", nLength);*/

                /* Header had not been fully received (last time). Try parsing now! */
                uStatus = OpcUa_WssStream_CheckHeader(a_pIstrm);

                /* return errors and call again status */
                if (OpcUa_IsBad(uStatus))
                {
                    return uStatus;
                }
            }
            while (OpcUa_IsEqual(OpcUa_GoodCallAgain));

            /* nothing more to doing if reading HTTP upgrade header. */
            if (pWssInputStream->ConnectionState == OpcUa_WssConnection_StreamState_HttpUpgrade)
            {
                return OpcUa_Good;
            }

            /* entire frame has been read now, */
            pWssInputStream->State = OpcUa_WssStream_State_MessageComplete;
            break;
        }
    case OpcUa_WssStream_State_HeaderComplete: /* Header was completed, currently message body */
        {
            /* security check for length exceeds buffersize (which would be an error) */
            if (nLength + pWssInputStream->Buffer.Position > pWssInputStream->BufferSize)
            {
               uStatus = OpcUa_BadInvalidArgument; /* message is too large */
               OpcUa_GotoError;
            }

            if (nLength > 0)
            {
                /* Read! (this might be a second read (actually in most cases) in one event) */
                /*OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_DataReady: (HeaderComplete) Trying to read %d bytes...\n", nLength);*/
                uStatus = OPCUA_P_SOCKET_READ(pWssInputStream->Socket,
                    &(pWssInputStream->Buffer.Data[pWssInputStream->Buffer.Position]),
                    nLength,
                    &nLength);

                /* return errors and call again status */
                if (OpcUa_IsBad(uStatus))
                {
                    if (OpcUa_IsEqual(OpcUa_BadWouldBlock))
                    {
                        /* in this case, only the first 8 Bytes have been received. */
                        /* the header was completed but no further data available.  */
                        /* should happen very rarely; must be tested. */
                        return OpcUa_GoodCallAgain;
                    }
                    else
                    {
                        /* bad statuscode; connection closed */
                        return uStatus;
                    }
                }
            }

            /* Update OpcUa_Buffer markers. (directly without using buffer methods) Current Position is the new end of data. */
            pWssInputStream->Buffer.EndOfData   = pWssInputStream->Buffer.EndOfData + nLength;
            pWssInputStream->Buffer.Position    = pWssInputStream->Buffer.EndOfData;

            OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssStream_DataReady: total %d bytes (%d last) of %d (w/o header) received.\n", pWssInputStream->Buffer.Position, nLength, pWssInputStream->MessageLength - OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH);

            /* Check if message is now complete and notify caller if needed. */
            if (pWssInputStream->MessageLength <= pWssInputStream->Buffer.EndOfData)
            {
                /* complete, set forth with OpcUa_WssStream_State_MessageComplete */
                pWssInputStream->State = OpcUa_WssStream_State_MessageComplete;
            }
            else
            {
                /* if not, call again when more data is available */
                return OpcUa_GoodCallAgain;
            }
        }
    case OpcUa_WssStream_State_MessageComplete: /* just in case... */
        {
            /* The message has been completely received and dispatched to the upper layer. */
            /* This must be the next chunk. */
            pWssInputStream->Buffer.Position = OPCUA_WSSSTREAM_TCP_MESSAGEHEADER_LENGTH;
            break;
        }
    default:
        {
            uStatus = OpcUa_BadInternalError;
            break;
        }
    } /* switch(pWssInputStream->State) */

    /************************************************************************************/

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}
