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

#ifdef OPCUA_HAVE_HTTPSAPI

#include <opcua_list.h>
#include <opcua_utilities.h>
#include <opcua_wss_internal.h>

/*============================================================================
 * OpcUa_WssHeader_Create
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeader_Create(
    OpcUa_String*       a_pHeaderName,
    OpcUa_String*       a_pHeaderValue,
    OpcUa_WssHeader** a_ppHttpHeader)
{
    OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeader_Create");

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderName);
    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderValue);
    OpcUa_ReturnErrorIfArgumentNull(a_ppHttpHeader);

    pHttpHeader = (OpcUa_WssHeader*)OpcUa_Alloc(sizeof(OpcUa_WssHeader));
    OpcUa_ReturnErrorIfArgumentNull(pHttpHeader);

    OpcUa_WssHeader_Initialize(pHttpHeader);

    uStatus = OpcUa_String_StrnCpy(&pHttpHeader->Name,
                                   a_pHeaderName,
                                   OPCUA_STRING_LENDONTCARE);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_String_StrnCpy(&pHttpHeader->Value,
                                   a_pHeaderValue,
                                   OPCUA_STRING_LENDONTCARE);
    OpcUa_GotoErrorIfBad(uStatus);

    *a_ppHttpHeader = pHttpHeader;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssHeader_Delete(&pHttpHeader);
    *a_ppHttpHeader = OpcUa_Null;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeader_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_WssHeader_Initialize(OpcUa_WssHeader* a_pHttpHeader)
{
    if(a_pHttpHeader != OpcUa_Null)
    {
        OpcUa_String_Initialize(&a_pHttpHeader->Name);
        OpcUa_String_Initialize(&a_pHttpHeader->Value);
    }
}

/*============================================================================
 * OpcUa_WssHeader_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_WssHeader_Clear(OpcUa_WssHeader* a_pValue)
{
    if(a_pValue != OpcUa_Null)
    {
        OpcUa_String_Clear(&a_pValue->Name);
        OpcUa_String_Clear(&a_pValue->Value);
    }
}

/*============================================================================
 * OpcUa_WssHeader_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_WssHeader_Delete(OpcUa_WssHeader** a_ppHttpHeader)
{
    if(a_ppHttpHeader != OpcUa_Null && *a_ppHttpHeader != OpcUa_Null)
    {
        OpcUa_WssHeader_Clear(*a_ppHttpHeader);

        OpcUa_Free(*a_ppHttpHeader);

        *a_ppHttpHeader = OpcUa_Null;
    }
}

/*============================================================================
 * OpcUa_WssHeader_Serialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeader_Serialize(
    OpcUa_WssHeader*  a_pHeader,
    OpcUa_Buffer*       a_pBuffer)
{
OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeader_Serialize");

    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);
    OpcUa_ReturnErrorIfArgumentNull(a_pHeader);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pHeader->Name);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)": ", 2);
    OpcUa_GotoErrorIfBad(uStatus);

    if(!OpcUa_String_IsNull(&a_pHeader->Value))
    {
        uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pHeader->Value);
        OpcUa_GotoErrorIfBad(uStatus);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_Trace(OPCUA_TRACE_LEVEL_ERROR, "OpcUa_WssHeader_Serialize: Could not serialize HTTP header. (0x%08X)\n", uStatus);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeader_Parse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeader_Parse(
    OpcUa_String*       a_pMessageLine,
    OpcUa_WssHeader** a_ppHttpHeader)
{
    OpcUa_CharA* pInitialChar   = OpcUa_Null;
    OpcUa_CharA* pTerminalChar  = OpcUa_Null;
    OpcUa_UInt32 uCharCount     = 0;
    OpcUa_CharA* pLineStart     = OpcUa_Null;
    OpcUa_UInt32 uLineLength    = 0;
    OpcUa_UInt32 uPos           = 0;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeader_Parse");

    OpcUa_ReturnErrorIfArgumentNull(a_ppHttpHeader);

    OpcUa_ReturnErrorIfTrue(    OpcUa_String_IsNull(a_pMessageLine)
                             || OpcUa_String_IsEmpty(a_pMessageLine),
                            OpcUa_BadInvalidArgument);

    *a_ppHttpHeader = (OpcUa_WssHeader*)OpcUa_Alloc(sizeof(OpcUa_WssHeader));
    OpcUa_ReturnErrorIfAllocFailed(*a_ppHttpHeader);

    OpcUa_WssHeader_Initialize(*a_ppHttpHeader);

    pLineStart  = OpcUa_String_GetRawString(a_pMessageLine);
    uLineLength = OpcUa_String_StrLen(a_pMessageLine);

    /* search semicolon */
    pInitialChar    = pLineStart;
    for(uPos = 0; uPos < uLineLength; uPos++)
    {
        if(pLineStart[uPos] == ':')
        {
            pTerminalChar = &pLineStart[uPos];
            break;
        }
    }

    OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

    uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);
    OpcUa_GotoErrorIfTrue(uCharCount == 0, OpcUa_BadInvalidArgument);

    uStatus = OpcUa_String_AttachToString(
        pInitialChar,
        uCharCount,
        uCharCount,
        OpcUa_False,
        OpcUa_False,
        &((*a_ppHttpHeader)->Name));

    OpcUa_GotoErrorIfBad(uStatus);

    /* skip semicolon */
    pInitialChar = pTerminalChar + 1;

    /* skip any LWS characters */
    while (*pInitialChar)
    {
        if(*pInitialChar != ' ' && *pInitialChar != '\t')
        {
            break;
        }

        uCharCount++;
        pInitialChar++;
    }

    uStatus = OpcUa_String_AttachToString(
        pInitialChar,
        uLineLength - uCharCount - 1,
        0,
        OpcUa_False,
        OpcUa_False,
        &((*a_ppHttpHeader)->Value));

    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssHeader_Delete(a_ppHttpHeader);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssRequestLine_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_WssRequestLine_Initialize(OpcUa_WssRequestLine* a_pValue)
{
    if(a_pValue != OpcUa_Null)
    {
        OpcUa_String_Initialize(&a_pValue->RequestMethod);
        OpcUa_String_Initialize(&a_pValue->RequestUri);
        OpcUa_String_Initialize(&a_pValue->HttpVersion);
        OpcUa_String_AttachReadOnly(&a_pValue->HttpVersion, OPCUA_HTTP_VERSION);
    }
}

/*============================================================================
 * OpcUa_WssRequestLine_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_WssRequestLine_Clear(OpcUa_WssRequestLine* a_pValue)
{
    if(a_pValue != OpcUa_Null)
    {
        OpcUa_String_Clear(&a_pValue->RequestMethod);
        OpcUa_String_Clear(&a_pValue->RequestUri);
        OpcUa_String_Clear(&a_pValue->HttpVersion);
    }
}

/*============================================================================
 * OpcUa_WssRequestLine_Serialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssRequestLine_Serialize(
    OpcUa_WssRequestLine* a_pRequestLine,
    OpcUa_Buffer*           a_pBuffer)
{
OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssRequestLine_Serialize");

    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);
    OpcUa_ReturnErrorIfArgumentNull(a_pRequestLine);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pRequestLine->RequestMethod);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\x20", 1);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pRequestLine->RequestUri);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\x20", 1);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pRequestLine->HttpVersion);
    OpcUa_GotoErrorIfBad(uStatus);

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\r\n", 2);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssRequestLine_Parse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssRequestLine_Parse(
    OpcUa_String*            a_pMessageLine,
    OpcUa_WssRequestLine*  a_pRequestLine)
{
    OpcUa_CharA* pInitialChar   = OpcUa_Null;
    OpcUa_CharA* pTerminalChar  = OpcUa_Null;
    OpcUa_UInt32 uCharCount     = 0;
    OpcUa_CharA* pLineStart     = OpcUa_Null;
    OpcUa_UInt32 uLineLength    = 0;
    OpcUa_UInt32 uPos           = 0;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssRequestLine_Parse");

    OpcUa_ReturnErrorIfTrue(    OpcUa_String_IsNull(a_pMessageLine)
                             || OpcUa_String_IsEmpty(a_pMessageLine),
                            OpcUa_BadInvalidArgument);

    OpcUa_ReturnErrorIfArgumentNull(a_pRequestLine);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG, "OpcUa_WssRequestLine_Parse: %.*s\n", OpcUa_String_StrLen(a_pMessageLine), OpcUa_String_GetRawString(a_pMessageLine));


    OpcUa_WssRequestLine_Initialize(a_pRequestLine);

    pLineStart  = OpcUa_String_GetRawString(a_pMessageLine);
    uLineLength = OpcUa_String_StrLen(a_pMessageLine);


    /* get method */
    pInitialChar    = pLineStart;
    for(uPos = 0; uPos < uLineLength; uPos++)
    {
        if(pLineStart[uPos] == ' ')
        {
            pTerminalChar = &pLineStart[uPos];
            break;
        }
    }

    OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

    uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);
    OpcUa_GotoErrorIfTrue(uCharCount == 0, OpcUa_BadInvalidArgument);

    uStatus = OpcUa_String_AttachToString(pInitialChar,
                                          uCharCount,
                                          uCharCount,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                          OpcUa_False,
                                          &(a_pRequestLine->RequestMethod));
    OpcUa_GotoErrorIfBad(uStatus);


    /* get URI */
    pInitialChar  = pTerminalChar + 1;
    uPos++;

    for(; uPos < uLineLength; uPos++)
    {
        if(pLineStart[uPos] == ' ')
        {
            pTerminalChar = &pLineStart[uPos];
            break;
        }
    }

    OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

    uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);
    OpcUa_GotoErrorIfTrue(uCharCount == 0, OpcUa_BadInvalidArgument);

    uStatus = OpcUa_String_AttachToString(pInitialChar,
                                          uCharCount,
                                          uCharCount,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                          OpcUa_False,
                                          &(a_pRequestLine->RequestUri));
    OpcUa_GotoErrorIfBad(uStatus);


    /* get HTTP Version */
    pInitialChar = pTerminalChar + 1;
    uPos++;

    if(     OpcUa_StrnCmpA(pInitialChar, "HTTP/1.1", uLineLength - uPos) != 0
#if OPCUA_HTTPS_ALLOW_HTTP10
        &&  OpcUa_StrnCmpA(pInitialChar, "HTTP/1.0", uLineLength - uPos) != 0,
#endif /* OPCUA_HTTPS_ALLOW_HTTP10 */
        )
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    uStatus = OpcUa_String_AttachToString(pInitialChar,
                                          OPCUA_STRINGLENZEROTERMINATED,
                                          0,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                          OpcUa_False,
                                          &(a_pRequestLine->HttpVersion));
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssRequestLine_Clear(a_pRequestLine);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStatusLine_Initialize
 *===========================================================================*/
OpcUa_Void OpcUa_WssStatusLine_Initialize(OpcUa_WssStatusLine* a_pValue)
{
    if(a_pValue != OpcUa_Null)
    {
        OpcUa_String_Initialize(&a_pValue->HttpVersion);
        OpcUa_String_AttachReadOnly(&a_pValue->HttpVersion, OPCUA_HTTP_VERSION);

        a_pValue->StatusCode = 200;

        OpcUa_String_Initialize(&a_pValue->ReasonPhrase);
    }
}

/*============================================================================
 * OpcUa_WssStatusLine_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_WssStatusLine_Clear(OpcUa_WssStatusLine* a_pValue)
{
    if(a_pValue != OpcUa_Null)
    {
        OpcUa_String_Clear(&a_pValue->HttpVersion);
        a_pValue->StatusCode = 0;
        OpcUa_String_Clear(&a_pValue->ReasonPhrase);
    }
}

/*============================================================================
 * OpcUa_WssStatusLine_Serialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStatusLine_Serialize(
    OpcUa_WssStatusLine*  a_pStatusLine,
    OpcUa_Buffer*           a_pBuffer)
{
    OpcUa_CharA chStatusCode[0x20] = {'\0'}; /* enough for 3 digits
                                                and 2 whitespaces */

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssStatusLine_Serialize");

    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);
    OpcUa_ReturnErrorIfArgumentNull(a_pStatusLine);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pStatusLine->HttpVersion);
    OpcUa_GotoErrorIfBad(uStatus);

    /* format status code */
    OpcUa_SPrintfA(chStatusCode,
#if OPCUA_USE_SAFE_FUNCTIONS
        sizeof(chStatusCode)/sizeof(chStatusCode[0]),
#endif
        " %.3u ",
        (unsigned int)a_pStatusLine->StatusCode);

    uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, OpcUa_String_FromCString(chStatusCode));
    OpcUa_GotoErrorIfBad(uStatus);

    if(    !OpcUa_String_IsNull(&a_pStatusLine->ReasonPhrase)
        && !OpcUa_String_IsEmpty(&a_pStatusLine->ReasonPhrase))
    {
        uStatus = OpcUa_Wss_WriteStringToBuffer(a_pBuffer, &a_pStatusLine->ReasonPhrase);
        OpcUa_GotoErrorIfBad(uStatus);
    }

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\r\n", 2);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssStatusLine_Parse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssStatusLine_Parse(
    OpcUa_String*           a_pMessageLine,
    OpcUa_WssStatusLine*  a_pStatusLine)
{
    OpcUa_CharA* pInitialChar       = OpcUa_Null;
    OpcUa_CharA* pTerminalChar      = OpcUa_Null;
    OpcUa_UInt32 uCharCount         = 0;
    OpcUa_CharA  chStatusCode[4]    = {'\0', '\0', '\0', '\0'};
    OpcUa_CharA* pLineStart         = OpcUa_Null;
    OpcUa_UInt32 uLineLength        = 0;
    OpcUa_UInt32 uPos               = 0;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssStatusLine_Parse");

    OpcUa_ReturnErrorIfTrue(    OpcUa_String_IsNull(a_pMessageLine)
                             || OpcUa_String_IsEmpty(a_pMessageLine),
                            OpcUa_BadInvalidArgument);

    OpcUa_ReturnErrorIfArgumentNull(a_pStatusLine);
    OpcUa_WssStatusLine_Initialize(a_pStatusLine);

    pLineStart  = OpcUa_String_GetRawString(a_pMessageLine);
    uLineLength = OpcUa_String_StrLen(a_pMessageLine);


    /* get HTTP version */
    pInitialChar = pLineStart;
    for(uPos = 0; uPos < uLineLength; uPos++)
    {
        if(pLineStart[uPos] == ' ')
        {
            pTerminalChar = &pLineStart[uPos];
            break;
        }
    }

    OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

    uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);
    OpcUa_GotoErrorIfTrue(uCharCount == 0, OpcUa_BadInvalidArgument);

    OpcUa_GotoErrorIfTrue(    OpcUa_StrnCmpA(pInitialChar, "HTTP/1.1", uCharCount) != 0
                           && OpcUa_StrnCmpA(pInitialChar, "HTTP/1.0", uCharCount) != 0,
                          OpcUa_BadInvalidArgument);

    uStatus = OpcUa_String_AttachToString(pInitialChar,
                                          uCharCount,
                                          uCharCount,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                          OpcUa_False,
                                          &(a_pStatusLine->HttpVersion));
    OpcUa_GotoErrorIfBad(uStatus);


    /* get status code */
    pInitialChar = pTerminalChar + 1;
    ++uPos;

    for(; uPos < uLineLength; uPos++)
    {
        if(pLineStart[uPos] == ' ')
        {
            pTerminalChar = &pLineStart[uPos];
            break;
        }
    }

    OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

    uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);
    OpcUa_GotoErrorIfTrue(uCharCount != 3, OpcUa_BadInvalidArgument);

    uStatus = OpcUa_MemCpy(chStatusCode, 4, pInitialChar, 3);
    OpcUa_GotoErrorIfBad(uStatus);

    a_pStatusLine->StatusCode = (OpcUa_UInt32)OpcUa_CharAToInt(chStatusCode);
    OpcUa_GotoErrorIfTrue(a_pStatusLine->StatusCode == 0,
                          OpcUa_BadInvalidArgument);


    /* get reason phrase */
    uStatus = OpcUa_String_AttachToString(++pTerminalChar,
                                          (uLineLength - uPos) - 1,
                                          0,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                          OpcUa_False,
                                          &(a_pStatusLine->ReasonPhrase));
    OpcUa_GotoErrorIfBad(uStatus);

    OpcUa_Trace(OPCUA_TRACE_LEVEL_DEBUG,
                "OpcUa_WssStatusLine_Parse: Version %.*s; Status %u; Reason %.*s;\n",
                OpcUa_String_StrLen(&a_pStatusLine->HttpVersion),
                OpcUa_String_GetRawString(&a_pStatusLine->HttpVersion),
                a_pStatusLine->StatusCode,
                OpcUa_String_StrLen(&a_pStatusLine->ReasonPhrase),
                OpcUa_String_GetRawString(&a_pStatusLine->ReasonPhrase));

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssStatusLine_Clear(a_pStatusLine);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeaderCollection_Clear
 *===========================================================================*/
OpcUa_Void OpcUa_WssHeaderCollection_Clear(OpcUa_WssHeaderCollection* a_pHeaderCollection)
{
    if(a_pHeaderCollection != OpcUa_Null)
    {
        OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

        OpcUa_List_ResetCurrent(a_pHeaderCollection);
        pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetCurrentElement(a_pHeaderCollection);

        while(pHttpHeader != OpcUa_Null)
        {
            OpcUa_WssHeader_Delete(&pHttpHeader);
            pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetNextElement(a_pHeaderCollection);
        }

        OpcUa_List_Clear(a_pHeaderCollection);
    }
}

/*============================================================================
 * OpcUa_WssHeaderCollection_Delete
 *===========================================================================*/
OpcUa_Void OpcUa_WssHeaderCollection_Delete(OpcUa_WssHeaderCollection** a_ppHeaderCollection)
{
    if(a_ppHeaderCollection != OpcUa_Null && *a_ppHeaderCollection != OpcUa_Null)
    {
        OpcUa_WssHeaderCollection_Clear(*a_ppHeaderCollection);
        OpcUa_List_Delete(a_ppHeaderCollection);
    }
}

/*============================================================================
 * OpcUa_WssHeaderCollection_AddHeader
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_AddHeader(
    OpcUa_WssHeaderCollection* a_pHeaderCollection,
    OpcUa_WssHeader*           a_pHttpHeader)
{
    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderCollection);
    OpcUa_ReturnErrorIfArgumentNull(a_pHttpHeader);

    OpcUa_Trace(    OPCUA_TRACE_LEVEL_DEBUG,
                    "OpcUa_WssHeaderCollection_AddHeader: %*.*s: %*.*s\n",
                    OpcUa_String_StrLen(&a_pHttpHeader->Name), OpcUa_String_StrLen(&a_pHttpHeader->Name), OpcUa_String_GetRawString((&a_pHttpHeader->Name)),
                    OpcUa_String_StrLen(&a_pHttpHeader->Value), OpcUa_String_StrLen(&a_pHttpHeader->Value), OpcUa_String_GetRawString((&a_pHttpHeader->Value)));

    return OpcUa_List_AddElementToEnd(a_pHeaderCollection, a_pHttpHeader);
}

/*============================================================================
 * OpcUa_WssHeaderCollection_FindHeader
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_FindHeader(
    OpcUa_WssHeaderCollection* a_pHeaderCollection,
    OpcUa_String*                a_pHeaderName,
    OpcUa_WssHeader**          a_ppHttpHeader)
{
    OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeaderCollection_FindHeader");

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderCollection);
    OpcUa_ReturnErrorIfArgumentNull(a_ppHttpHeader);

    if(OpcUa_String_IsNull(a_pHeaderName) || OpcUa_String_IsEmpty(a_pHeaderName))
    {
        return OpcUa_BadInvalidArgument;
    }

    *a_ppHttpHeader = OpcUa_Null;

    OpcUa_List_ResetCurrent(a_pHeaderCollection);
    pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetCurrentElement(a_pHeaderCollection);

    while(pHttpHeader != OpcUa_Null)
    {
        if(OpcUa_String_StrnCmp(&pHttpHeader->Name,
                                a_pHeaderName,
                                OPCUA_STRING_LENDONTCARE,
                                OpcUa_True) == 0)
        {
            *a_ppHttpHeader = pHttpHeader;
            break;
        }

        pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetNextElement(a_pHeaderCollection);
    }

    uStatus = (*a_ppHttpHeader != OpcUa_Null)? OpcUa_Good: OpcUa_GoodNoData;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeaderCollection_GetValue
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_GetValue(
    OpcUa_WssHeaderCollection* a_pHeaderCollection,
    OpcUa_String*                a_pHeaderName,
    OpcUa_Boolean                a_bGiveCopy,
    OpcUa_String*                a_pHeaderValue)
{
    OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeaderCollection_GetValue");

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderCollection);

    if(OpcUa_String_IsNull(a_pHeaderName) || OpcUa_String_IsEmpty(a_pHeaderName))
    {
        return OpcUa_BadInvalidArgument;
    }

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderValue);

    OpcUa_String_Clear(a_pHeaderValue);

    uStatus = OpcUa_WssHeaderCollection_FindHeader(a_pHeaderCollection, a_pHeaderName, &pHttpHeader);
    OpcUa_GotoErrorIfBad(uStatus);

    if(uStatus != OpcUa_GoodNoData)
    {
        if(a_bGiveCopy != OpcUa_False)
        {
            uStatus = OpcUa_String_StrnCpy(a_pHeaderValue, &(pHttpHeader->Value), OPCUA_STRING_LENDONTCARE);
        }
        else
        {
            OpcUa_StringA   strRaw  = OpcUa_Null;
            OpcUa_UInt      uLength = 0;

            strRaw  = OpcUa_String_GetRawString(&(pHttpHeader->Value));
            uLength = OpcUa_String_StrSize(&(pHttpHeader->Value));

            uStatus = OpcUa_String_AttachToString(strRaw,
                                                    uLength,
                                                    uLength,
                                                    OpcUa_False,
                                                    OpcUa_False,
                                                    a_pHeaderValue);
        }
        OpcUa_GotoErrorIfBad(uStatus);
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_String_Clear(a_pHeaderValue);

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeaderCollection_SetValue
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_SetValue(
    OpcUa_WssHeaderCollection* a_pHeaderCollection,
    OpcUa_String*                a_pHeaderName,
    OpcUa_String*                a_pHeaderValue)
{
    OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeaderCollection_SetValue");

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderCollection);

    OpcUa_ReturnErrorIfTrue(    OpcUa_String_IsNull(a_pHeaderName)
                             || OpcUa_String_IsEmpty(a_pHeaderName),
                            OpcUa_BadInvalidArgument)

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderValue);

    uStatus = OpcUa_WssHeaderCollection_FindHeader(a_pHeaderCollection, a_pHeaderName, &pHttpHeader);
    OpcUa_GotoErrorIfBad(uStatus);

    if(uStatus != OpcUa_GoodNoData)
    {
        OpcUa_Trace(    OPCUA_TRACE_LEVEL_DEBUG,
                        "OpcUa_WssHeaderCollection_SetValue: %.*s: %.*s\n",
                        OpcUa_String_StrLen(&pHttpHeader->Name), OpcUa_String_GetRawString((&pHttpHeader->Name)),
                        OpcUa_String_StrLen(&pHttpHeader->Value), OpcUa_String_GetRawString((&pHttpHeader->Value)));

        /* header is found, set the new value */
        uStatus = OpcUa_String_StrnCpy(&(pHttpHeader->Value), a_pHeaderValue, OPCUA_STRING_LENDONTCARE);
        OpcUa_GotoErrorIfBad(uStatus);
    }
    else
    {
        /* header is not found, add the new one */
        uStatus = OpcUa_WssHeader_Create(a_pHeaderName, a_pHeaderValue, &pHttpHeader);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_WssHeaderCollection_AddHeader(    a_pHeaderCollection,
                                                            pHttpHeader);

        if(OpcUa_IsBad(uStatus))
        {
            OpcUa_WssHeader_Delete(&pHttpHeader);
        }
    }

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;
OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeaderCollection_Serialize
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_Serialize(
    OpcUa_WssHeaderCollection* a_pHeaderCollection,
    OpcUa_Buffer*                a_pBuffer)
{
    OpcUa_WssHeader* pHttpHeader = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeaderCollection_Serialize");

    OpcUa_ReturnErrorIfArgumentNull(a_pHeaderCollection);
    OpcUa_ReturnErrorIfArgumentNull(a_pBuffer);

    OpcUa_List_ResetCurrent(a_pHeaderCollection);
    pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetCurrentElement(a_pHeaderCollection);

    while(pHttpHeader != OpcUa_Null)
    {
        uStatus = OpcUa_WssHeader_Serialize(pHttpHeader, a_pBuffer);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\r\n", 2);
        OpcUa_GotoErrorIfBad(uStatus);

        pHttpHeader = (OpcUa_WssHeader*)OpcUa_List_GetNextElement(a_pHeaderCollection);
    }

    uStatus = OpcUa_Buffer_Write(a_pBuffer, (OpcUa_Byte*)"\r\n", 2);
    OpcUa_GotoErrorIfBad(uStatus);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

OpcUa_FinishErrorHandling;
}

/*============================================================================
 * OpcUa_WssHeaderCollection_Parse
 *===========================================================================*/
OpcUa_StatusCode OpcUa_WssHeaderCollection_Parse(
    OpcUa_String*                 a_pHeaderString,
    OpcUa_WssHeaderCollection** a_ppHeaderCollection)
{
    OpcUa_CharA*      pInitialChar   = OpcUa_Null;
    OpcUa_CharA*      pTerminalChar  = OpcUa_Null;
    OpcUa_UInt32      uCharCount     = 0;
    OpcUa_String      sSubstring     = OPCUA_STRING_STATICINITIALIZER;
    OpcUa_WssHeader* pHttpHeader    = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_HttpStream, "OpcUa_WssHeaderCollection_Parse");

    OpcUa_ReturnErrorIfTrue(    OpcUa_String_IsNull(a_pHeaderString)
                             || OpcUa_String_IsEmpty(a_pHeaderString),
                            OpcUa_BadInvalidArgument);
    OpcUa_ReturnErrorIfArgumentNull(a_ppHeaderCollection);

    uStatus = OpcUa_WssHeaderCollection_Create(a_ppHeaderCollection);
    OpcUa_GotoErrorIfBad(uStatus);

    pInitialChar = OpcUa_String_GetRawString(a_pHeaderString);

    while(     pInitialChar != OpcUa_Null
           && *pInitialChar != '\0')
    {
        pTerminalChar = OpcUa_StrStrA(pInitialChar, "\r\n");

        /* check whether the header is properly terminated by \r\n */
        OpcUa_GotoErrorIfNull(pTerminalChar, OpcUa_BadInvalidArgument);

        uCharCount = (OpcUa_UInt32)(pTerminalChar - pInitialChar);

        uStatus = OpcUa_String_AttachToString(pInitialChar,
                                              uCharCount,
                                              uCharCount,
#if OPCUA_HTTPS_COPYHEADERS
                                          OpcUa_True,
#else
                                          OpcUa_False,
#endif
                                              OpcUa_False,
                                              &sSubstring);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_WssHeader_Parse(&sSubstring, &pHttpHeader);
        OpcUa_GotoErrorIfBad(uStatus);

        uStatus = OpcUa_WssHeaderCollection_AddHeader(*a_ppHeaderCollection, pHttpHeader);
        OpcUa_GotoErrorIfBad(uStatus);

        pInitialChar = (pTerminalChar != OpcUa_Null)? pTerminalChar + 2: pTerminalChar;
    }

    OpcUa_String_Clear(&sSubstring);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    OpcUa_WssHeader_Delete(&pHttpHeader);
    OpcUa_WssHeaderCollection_Delete(a_ppHeaderCollection);
    OpcUa_String_Clear(&sSubstring);

OpcUa_FinishErrorHandling;
}

#endif /* OPCUA_HAVE_HTTPSAPI */
