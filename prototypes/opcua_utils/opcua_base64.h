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

#ifndef _OpcUa_Base64_H_
#define _OpcUa_Base64_H_ 1

#ifdef OPCUA_HAVE_BASE64

OPCUA_BEGIN_EXTERN_C

OpcUa_StatusCode OpcUa_Base64_Encode(
    OpcUa_Byte*     a_pBytes,
    OpcUa_Int32     a_iByteCount,
    OpcUa_StringA*  a_psString);

OpcUa_StatusCode OpcUa_Base64_Decode(
	const OpcUa_CharA* a_sString,
    OpcUa_Int32*       a_piByteCount,
    OpcUa_Byte**       a_ppBytes);

OPCUA_END_EXTERN_C

#endif /* OPCUA_HAVE_BASE64 */
#endif /* _OpcUa_Base64_H_ */
