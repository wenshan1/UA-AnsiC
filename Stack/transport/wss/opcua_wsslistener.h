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

#ifndef _OpcUa_WssListener_H_
#define _OpcUa_WssListener_H_ 1

#include <opcua_listener.h>
#include <opcua_securelistener.h>

OPCUA_BEGIN_EXTERN_C

/** 
* @brief Function, that needs to be implemented to receive notifications about secure channel events.
*
* @param uSecureChannelId      [in] The id assigned to the secure channel.
* @param eEvent                [in] What type of event on the secure channel occured.
* @param uStatus               [in] The result of the operation.
* @param pbsClientCertificate  [in] The certificate of the client.
* @param sSecurityPolicy       [in] The security policy in case of open or renew.
* @param eMessageSecurityMode  [in] What type of event on the secure channel occured.
* @param uRequestedLifetime    [in] The requested securechannel lifetime.
* @param pCallbackData         [in] Data pointer received at creation.
*/
typedef OpcUa_StatusCode (OpcUa_WssListener_PfnSecureChannelCallback)(
    OpcUa_UInt32                                        uSecureChannelId,
    OpcUa_SecureListener_SecureChannelEvent             eSecureChannelEvent,
    OpcUa_StatusCode                                    uStatus,
    OpcUa_ByteString*                                   pbsClientCertificate,
    OpcUa_String*                                       sSecurityPolicy,
    OpcUa_UInt16                                        uMessageSecurityModes,
    OpcUa_Void*                                         pCallbackData);

/**
  @brief Creates a new tcp listener object.

  @param listener [out] The new listener.
*/
OPCUA_EXPORT OpcUa_StatusCode OpcUa_WssListener_Create(
    OpcUa_ByteString*                           pServerCertificate,
    OpcUa_Key*                                  pServerPrivateKey,
    OpcUa_Void*                                 pPKIConfig,
    OpcUa_WssListener_PfnSecureChannelCallback* pfSecureChannelCallback,
    OpcUa_Void*                                 pSecureChannelCallbackData,
    OpcUa_Listener**                            pListener);

OPCUA_END_EXTERN_C

#endif /* _OpcUa_WssListener_H_ */
