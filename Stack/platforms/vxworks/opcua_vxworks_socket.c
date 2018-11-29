/* opcua_vxworks_socket.c - socketpair for OPCUA */

/* ========================================================================
 * Copyright (c) 2005-2018 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

/* Copyright 2018 Wind River Systems, Inc. */

/*
modification history
--------------------
08nov18,lan  written.
*/

#include <vxWorks.h>
#include <stdlib.h>
#include <string.h>
#include <ioLib.h>
#include <errnoLib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <opcua_vxworks_socket.h>

/*******************************************************************************
*
* socketpair - create a pair of connected sockets
* 
* The socketpair() function creates an unbound pair of connected sockets in a 
* specified domain, of a specified type, under the protocol optionally specified 
* by the protocol argument. The file descriptors used in referencing the 
* created sockets be returned in socket_vector[0] and socket_vector[1].
*
* Note: For OPCUA, we only need socketpair() to send/receive events.
*       This function only implements streaming.
*/

int socketpair
    (
    int domain,  
    int type, 
    int protocol, 
    int sv[2]
    )
    {
    struct addrinfo * res = NULL;
    struct addrinfo   hints;
    int               ret;
    int               listenSock  = -1;
    int               connectSock = -1;
    int               acceptSock  = -1;
    socklen_t         addrlen;
    
    (void) memset (&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(NULL, "0", &hints, &res);
    if (ret < 0)
    	goto fail;
    listenSock = socket(res->ai_family, SOCK_STREAM, res->ai_protocol);
    if (listenSock == -1)
    	goto fail;
    
    connectSock = socket(res->ai_family, SOCK_STREAM, res->ai_protocol);
    if (connectSock == -1)
    	goto fail;  

    /* Bind to an ephemeral port */
    if (bind(listenSock, res->ai_addr, (socklen_t) res->ai_addrlen) != 0)
        goto fail;  

    addrlen = (socklen_t) res->ai_addrlen;
    
    if (getsockname(listenSock, res->ai_addr, &addrlen) != 0)
        goto fail; 

    if (listen(listenSock, 1) != 0)
        goto fail;

    if (connect(connectSock, res->ai_addr, (socklen_t) res->ai_addrlen) != 0)
        goto fail;

    acceptSock = accept(listenSock, NULL, NULL);
    if (acceptSock == -1)
        goto fail;
    
    sv[0] = connectSock;
    sv[1] = acceptSock;
    close (listenSock);
    freeaddrinfo(res);
    return 0;
fail:
    if (res != NULL)
    	freeaddrinfo(res);
    if (listenSock != -1)
    	close (listenSock);
    if (connectSock != -1)
    	close (connectSock);
    return -1;        
    }
