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

/* Copyright (c) 2018 Wind River Systems, Inc. */

/*
modification history
--------------------
06nov18,lan  use VxWorks native api to implement OPC-UA mutex.
*/

#include <vxWorks.h>
#include <semLib.h>
#include <opcua_platformdefs.h>
#include <opcua.h>

#include <opcua_mutex.h>
#include <opcua_p_mutex.h>
#include <opcua_p_memory.h>
#include <string.h>
#include <stdlib.h>

/*============================================================================
 * Allocate the mutex.
 *===========================================================================*/
OpcUa_StatusCode OPCUA_DLLCALL OpcUa_P_Mutex_Create
    (
    OpcUa_Mutex* a_phMutex
    )
    {
    SEM_ID          semid;

    semid = semMCreate (SEM_Q_PRIORITY | SEM_INVERSION_SAFE | SEM_DELETE_SAFE);

    if (semid == SEM_ID_NULL)
        {
        return OpcUa_Bad;
        }

    *a_phMutex = semid;

    return OpcUa_Good;
    }

/*============================================================================
 * Clear and free the mutex.
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Mutex_Delete
    (
    OpcUa_Mutex* a_phMutex
    )
    {
    SEM_ID          semid;

    if (a_phMutex == OpcUa_Null || *a_phMutex == OpcUa_Null)
        {
        return;
        }

    semid = (SEM_ID) *a_phMutex;

    (void) semDelete (semid);
    *a_phMutex = OpcUa_Null;
    }

/*============================================================================
 * Lock the mutex.
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Mutex_Lock
    (
    OpcUa_Mutex hMutex
    )
    {
    SEM_ID          semid;

    if (hMutex != OpcUa_Null)
        {
        semid = (SEM_ID) hMutex;
        (void) semTake (semid, WAIT_FOREVER);
        }
    }

/*============================================================================
 * Unlock the mutex.
 *===========================================================================*/
OpcUa_Void OPCUA_DLLCALL OpcUa_P_Mutex_Unlock
    (
    OpcUa_Mutex hMutex
    )
    {
    SEM_ID          semid;
    if (hMutex != OpcUa_Null)
        {
        semid = (SEM_ID) hMutex;
        (void) semGive (semid);
        }
    }
