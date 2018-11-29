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
07nov18,lan  use VxWorks native api to implement OPC-UA semaphore.
*/

#include <vxWorks.h>
#include <semLib.h>
#include <sysLib.h>
#include <errnoLib.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* UA platform definitions */
#include <opcua_p_internal.h>

/* additional UA dependencies */
#include <opcua_p_datetime.h>
#include <opcua_p_memory.h>
#include <opcua_utilities.h>

/* own headers */
#include <opcua_semaphore.h>
#include <opcua_p_semaphore.h>

/** Creates a new semaphore.
 * @param a_Semaphore Pointer to semaphore handle. 
 *        This returns the newly created semaphore.
 * @param a_uInitalValue The initial value of the semaphore.
 * @param a_uMaxRange The maximum value of the semaphore. This has no effect 
 *        on linux, because the system has no maximim limit. But the parameter is checked 
 *        to make sense 0 &lt;= InitValue &lt; MaxRange.
 * @return OpcUa_Good if the semaphore could be created, OpcUa_BadInvalidArgument 
 *         MaxRange is not plausible, or OpcUa_BadInternalError in case of a system call error.
 */
OpcUa_StatusCode OpcUa_P_Semaphore_Create
    (
    OpcUa_Semaphore*  a_Semaphore,
    OpcUa_UInt32      a_uInitalValue,
    OpcUa_UInt32      a_uMaxRange
    )
    {
    SEM_ID  semid;

    *a_Semaphore = OpcUa_Null;
    if (a_uMaxRange == 0 || a_uMaxRange < a_uInitalValue) 
        {
        return OpcUa_BadInvalidArgument;
        }

    /* don't set SEM_INTERRUPTIBLE option */

    semid = semCCreate (SEM_Q_PRIORITY|SEM_Q_FIFO, 
                        (int) a_uInitalValue);
    if (semid == SEM_ID_NULL)
        {
        return OpcUa_Bad;
        }

    *a_Semaphore = (OpcUa_Semaphore) semid;
    return OpcUa_Good;
    }

/** Deletes the semaphore. */
OpcUa_Void OpcUa_P_Semaphore_Delete
    (
    OpcUa_Semaphore* pRawSemaphore
    )
    {
    SEM_ID  semid;
    if (pRawSemaphore == OpcUa_Null || *pRawSemaphore == OpcUa_Null) 
        return;

    semid = (SEM_ID) *pRawSemaphore;
    (void) semDelete (semid);
    *pRawSemaphore = OpcUa_Null;
    return;
    }

/** Aquires a resource.
 * This function blocks until a resource could be aquired.
 * Use OpcUa_P_Semaphore_TimedWait if you don't wont to block forever.
 * This function handles interruptions due to signals and automatically
 * restarts the wait operation.
 * @param RawSemaphore Handle to semaphore.
 * @return OpcUa_Good if the resource was successfully aquired,
 * OpcUa_BadInternalError in case of a system call error.
 */
OpcUa_StatusCode OpcUa_P_Semaphore_Wait
    (
    OpcUa_Semaphore RawSemaphore
    )
    {
    SEM_ID  semid = (SEM_ID) RawSemaphore;
    STATUS  vxst;
    
    vxst = semTake (semid, WAIT_FOREVER); 
    if (vxst != OK)
        {
        return OpcUa_BadInternalError;            
        }
    return OpcUa_Good;
    }

/** Aquires a resource.
 * This function behaves like OpcUa_P_Semaphore_Wait, but does not block forever.
 * In case of a timeout the function returns OpcUa_GoodNonCriticalTimeout.
 * @param RawSemaphore Handle to semaphore.
 * @param msecTimeout Maximum time to wait to aquire the resource.
 * @return OpcUa_Good if the resource was successfully aquired, 
 *         OpcUa_GoodNonCriticalTimeout in case of a timeout,
 * OpcUa_BadInternalError in case of a system call error.
 */
OpcUa_StatusCode OpcUa_P_Semaphore_TimedWait
    (
    OpcUa_Semaphore RawSemaphore, 
    OpcUa_UInt32    msecTimeout
    )
    {
    SEM_ID       semid = (SEM_ID) RawSemaphore;
    STATUS       vxst;
    UINT64       ticks;
    int          err;

    if (msecTimeout == OpcUa_Infinite)
        {
        vxst = semTake (semid, WAIT_FOREVER);
        if (vxst != OK)
            return OpcUa_BadInternalError;
        }
    else
        {
        /* msecTimeout  millisecond */

        ticks = sysClkRateGet() * msecTimeout / 1000;  
        if (ticks == 0)
            ticks = 1;
        vxst = semTake (semid, (_Vx_ticks_t) ticks);
        err = errnoGet ();
        if (vxst != OK)
            {
            if (err == S_objLib_OBJ_TIMEOUT) /* timeout*/
                {
                return OpcUa_GoodNonCriticalTimeout;
                }
            return OpcUa_BadInternalError;
            }
        }

    return OpcUa_Good;
    }

/** Gives back a number of aquired resources.
 * This means it unblocks other blocking OpcUa_P_Semaphore_Wait or OpcUa_P_Semaphore_TimedWait calls.
 * @param RawSemaphore Handle to semaphore.
 * @param uReleaseCount Gives back uReleaseCount resources.
 * @return OpcUa_Good on success or OpcUa_BadInternalError in case of a system call error.
 */
OpcUa_StatusCode OpcUa_P_Semaphore_Post
    (
    OpcUa_Semaphore RawSemaphore,
    OpcUa_UInt32    uReleaseCount
    )
    {
    SEM_ID  semid = (SEM_ID) RawSemaphore;
    STATUS  vxst;

    if (uReleaseCount == 0) 
        return OpcUa_BadInvalidArgument;

    while (uReleaseCount > 0)
        {
        vxst = semGive (semid);  
        if (vxst != OK)  
            return OpcUa_BadInternalError;
        --uReleaseCount;
        }

    return OpcUa_Good;
    }
