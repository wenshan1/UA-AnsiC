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
06nov18,lan  use VxWorks native api to implement OPC-UA thread.
*/

#include <vxWorks.h>
#include <taskLib.h>
#include <sysLib.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include <opcua_p_internal.h>
#include <opcua_p_thread.h>
#include <opcua_p_memory.h>
#include <opcua_p_openssl.h>

/*============================================================================
 * Port Layer Thread Main
 *===========================================================================*/

#define TASKNAME_SIZE   16

typedef struct _OpcUa_P_ThreadArg
    {
    TASK_ID                      hThread;
    OpcUa_CharA                  taskName[TASKNAME_SIZE];
    OpcUa_Int                    taskPrio;
    size_t                       taskStackSize;
    OpcUa_PfnInternalThreadMain* pfnInternalThreadMain;
    OpcUa_Void*                  ThreadArgs;
    } OpcUa_P_ThreadArg;

/**
* This is the function, the new thread starts with. The only thing to do here,
* is calling the InternalThreadMain from OpcUa_Thread.c and your internal stuff.
*/

static int task_start
    (
    void* args
    )
    {
    OpcUa_P_ThreadArg*  pThreadArguments;
    
    if (args == OpcUa_Null)
        {
        return -1;
        }

    pThreadArguments = (OpcUa_P_ThreadArg*) args ;

    /* run stack thread! */
    pThreadArguments->pfnInternalThreadMain (pThreadArguments->ThreadArgs);

#if OPCUA_REQUIRE_OPENSSL
    OpcUa_P_OpenSSL_Thread_Cleanup();
#endif

    return 0;
    }

/*============================================================================
 * Create a platform thread
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Thread_Create
    (
    OpcUa_RawThread* pRawThread
    )
    {
    OpcUa_StatusCode    uStatus     = OpcUa_Good;
    OpcUa_P_ThreadArg*  pThreadArgs = OpcUa_Null;
    static OpcUa_Int32  taskNum  = 0;

    *pRawThread = OpcUa_Null;

    pThreadArgs = (OpcUa_P_ThreadArg *) OpcUa_P_Memory_Alloc (sizeof(OpcUa_P_ThreadArg));
    OpcUa_ReturnErrorIfAllocFailed(pThreadArgs);

    pThreadArgs->hThread                = TASK_ID_ERROR;
    pThreadArgs->pfnInternalThreadMain  = OpcUa_Null;
    pThreadArgs->ThreadArgs             = OpcUa_Null;
    pThreadArgs->taskPrio               = 200; 
    pThreadArgs->taskStackSize          = 1024 * 4; 
    
    (void) OpcUa_P_String_snprintf (pThreadArgs->taskName, TASKNAME_SIZE, 
                                    "tOpcUa%d", taskNum);
    ++taskNum;
    *pRawThread = (OpcUa_RawThread) pThreadArgs;
    return uStatus;
    }

/*============================================================================
 * Delete Raw Thread
 *===========================================================================*/
OpcUa_Void OpcUa_P_Thread_Delete
    (
    OpcUa_RawThread* pRawThread
    )
    {
    OpcUa_P_ThreadArg* pThreadArgs;

    if (pRawThread == OpcUa_Null || *pRawThread == OpcUa_Null)
        {
        return;    
        }
    else
        {
        pThreadArgs = (OpcUa_P_ThreadArg*)*pRawThread;
        if (pThreadArgs->hThread != TASK_ID_ERROR)
            {
            (void) taskWait (pThreadArgs->hThread, WAIT_FOREVER);
            }
        }
    OpcUa_P_Memory_Free (*pRawThread);
    *pRawThread = OpcUa_Null;
    return;
    }

/*============================================================================
 * Create Thread
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Thread_Start
    (  
    OpcUa_RawThread             pThread,
    OpcUa_PfnInternalThreadMain pfnStartFunction,
    OpcUa_Void*                 pArguments
    )
    {
    OpcUa_P_ThreadArg*  pThreadArguments;
    TASK_ID             tid;
    _Vx_usr_arg_t       targ     = 0;

    if(pThread == OpcUa_Null)
        {
        return OpcUa_BadInvalidArgument;
        }

    pThreadArguments = (OpcUa_P_ThreadArg*) pThread;

    pThreadArguments->pfnInternalThreadMain = pfnStartFunction;
    pThreadArguments->ThreadArgs            = pArguments;

    tid = taskSpawn (pThreadArguments->taskName, 
                     pThreadArguments->taskPrio, VX_FP_TASK, 
                     pThreadArguments->taskStackSize,
                     (FUNCPTR) task_start, (_Vx_usr_arg_t) pThreadArguments, 
                     targ, targ, targ, targ, targ, targ, targ, targ, targ);
    if (tid == TASK_ID_ERROR)
        {
        return OpcUa_BadResourceUnavailable;
        }
    pThreadArguments->hThread = tid;
    return OpcUa_Good;
    }

/*============================================================================
 * Send the thread to sleep.
 *===========================================================================*/
OpcUa_Void OpcUa_P_Thread_Sleep
    (
    OpcUa_UInt32 msecTimeout
    )
    {
    struct timespec ntp;

    ntp.tv_sec = msecTimeout / 1000;
    ntp.tv_nsec = (msecTimeout % 1000) * 1000 * 1000;

    clock_nanosleep (CLOCK_REALTIME, 0, &ntp, NULL);
    }

/*============================================================================
 * Get Current Thread Id
 *===========================================================================*/
unsigned long OpcUa_P_Thread_GetCurrentThreadId (OpcUa_Void)
    {
    return (unsigned long) taskIdSelf ();
    }

/*============================================================================
 * Set the platform thread attribute. 
 * It should be called before the thread start.
 *===========================================================================*/
OpcUa_StatusCode    OpcUa_P_Thread_SetAttribute
    (
    OpcUa_RawThread pThread, 
    OpcUa_CharA *   pName,
    OpcUa_Int       priority,
    size_t          stackSize
    )
    {
    OpcUa_P_ThreadArg*  pThreadArguments;

    if (pThread == OpcUa_Null || pName == OpcUa_Null || 
        priority < 0 || stackSize < 1024)
        {
        return OpcUa_BadInvalidArgument;
        }
    pThreadArguments = (OpcUa_P_ThreadArg*) pThread; 
    (void) OpcUa_P_String_snprintf (pThreadArguments->taskName, TASKNAME_SIZE, 
                                    "%s", pName);
    pThreadArguments->taskPrio = priority;
    pThreadArguments->taskStackSize = stackSize;

    return OpcUa_Good;
    }