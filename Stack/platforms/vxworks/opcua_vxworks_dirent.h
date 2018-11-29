/* opcua_vxworks_dirent.h - POSIX directory handling definitions for OPCUA */

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
07sep18,lan  written.
*/

#ifndef __INopcua_vxworks_dirent
#define __INopcua_vxworks_dirent

#include <vxWorks.h>			/* for SEM_ID, BOOL, STATUS */
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern int scandir 
    (
    const char *      dirp, 
	struct dirent *** namelist,
    int (*filter)(const struct dirent *),
    int (*compar)(const struct dirent **, const struct dirent **)
    );
             
extern int alphasort
    (
    const struct dirent **a, 
	const struct dirent **b
	);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INopcua_vxworks_dirent */
