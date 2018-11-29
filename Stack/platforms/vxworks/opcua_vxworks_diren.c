/* opcua_vxworks_dirent.c - POSIX directory handling definitions for OPCUA */

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

#include <vxWorks.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <errnoLib.h>

#include <opcua_vxworks_dirent.h>

#define MAX_DIR_ENTRY    64

/*******************************************************************************
*
* scandir - scan a directory for matching entries
* 
* The scandir() function scans the directory 'dirp', calling the function 
* referenced by 'filter' on each directory entry. Entries for which the function 
* referenced by 'filter' returns non-zero shall be stored in strings allocated 
* as if by a call to malloc(), and sorted as if by a call to qsort() with the 
* comparison function 'compar', except that 'compar' need not provide total 
* ordering.  
*
*/

int scandir 
    (
    const char *      dirp, 
	struct dirent *** namelist,
    int (*filter)(const struct dirent *),
    int (*compar)(const struct dirent **, const struct dirent **)
    )
    {
    DIR *            odir;
    struct dirent ** lst;
    struct dirent *  ent;
    struct dirent *  pa;
    int              nCount = 0;
    BOOL             outofmemory = FALSE;

    if ((dirp == NULL) || (namelist == NULL))
        {
        return -1;
        }

    odir = opendir (dirp);
    if (odir == NULL)
        {
        (void) errnoSet (ENOTDIR);    	
        return -1;
        }

    lst = (struct dirent **) malloc (MAX_DIR_ENTRY * sizeof (struct dirent *));
    if (lst == NULL)
        {
        (void) closedir (odir);
        (void) errnoSet (ENOMEM);        
        return -1;
        }

    while ((ent = readdir (odir)) != NULL)
        {
        if (filter && !filter (ent))
            continue;
        pa = (struct dirent *) malloc (sizeof (struct dirent));
        if (pa == NULL)
            {
            outofmemory = TRUE;
            break;
            }

        (void) memcpy ((void *) pa, (void *) ent, sizeof (struct dirent));
        lst[nCount] = pa;
        nCount ++;
        }

    /* out of memory to free memory */

    if (outofmemory)
        {
        while (nCount)
            {
            free (lst[nCount]);
            }
        free(lst);
        return -1;
        }

    if (nCount > 0 && compar)
        {
        qsort(lst, nCount, sizeof (struct dirent **), compar);
        }
    * namelist = lst;
	return nCount;	
    }
     
/*******************************************************************************
 * 
 * alphasort - sort the directory entries, 'a' and 'b', into alphabetical order
 * 
 * The alphasort() function be used as the comparison function for the 'scandir'
 * function to sort the directory entries, 'a' and 'b', into alphabetical order. 
 *
 */

int alphasort
    (
    const struct dirent ** a, 
	const struct dirent ** b
	)
    {
    if (a == NULL || b == NULL)
        {
        return 0;
        }

    return strcmp ((*a)->d_name, (*b)->d_name);
    }
