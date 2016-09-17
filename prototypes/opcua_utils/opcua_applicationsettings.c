// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include "opcua_applicationsettings.h"
#include "urldecode.h"

char* OpcUa_StrnDup(const char* pSrc, int length)
{
	char* pDst = NULL;

	if (pSrc == NULL)
	{
		return NULL;
	}

	pDst = malloc(length + 1);
	memcpy(pDst, pSrc, length);
	pDst[length] = 0;

	return pDst;
}

#define OpcUa_Alloc(x) malloc(x)
#define OpcUa_Free(x) if (x != NULL) { free(x); x = NULL; }
#define OpcUa_StrDup(x) OpcUa_StrnDup(x, strlen(x))

void OpcUa_ApplicationSettings_Initialize(OpcUa_ApplicationSettings* a_pSettings)
{
    memset(a_pSettings, 0, sizeof(OpcUa_ApplicationSettings));
}

void OpcUa_ApplicationSettings_Clear(OpcUa_ApplicationSettings* a_pSettings)
{
    if (a_pSettings != NULL)
    {
        OpcUa_Free(a_pSettings->UrlScheme);
        OpcUa_Free(a_pSettings->BrokerAddress);
        OpcUa_Free(a_pSettings->Username);
        OpcUa_Free(a_pSettings->Password);
        OpcUa_Free(a_pSettings->AmqpNodeName);

        memset(a_pSettings, 0, sizeof(OpcUa_ApplicationSettings));
    }
}

static void OpcUa_CheckArgument(int argc, int optPlace, char * option)
{
    if (optPlace + 1 == argc) //If the option is the last argument
    {
        printf("%s", option);
        printf(" requires an argument. Call -h if you require help running this program.");
        exit(0);
    }
}

int OpcUa_GetApplicationSettings(int argc, char ** argv, OpcUa_ApplicationSettings* a_pSettings)
{
    int count = 1;
    OpcUa_ApplicationSettings_Initialize(a_pSettings);

    a_pSettings->Iterations = 10;

    if (argc == 1)
    {
        fprintf(stderr, "c-amqp-subscriber requires arguments. Call -h if you require help running this program.");
        exit(0);
    }
    else
    {
        while (count < argc)
        {
            if (strcmp(argv[count], "-h") == 0 || strcmp(argv[count], "-help") == 0)
            {
                printf("c-amqp-subscriber takes the following arguments to subscribe to a message broker \n");
                printf("-b: Broker URL \n");
                printf("-u: Username \n");
                printf("-p: Password \n");
                printf("-t: Terminus name \n");
                printf("-c: Number of messages to read\n");
                printf("All arguments must be URL encoded");
                exit(0);
            }
            else if (strcmp(argv[count], "-b") == 0)
            {
                int ii = 0;
                int start = 0;
                char* arg = NULL;
                OpcUa_CheckArgument(argc, count, "-b");
                arg = argv[count + 1];

                for (ii = 0; arg[ii] != 0; ii++)
                {
                    if (arg[ii] == ':')
                    {
                        a_pSettings->UrlScheme = OpcUa_StrnDup(arg, ii);
                        start = ii + 3;
                        break;
                    }
                }

                for (ii = start; arg[ii] != 0; ii++)
                {
                    if (arg[ii] == ':')
                    {
                        a_pSettings->BrokerAddress = OpcUa_StrnDup(arg + start, ii - start);
                        start = ii + 1;
                        break;
                    }
                }

                if (arg[ii] == 0)
                {
                    a_pSettings->BrokerAddress = OpcUa_StrnDup(arg + start, ii - start);
                    a_pSettings->Port = 5671;

                    if (a_pSettings->UrlScheme != NULL && strcmp(a_pSettings->UrlScheme, URI_SCHEME_WSS) == 0)
                    {
                        a_pSettings->Port = 443;
                    }
                }
                else
                {
                    a_pSettings->Port = (unsigned short)atoi(arg + start);
                }

                count++;
            }
            else if (strcmp(argv[count], "-p") == 0)
            {
                OpcUa_CheckArgument(argc, count, "-p");
                a_pSettings->Password = urlDecode(argv[count + 1]);
                count++;
            }
            else if (strcmp(argv[count], "-u") == 0)
            {
                OpcUa_CheckArgument(argc, count, "-u");
                a_pSettings->Username = urlDecode(argv[count + 1]);
                count++;
            }
            else if (strcmp(argv[count], "-t") == 0)
            {
                OpcUa_CheckArgument(argc, count, "-t");
                a_pSettings->AmqpNodeName = OpcUa_StrnDup(argv[count + 1], strlen(argv[count + 1]));
                count++;
            }
            else if (strcmp(argv[count], "-c") == 0)
            {
                OpcUa_CheckArgument(argc, count, "-c");
                a_pSettings->Iterations = atoi(argv[count + 1]);
                count++;
            }
            else
            {
                printf("%s", argv[count]);
                printf(" is not a valid option. Call -h if you require help running this program.");
                exit(0);
            }

            count++;
        }
    }

    return 0;
}
