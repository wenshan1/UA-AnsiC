#include "main.h"

extern int Main_GetSecurityKeyWithUaTcp();

extern int Main_GetSecurityKeyWithHttps();

/*===========================================================================================*/
/** @brief Main entry function.                                                              */
/*===========================================================================================*/
int main(int argc, char* argv[])
{
#if UACLIENT_USE_CRTDBG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
	//_CrtSetBreakAlloc(7616);
#endif

	OpcUa_ReferenceParameter(argc);
	OpcUa_ReferenceParameter(argv);

	OAuth2TestClient_Initialize();

	Main_GetSecurityKeyWithUaTcp();
	Main_GetSecurityKeyWithHttps();

#if UACLIENT_WAIT_FOR_USER_INPUT
	printf("Shutdown complete!\nPress enter to exit!\n");
	getchar();
#endif

	OAuth2TestClient_Cleanup();

	return 0;
}

/*********************************************************************************************/
/***********************                End Of File                   ************************/
/*********************************************************************************************/