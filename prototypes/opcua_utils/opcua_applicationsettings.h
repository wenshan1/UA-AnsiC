#ifndef OpcUa_ApplicationSettings_H
#define OpcUa_ApplicationSettings_H

typedef struct _OpcUa_ApplicationSettings
{
    char* UrlScheme;
    char* BrokerAddress;
    unsigned short Port;
    char* Username;
    char* Password;
    char* AmqpNodeName;
    int Iterations;
}
OpcUa_ApplicationSettings;

void OpcUa_ApplicationSettings_Initialize(OpcUa_ApplicationSettings* a_pSettings);
void OpcUa_ApplicationSettings_Clear(OpcUa_ApplicationSettings* a_pSettings);
int OpcUa_GetApplicationSettings(int argc, char ** argv, OpcUa_ApplicationSettings* a_pSettings);

#define URI_SCHEME_AMQPS "amqps"
#define DEFAULT_PORT_AMQPS 5671
#define URI_SCHEME_WSS   "wss"
#define DEFAULT_PORT_WSS 443

#endif // OPCUA_UTILS_H


