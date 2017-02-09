// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#define _CRTDBG_MAP_ALLOC 1

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include <stdio.h>
#include <stdbool.h>
#include "opcua_amqpmessage.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_uamqp_c/message_sender.h"
#include "azure_uamqp_c/message.h"
#include "azure_uamqp_c/messaging.h"
#include "azure_uamqp_c/amqpalloc.h"
#include "azure_uamqp_c/saslclientio.h"
#include "azure_uamqp_c/sasl_plain.h"
#include "azure_uamqp_c/cbs.h"

#if _WIN32
#include "windows.h"
#endif

#ifdef USE_OPENSSL
#include "azure_c_shared_utility/tlsio_openssl.h"
#include <openssl\ssl.h>
#include <openssl\x509.h>
#include <openssl\err.h>
#include <openssl\engine.h>
#include <openssl\conf.h>
#endif

#define EH_MAX_MESSAGE_COUNT 10
static unsigned int sent_messages = 0;

static void on_message_send_complete(void* context, MESSAGE_SEND_RESULT send_result)
{
	(void)send_result;
	(void)context;

	sent_messages++;
}

#ifdef USE_OPENSSL
static int verify_remote_certificate(X509_STORE_CTX *x509_store_ctx, void *arg)
{
	char name[4096];
	X509_NAME_oneline(X509_get_subject_name(x509_store_ctx->cert), name, XN_FLAG_ONELINE);

	char issuer[4096];
	X509_NAME_oneline(X509_get_issuer_name(x509_store_ctx->cert), issuer, XN_FLAG_ONELINE);

	TLSIO_CONFIG* pConfig = (TLSIO_CONFIG*)arg;

	int length = strlen(name);

	for (int ii = 0; ii < length; ii++)
	{
		if (strncmp("CN=", name + ii, 3) == 0)
		{
			int expected = strlen(pConfig->hostname);
			int actual = strlen(name + ii + 3);

			if (expected >= actual && strncmp(name + ii + 3, pConfig->hostname + expected - actual, strlen(pConfig->hostname) + expected - actual) == 0)
			{
				printf("Accepting Certificate with correct Domain Name: %s IssuedBy: %s\r\n", name, issuer);
				return 1;
			}
		}
	}

	printf("Rejecting Certificate with incorrect Domain Name: %s IssuedBy: %s\r\n", name, issuer);
	return 0;
}
#endif

void on_connection_state_changed(void* context, CONNECTION_STATE new_connection_state, CONNECTION_STATE previous_connection_state)
{
	printf("Connection State Changed: %u to %u\r\n", previous_connection_state, new_connection_state);
}

void on_io_error(void* context)
{
	int x = 0;
}

int main(int argc, char** argv)
{
	int result;

#ifdef _CRTDBG_MAP_ALLOC
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
	//_CrtSetBreakAlloc(123);
#endif

	OpcUa_ApplicationSettings settings;
	OpcUa_GetApplicationSettings(argc, argv, &settings);

	amqpalloc_set_memory_tracing_enabled(true);

	if (platform_init() != 0)
	{
		result = -1;
	}
	else
	{
		XIO_HANDLE sasl_io;
		CONNECTION_HANDLE connection;
		SESSION_HANDLE session;
		LINK_HANDLE link;
		MESSAGE_SENDER_HANDLE message_sender;
		MESSAGE_HANDLE message;
		char buffer[512];

		size_t last_memory_used = 0;

		/* create SASL PLAIN handler */
		SASL_PLAIN_CONFIG sasl_plain_config;
		sasl_plain_config.authcid = settings.Username;
		sasl_plain_config.passwd = settings.Password;
		sasl_plain_config.authzid = NULL;

		SASL_MECHANISM_HANDLE sasl_mechanism_handle = saslmechanism_create(saslplain_get_interface(), &sasl_plain_config);
		XIO_HANDLE tls_io;

		/* create the TLS IO */
		TLSIO_CONFIG tls_io_config;
		tls_io_config.hostname = settings.BrokerAddress;
		tls_io_config.port = settings.Port;

		const IO_INTERFACE_DESCRIPTION* tlsio_interface = platform_get_default_tlsio();
		tls_io = xio_create(tlsio_interface, &tls_io_config);

#ifdef USE_OPENSSL
		/* set the TLS options */
		xio_setoption(tls_io, "tls_version", (const void*)10);
		xio_setoption(tls_io, "tls_validation_callback", verify_remote_certificate);
		xio_setoption(tls_io, "tls_validation_callback_data", &tls_io_config);
#endif

		/* create the SASL client IO using the TLS IO */
		SASLCLIENTIO_CONFIG sasl_io_config;
        sasl_io_config.underlying_io = tls_io;
        sasl_io_config.sasl_mechanism = sasl_mechanism_handle;
		sasl_io = xio_create(saslclientio_get_interface_description(), &sasl_io_config);

		/* create the connection, session and link */
		connection = connection_create2(sasl_io, settings.BrokerAddress, "some", NULL, NULL, on_connection_state_changed, NULL, on_io_error, NULL);
		session = session_create(connection, NULL, NULL);
		session_set_incoming_window(session, 2147483647);
		session_set_outgoing_window(session, 65536);

		AMQP_VALUE source = messaging_create_source("ingress");
		AMQP_VALUE target = messaging_create_target(settings.AmqpNodeName);
		link = link_create(session, "sender-link", role_sender, source, target);
		link_set_snd_settle_mode(link, sender_settle_mode_unsettled);
		(void)link_set_max_message_size(link, 65536);

		amqpvalue_destroy(source);
		amqpvalue_destroy(target);

		message = message_create();

		/* initialize the header with static information */
		OpcUa_AmqpMessageHeader header;
		OpcUa_AmqpMessageHeader_Initialize(&header);

		header.MessageId = NULL;
		header.SubjectId = _strdup("ua-data");
		header.ContentType = _strdup("application/opcua+uajson");
		header.PublisherId = _strdup("uAMQP");
		header.DataSetWriterId = _strdup("MyDataSetWriter");
		header.SequenceNumber = 0;
		header.DataSetClassId = _strdup("MyDataSetClass");
		header.MetaDataNodeName = _strdup("MetaDataTopicName");

		OpcUa_Message_SetHeader(message, &header);
		OpcUa_AmqpMessageHeader_Clear(&header);

		/* create a message sender */
		message_sender = messagesender_create(link, NULL, NULL);
		if (messagesender_open(message_sender) == 0)
		{
			int ii = 0;

#if _WIN32
			unsigned long startTime = (unsigned long)GetTickCount64();
#endif

			for (ii = 0; ii < settings.Iterations; ii++)
			{
				time_t rawtime;
				struct tm * timeinfo;

				/* update the header with a new message id and sequence number */
				sprintf(buffer, "1234567890:%u", ii + 1);

				if (OpcUa_Message_SetMessageId(message, buffer, ii + 1) != 0)
				{
					printf("ERROR: Could not update message header.\r\n");
				}

				/* update the body with a new event. */
				OpcUa_AmqpMessageBody body;
				OpcUa_AmqpMessageBody_Initialize(&body);

				body.EventId = _strdup(buffer);
				body.EventType = _strdup("11446");
				body.SourceNode = _strdup("2253");
				body.SourceName = _strdup("Server");

				time(&rawtime);
				timeinfo = localtime(&rawtime);

				strftime(buffer, 512, "%FT%TZ", timeinfo);
				body.Time = _strdup(buffer);
				body.ReceiveTime = _strdup(buffer);

				sprintf(buffer, "The system cycle '%u' has started.", ii + 1);
				body.Message = _strdup(buffer);
				body.Severity = ((uint16_t)ii * 10) % 1000;

				if (OpcUa_Message_SetBody(message, &body) != 0)
				{
					printf("ERROR: Could not write body of message.\r\n");
				}
				else
				{
					/* send the message to the broker. */
					messagesender_send(message_sender, message, on_message_send_complete, message);
				}

				OpcUa_AmqpMessageBody_Clear(&body);
			}

			message_destroy(message);

			while (true)
			{
				size_t current_memory_used;
				size_t maximum_memory_used;
				connection_dowork(connection);

				current_memory_used = amqpalloc_get_current_memory_used();
				maximum_memory_used = amqpalloc_get_maximum_memory_used();

				if (current_memory_used != last_memory_used)
				{
					(void)printf("Current memory usage:%lu (max:%lu)\r\n", (unsigned long)current_memory_used, (unsigned long)maximum_memory_used);
					last_memory_used = current_memory_used;
				}

				if (sent_messages == EH_MAX_MESSAGE_COUNT)
				{
					break;
				}
			}

#if _WIN32
			unsigned long endTime = (unsigned long)GetTickCount64();

			(void)printf("Send %zu messages in %lu ms: %.02f msgs/sec\r\n", EH_MAX_MESSAGE_COUNT, (endTime - startTime), (float)EH_MAX_MESSAGE_COUNT / ((float)(endTime - startTime) / 1000));
#endif
		}

		messagesender_destroy(message_sender);
		link_destroy(link);
		session_destroy(session);
		connection_destroy(connection);
		xio_destroy(sasl_io);
		xio_destroy(tls_io);
		saslmechanism_destroy(sasl_mechanism_handle);
		platform_deinit();
		OpcUa_ApplicationSettings_Clear(&settings);

		(void)printf("Max memory usage:%lu\r\n", (unsigned long)amqpalloc_get_maximum_memory_used());
		(void)printf("Current memory usage:%lu\r\n", (unsigned long)amqpalloc_get_current_memory_used());

		result = 0;
	}       

	printf("Press a key and hit <enter> to exit\r\n");
	getc(stdin);

#ifdef _CRTDBG_MAP_ALLOC
	_CrtDumpMemoryLeaks();
#endif

	return result;
}
