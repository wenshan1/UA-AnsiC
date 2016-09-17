#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include_directories(.)

set(oauth2_client_HEADERS
	oauth2api.h
	print.h
	main.h
    ${OPCUA_UTILS_DIR}/opcua_applicationsettings.h
    ${OPCUA_UTILS_DIR}/opcua_base64.h
    ${OPCUA_UTILS_DIR}/urldecode.h
)

set(oauth2_client_SOURCES
	main.c
	main_https.c
	main_uatcp.c
	oauth2api.c
	print.c
    ${OPCUA_UTILS_DIR}/opcua_applicationsettings.c
    ${OPCUA_UTILS_DIR}/opcua_base64.c
    ${OPCUA_UTILS_DIR}/urldecode.c
)

add_executable(
	oauth2_client
    ${oauth2_client_SOURCES}
    ${oauth2_client_HEADERS})

target_link_libraries(
	oauth2_client
	${UASTACK_LIBRARIES}
	${JSONC_LIBRARIES}
	${CURL_LIBRARIES}
	${OPENSSL_LIBRARIES})
	
if (WIN32)

	#windows needs this define
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	add_definitions(-DOPCUA_TRACE_ENABLE)

	target_link_libraries(
		oauth2_client
		ws2_32
		secur32
		crypt32
		rpcrt4)
		
	file(COPY $ENV{OPENSSL_ROOT_DIR}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY $ENV{OPENSSL_ROOT_DIR}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY ${CURL_LIB_DIR}/../bin/libcurl.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../PKI DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

else()
	
	target_link_libraries(
		oauth2_client
		ssl
		crypto)
		
endif()

