#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include_directories(.)

set(websockets_testclient_HEADERS
    ${OPCUA_UTILS_DIR}/opcua_applicationsettings.h
    ${OPCUA_UTILS_DIR}/urldecode.h
)

set(websockets_testclient_SOURCES
	uatestclient.c
    ${OPCUA_UTILS_DIR}/opcua_applicationsettings.c
    ${OPCUA_UTILS_DIR}/urldecode.c
)

add_executable(
	websockets_testclient
    ${websockets_testclient_SOURCES}
    ${websockets_testclient_HEADERS})

add_dependencies(websockets_testclient uastack)

target_link_libraries(
	websockets_testclient
	${UASTACK_LIBRARIES}
	${OPENSSL_LIBRARIES})
	
if (WIN32)

	#windows needs this define
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	add_definitions(-DOPCUA_TRACE_ENABLE)

	target_link_libraries(
		websockets_testclient
		ws2_32
		secur32
		crypt32
		rpcrt4)
		
	file(COPY ${OPENSSL_ROOT_DIR}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY ${OPENSSL_ROOT_DIR}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../PKI DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

else()
	
	target_link_libraries(
		websockets_testclient
		ssl
		crypto)
		
endif()

install(TARGETS websockets_testclient
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib)

