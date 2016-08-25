#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include_directories(.)

set(amqp_ansic_subscriber_HEADERS
    ${OPCUA_UTILS_DIR}/opcua_utils.h
)

set(amqp_ansic_subscriber_SOURCES
    ${OPCUA_UTILS_DIR}/opcua_utils.c
    ${OPCUA_UTILS_DIR}/urldecode.c
)

add_executable(
	amqp_ansic_subscriber
	main.c
    ${amqp_ansic_subscriber_SOURCES}
    ${amqp_ansic_subscriber_HEADERS})

target_link_libraries(
	amqp_ansic_subscriber
	${JSONC_LIBRARIES}
	${UAMQP_LIBRARIES}
	${OPENSSL_LIBRARIES})
	
if (WIN32)

	#windows needs this define
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	
	target_link_libraries(
		amqp_ansic_subscriber
		ws2_32
		secur32)

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_OPENSSL /wd4152")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_OPENSSL /wd4152")
		
	file(COPY ./ansic_subscriber_activemq.bat DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY ./ansic_subscriber_azureservicebus.bat DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY $ENV{OPENSSL_ROOT_DIR}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
	file(COPY $ENV{OPENSSL_ROOT_DIR}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)

else()
	
	target_link_libraries(
		amqp_ansic_subscriber
		ssl
		crypto)
		
endif()

