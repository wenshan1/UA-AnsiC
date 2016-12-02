project(ua-ansic-websockets)
cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

find_package(OpenSSL)

if (NOT $ENV{OPENSSL_ROOT_DIR} STREQUAL "")
	STRING(REGEX REPLACE "\\\\" "/" OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR})
endif()

if (NOT OPENSSL_FOUND)
	MESSAGE(WARNING "OPENSSL_ROOT_DIR environment variable was not set. Assuming a relative path will work." )
	set(${OPENSSL_ROOT_DIR} ${CMAKE_CURRENT_LIST_DIR}/../../third-party/openssl INTERNAL)
	set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include CACHE INTERNAL "This is the include folder for OpenSSL" FORCE)
	set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib/ssleay32.lib ${OPENSSL_ROOT_DIR}/lib/libeay32.lib CACHE INTERNAL "These are the OpenSSL libraries" FORCE)
endif()

set(OPCUA_UTILS_DIR ${CMAKE_CURRENT_LIST_DIR}/../opcua_utils CACHE INTERNAL "This is the include folder for the OPC UA sample utilities" FORCE)

set(UASTACK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../Stack CACHE INTERNAL "This is the base folder for the UASTACK" FORCE)

set(UASTACK_INCLUDE_DIR 
	${UASTACK_DIR}/platforms/win32 
	${UASTACK_DIR}/core
	${UASTACK_DIR}/stackcore
	${UASTACK_DIR}/securechannel
	${UASTACK_DIR}/transport/tcp
	${UASTACK_DIR}/transport/https
	${UASTACK_DIR}/proxystub/clientproxy
	${UASTACK_DIR}/proxystub/serverstub
	CACHE 
	INTERNAL 
	"This is the include folder for the UASTACK" 
	FORCE)
	
set(UASTACK_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/Stack/${CMAKE_CFG_INTDIR} CACHE INTERNAL "This is the lib folder for the UASTACK" FORCE)
set(UASTACK_LIBRARIES ${UASTACK_LIB_DIR}/uastack.lib CACHE INTERNAL "These are the the UASTACK libraries" FORCE)

set(UAMQP_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/azure-uamqp-c/include CACHE INTERNAL "This is the include folder for UAMQP" FORCE)
set(UAMQP_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/azure-uamqp-c/lib CACHE INTERNAL "This is the lib folder for UAMQP" FORCE)
set(UAMQP_LIBRARIES ${UAMQP_LIB_DIR}/uamqp.lib ${UAMQP_LIB_DIR}/aziotsharedutil.lib CACHE INTERNAL "These are the UAMQP libraries" FORCE)

set(CURL_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/curl/include CACHE INTERNAL "This is the include folder for CURL" FORCE)
set(CURL_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/curl/lib CACHE INTERNAL "This is the lib folder for CURL" FORCE)
set(CURL_LIBRARIES ${CURL_LIB_DIR}/libcurl_imp.lib CACHE INTERNAL "These are the CURL libraries" FORCE)

set(JSONC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/json-c/include CACHE INTERNAL "This is the include folder for JSON-C" FORCE)
set(JSONC_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/json-c/lib CACHE INTERNAL "This is the lib folder for JSON-C" FORCE)
set(JSONC_LIBRARIES ${JSONC_LIB_DIR}/json-c.lib CACHE INTERNAL "These are the JSON-C libraries" FORCE)

include_directories(${OPCUA_UTILS_DIR})
include_directories(${UASTACK_INCLUDE_DIR})
include_directories(${CURL_INCLUDE_DIR})
include_directories(${JSONC_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(${UASTACK_DIR} ${CMAKE_CURRENT_BINARY_DIR}/Stack)
add_subdirectory(websockets_testserver)
add_subdirectory(websockets_testclient)
		
install(FILES 
		${OPENSSL_ROOT_DIR}/bin/libeay32.dll 
		${OPENSSL_ROOT_DIR}/bin/ssleay32.dll 
		DESTINATION bin)
		
install(DIRECTORY  
		${CMAKE_CURRENT_SOURCE_DIR}/PKI 
		DESTINATION bin)
