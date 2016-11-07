project(ua-ansic-amqp)
cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

find_package(OpenSSL)

if (NOT OPENSSL_FOUND)
	MESSAGE(WARNING "OPENSSL_ROOT_DIR environment variable was not set. Assuming a relative path will work." )
	set(ENV{OPENSSL_ROOT_DIR} ${CMAKE_CURRENT_LIST_DIR}/../../third-party/openssl INTERNAL)
	set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_ROOT_DIR}/include CACHE INTERNAL "This is the include folder for OpenSSL" FORCE)
	set(OPENSSL_LIBRARIES $ENV{OPENSSL_ROOT_DIR}/lib/ssleay32.lib $ENV{OPENSSL_ROOT_DIR}/lib/libeay32.lib CACHE INTERNAL "These are the OpenSSL libraries" FORCE)
endif()

set(OPCUA_UTILS_DIR ${CMAKE_CURRENT_LIST_DIR}/../opcua_utils CACHE INTERNAL "This is the include folder for the OPC UA sample utilities" FORCE)

set(UAMQP_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/azure-uamqp-c/include CACHE INTERNAL "This is the include folder for UAMQP" FORCE)
set(UAMQP_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/azure-uamqp-c/lib CACHE INTERNAL "This is the lib folder for UAMQP" FORCE)
set(UAMQP_LIBRARIES ${UAMQP_LIB_DIR}/uamqp.lib ${UAMQP_LIB_DIR}/aziotsharedutil.lib CACHE INTERNAL "These are the UAMQP libraries" FORCE)

set(JSONC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/json-c/include CACHE INTERNAL "This is the include folder for JSON-C" FORCE)
set(JSONC_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../third-party/json-c/lib CACHE INTERNAL "This is the lib folder for JSON-C" FORCE)
set(JSONC_LIBRARIES ${JSONC_LIB_DIR}/json-c.lib CACHE INTERNAL "These are the JSON-C libraries" FORCE)

include_directories(${OPCUA_UTILS_DIR})
include_directories(${UAMQP_INCLUDE_DIR})
include_directories(${JSONC_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(amqp_ansic_subscriber)
add_subdirectory(amqp_ansic_publisher)