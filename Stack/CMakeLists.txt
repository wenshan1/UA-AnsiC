#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include_directories(.)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/platforms/${UASTACK_PLATFORM})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/stackcore)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/securechannel)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/transport/tcp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/transport/https)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/transport/wss)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/proxystub/clientproxy)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/proxystub/serverstub)

file(GLOB CORE_C          "${CMAKE_CURRENT_SOURCE_DIR}/core/*.c")
file(GLOB PLATFORMS_C     "${CMAKE_CURRENT_SOURCE_DIR}/platforms/win32/*.c")
file(GLOB STACKCORE_C     "${CMAKE_CURRENT_SOURCE_DIR}/stackcore/*.c")
file(GLOB TCP_C           "${CMAKE_CURRENT_SOURCE_DIR}/transport/tcp/*.c")
file(GLOB HTTPS_C         "${CMAKE_CURRENT_SOURCE_DIR}/transport/https/*.c")
file(GLOB WSS_C           "${CMAKE_CURRENT_SOURCE_DIR}/transport/wss/*.c")
file(GLOB SECURECHANNEL_C "${CMAKE_CURRENT_SOURCE_DIR}/securechannel/*.c")
file(GLOB CLIENTPROXY_C   "${CMAKE_CURRENT_SOURCE_DIR}/proxystub/clientproxy/*.c")
file(GLOB SERVERSTUB_C    "${CMAKE_CURRENT_SOURCE_DIR}/proxystub/serverstub/*.c")

file(GLOB CORE_H          "${CMAKE_CURRENT_SOURCE_DIR}/core/*.h")
file(GLOB PLATFORMS_H     "${CMAKE_CURRENT_SOURCE_DIR}/platforms/win32/*.h")
file(GLOB STACKCORE_H     "${CMAKE_CURRENT_SOURCE_DIR}/stackcore/*.h")
file(GLOB TCP_H           "${CMAKE_CURRENT_SOURCE_DIR}/transport/tcp/*.h")
file(GLOB HTTPS_H         "${CMAKE_CURRENT_SOURCE_DIR}/transport/https/*.h")
file(GLOB WSS_H           "${CMAKE_CURRENT_SOURCE_DIR}/transport/wss/*.h")
file(GLOB SECURECHANNEL_H "${CMAKE_CURRENT_SOURCE_DIR}/securechannel/*.h")
file(GLOB CLIENTPROXY_H   "${CMAKE_CURRENT_SOURCE_DIR}/proxystub/clientproxy/*.h")
file(GLOB SERVERSTUB_H    "${CMAKE_CURRENT_SOURCE_DIR}/proxystub/serverstub/*.h")

add_library(uastack
	${CORE_C}
	${PLATFORMS_C}
	${STACKCORE_C}
	${TCP_C}
	${HTTPS_C}
	${WSS_C}
	${SECURECHANNEL_C}
	${CLIENTPROXY_C}
	${SERVERSTUB_C}
	${PLATFORMS_C}
	${CORE_H}
	${PLATFORMS_H}
	${STACKCORE_H}
	${TCP_H}
	${HTTPS_H}
	${WSS_H}
	${SECURECHANNEL_H}
	${CLIENTPROXY_H}
	${SERVERSTUB_H}
)

add_definitions(-DOPCUA_TRACE_ENABLE)
