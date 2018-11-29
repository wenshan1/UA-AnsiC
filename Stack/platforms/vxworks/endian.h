/* endian.h - minimal endian library  */

#ifndef __INCendianh
#define __INCendianh

/* includes */
#include <types/vxCpu.h>
#include <types/vxArch.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* defines */

#ifndef BYTE_ORDER
# if _BYTE_ORDER == _LITTLE_ENDIAN
#  undef LITTLE_ENDIAN  
#  define  LITTLE_ENDIAN  _LITTLE_ENDIAN 
#  define BYTE_ORDER LITTLE_ENDIAN
# elif _BYTE_ORDER == _BIG_ENDIAN
#  undef BIG_ENDIAN
#  define BIG_ENDIAN _BIG_ENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# else
#  error "don't know byte order"
# endif
#endif

/* typedefs */

/* function declarations */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __INCendianh */
