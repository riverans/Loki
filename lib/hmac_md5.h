/*
 * hmac_md5.h
 */

#ifndef hmac_md5_INCLUDED
#define hmac_md5_INCLUDED

#ifndef ARCH_IS_BIG_ENDIAN
#define ARCH_IS_BIG_ENDIAN 0
#endif
#include "md5.h"

#ifdef __cplusplus
extern "C"
{
#endif

void hmac_md5(unsigned char* text, int text_len, unsigned char* key, int key_len, md5_byte_t* digest);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif /* hmac_md5_INCLUDED */
