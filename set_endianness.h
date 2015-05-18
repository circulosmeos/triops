#ifndef SET_ENDIANNESS_H
#define SET_ENDIANNESS_H

#ifdef ANDROID_LIBRARY
/*
   __BIG_ENDIAN__ and __LITTLE_ENDIAN__ are defined in some gcc versions
  only, probably depending on the architecture. Try to use endian.h if
  the gcc way fails - endian.h also does not seem to be available on all
  platforms.
*/
#ifdef __BIG_ENDIAN__
#undef LOCAL_LITTLE_ENDIAN
#else /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
#define LOCAL_LITTLE_ENDIAN
#else
#ifdef BSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#undef LOCAL_LITTLE_ENDIAN
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define LOCAL_LITTLE_ENDIAN
#else
#error "unable to determine endianess!"
#endif /* __BYTE_ORDER */
#endif /* __LITTLE_ENDIAN__ */
#endif /* __BIG_ENDIAN__ */

#endif /* ANDROID_LIBRARY */

#endif
