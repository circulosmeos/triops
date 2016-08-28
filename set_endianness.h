#ifndef SET_ENDIANNESS_H
#define SET_ENDIANNESS_H

//#ifdef ANDROID_LIBRARY
/*
   __BIG_ENDIAN__ and __LITTLE_ENDIAN__ are defined in some gcc versions
  only, probably depending on the architecture. Try to use endian.h if
  the gcc way fails - endian.h also does not seem to be available on all
  platforms.
*/

// http://esr.ibiblio.org/?p=5095
// http://stackoverflow.com/questions/2100331/c-macro-definition-to-determine-big-endian-or-little-endian-machine

/* definition to expand macro then apply to pragma message */
// http://stackoverflow.com/questions/1562074/how-do-i-show-the-value-of-a-define-at-compile-time
/*#define VALUE_TO_STRING(x) #x
#define VALUE(x) VALUE_TO_STRING(x)
#define VAR_NAME_VALUE(var) #var "="  VALUE(var)*/

#ifdef __BIG_ENDIAN__
#	undef LOCAL_LITTLE_ENDIAN
#else
#	ifdef __LITTLE_ENDIAN__
#		define LOCAL_LITTLE_ENDIAN
#	else
#		ifdef BSD
#			include <sys/endian.h>
#		elif defined(__linux__)
#			include <endian.h>
#		endif /* BSD */
#		if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __BIG_ENDIAN__
#			undef LOCAL_LITTLE_ENDIAN
#		elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __LITTLE_ENDIAN__
#			define LOCAL_LITTLE_ENDIAN
#		elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#			undef LOCAL_LITTLE_ENDIAN
#		elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#			define LOCAL_LITTLE_ENDIAN
#		else
#			error "unable to determine endianess!"
#		endif /* __BYTE_ORDER == __BIG_ENDIAN */
#	endif /* __LITTLE_ENDIAN__ */
#endif /* __BIG_ENDIAN__ */

/*#pragma message(VAR_NAME_VALUE(LOCAL_LITTLE_ENDIAN))*/

//#endif /* ANDROID_LIBRARY */

#endif
