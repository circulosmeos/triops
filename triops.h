/*
 * triops.h
 *
 *  Created on: 06/09/2014
 *
 */

#ifndef TRIOPS_H_
#define TRIOPS_H_


// .................................................
// large file support (LFS) (files with size >2^31 (2 GiB) in linux, and >4 GiB in Windows)
#define _FILE_OFFSET_BITS 64    // stat, fseek
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE     // off64_t for fseek64
#define ZERO_LL 0LL             // long long zero - crafted specially to be used in FSEEK( , , SEEK_END);
// .................................................

// truncate() glibc's requirement
#define _XOPEN_SOURCE 500

// .................................................
// Endianness determination: 
// Little Endian processors (Intel/AMD x86 & x86_64, or ARM ...) 
// Big Endian processors (SPARC (with Solaris), or Itanium with HP-UX ...)
#include "set_endianness.h" // LOCAL_LITTLE_ENDIAN is automagically determined if ANDROID_LIBRARY is set
                            // as the library can, and will, be compiled for multiple plataforms.
//#define LOCAL_LITTLE_ENDIAN // replaced by (hopefully) automatic determination in "set_endianness.h"
                              // but if set_endianness.h fails, it can be set (define/undef) here.
// .................................................


// .................................................
// If defined, avoid stdin and stdout manipulations, as this will be an OS library (.so)
// and replace main() with a JNI-aware function
#undef ANDROID_LIBRARY
// .................................................



//#include <stdint.h>
// v6: Solaris compatibility
#include <inttypes.h>


#ifndef _WIN32

#   undef WINDOWS_PLATFORM

#   define MAX_PATH          260

#   ifndef NULL
#       define NULL    ((void *)0)
#   endif

#   ifndef FALSE
#       define FALSE               0
#   endif

#   ifndef TRUE
#       define TRUE                1
#   endif

    // 64 bit compatibility
    typedef uint32_t            DWORD;
    typedef uint16_t            WORD;

    typedef int                 BOOL;
    typedef unsigned char       BYTE;
    typedef BYTE                *LPBYTE;
    typedef DWORD               *LPDWORD;
    typedef char                *LPSTR;

#   include <utime.h>   // to change the modification time (and so to preverve the original one)
#   define FSEEK fseeko // (LFS)

#else

#   define WINDOWS_PLATFORM

#   include <windows.h>
#   include <winbase.h>     // to use GetFileTime and SetFileTime (on Unix I use utime)
#   include <io.h>          // _chsize_s, _open (LFS)
#   define FSEEK _fseeki64  // large file support in windows (LFS)

#endif


#include <string.h>
#include <fcntl.h>  // open, etc.

#include <unistd.h> // getopt(), truncate()
#include <ctype.h>  // isprint()

#ifndef __sun
#   include <getopt.h> // getopt() compatible with -std=c99
#endif

// sets binary mode for stdin in Windows
#define STDIN 0
#define STDOUT 1
#ifdef _WIN32
#   include <io.h>
#   include <fcntl.h>
#   define SET_BINARY_MODE(handle) setmode(handle, O_BINARY)
#else
#   define SET_BINARY_MODE(handle) ((void)0)
#endif


#endif /* TRIOPS_H_ */
