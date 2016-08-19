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
#define _FILE_OFFSET_BITS 64	// stat, fseek
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE		// off64_t for fseek64
#define ZERO_LL 0LL				// long long zero - crafted specially to be used in FSEEK( , , SEEK_END);
// .................................................

// .................................................
#define WINDOWS_PLATFORM 	// Compile for Unix or for Windows: #undef o #define
							// this just includes (*nix) or don't (windows) "windef.h"
#define LOCAL_LITTLE_ENDIAN	// it is important to undef in order to compile
							// on Big Endian processors (p. ej. SPARC, or Itanium with HP-UX)
// .................................................

#undef ANDROID_LIBRARY 		// avoid stdin and stdout manipulations, as this will be an OS library (.so)

#include "set_endianness.h"	// LOCAL_LITTLE_ENDIAN is automagically determined if ANDROID_LIBRARY is set
 							// as the library can, and will, be compiled for multiple plataforms.

//#include <stdint.h>
// v6: Solaris compatibility
#include <inttypes.h>


#ifndef WINDOWS_PLATFORM
#include "windef.h" // Windows types definitions
#include <utime.h>  // to change the modification time (and so to preverve the original one)
#define FSEEK fseeko 	// (LFS)
#else
#include <windows.h>
#include <winbase.h> // to use GetFileTime and SetFileTime (on Unix I use utime)
#include <io.h>		 // _chsize_s, _open (LFS)
#define FSEEK _fseeki64 // large file support in windows (LFS)
#endif

#include <string.h>
#include <fcntl.h>  // open, etc.

#include <unistd.h> // getopt()
#include <ctype.h>  // isprint()

#ifndef __sun
#include <getopt.h> // getopt() compatible with -std=c99
#endif

// sets binary mode for stdin in Windows
#define STDIN 0
#define STDOUT 1
#ifdef _WIN32
# include <io.h>
# include <fcntl.h>
# define SET_BINARY_MODE(handle) setmode(handle, O_BINARY)
#else
# define SET_BINARY_MODE(handle) ((void)0)
#endif


#endif /* TRIOPS_H_ */
