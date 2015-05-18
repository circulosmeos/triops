/*
 * crypty.h
 *
 *  Created on: 06/09/2014
 *
 */

#ifndef CRYPTY_H_
#define CRYPTY_H_

// .................................................
#undef WINDOWS_PLATFORM 	// Compile for Unix or for Windows: #undef o #define
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
#else
#include <windows.h>
#include <winbase.h> // to use GetFileTime and SetFileTime (on Unix I use utime)
#endif
#include <string.h>
#include <fcntl.h>  // open, etc.
#ifndef WINDOWS_PLATFORM
#include <unistd.h> // truncate
#else
#include <io.h> 	// I use fopen(), not open(), except in truncateFile()
#endif


#endif /* CRYPTY_H_ */
