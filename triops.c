//
// triops:
//  	Encrypt/decrypt files using
// 		CHACHA20 as cipher algorithm and KECCAK-512 as hash algorithm.
// Features:
// *	Files are (by default) encrypted/decrypted on-the-fly, 
// 		so content is overwritten. This is interesting from a security
//		point of view, as no clear content is left on disk.
// *	When decrypting, if password is not the one used for encrypting, 
//		the process is aborted, so the file cannot be rendered unusable.
//		This behaviour is achieved thanks to a password hash stored within
//		the encrypted file. This hash can optionally be erased when 
//		encrypting (in this case the file could end up be decrypted with
//		an incorrect password, so content could be irrecoverable). 
//		This hash is *not* the same used to encrypt!
// *	File modification time is maintained. File dates are important!
// *	Files can be used as passwords: for example jpg images, etc.
//		(do not lose this 'password' file and do not modify it!)
// 
// Type './triops -h' to obtain command-line help.
//
// Pure C99 code,
// by circulosmeos, May 2015. June 2015. July 2016.
// http://circulosmeos.wordpress.com
// Licensed under GPL v3:
//
//    Copyright (C) 2015  circulosmeos (http://circulosmeos.wordpress.com)
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include "triops.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef ANDROID_LIBRARY
#include <jni.h>
//#include <android/log.h>
//#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "TRIOPS", __VA_ARGS__);
#endif

// stat() in FileSize() (and obtainTimestamp(), #ifndef WINDOWS_PLATFORM)
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WINDOWS_PLATFORM
#include <conio.h>
#else
int getch(void);
#endif

#include "ecrypt-sync.h"
#include "crypto_hash.h"
#include "sph_keccak.h"



// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// data types:



#define TRIOPS_VERSION "8.0"
#define PROGRAM_NAME "triops"

#define BUFFERSIZE 16384 // for CHACHA20: multiple of 64 bytes to avoid bad implementation (http://goo.gl/DHCLz1)
#define KEYSIZE_v3 32 	// KEYSIZE_v3  is for CHACHA20 = 256 bits (256/8=32 bytes)
#define IVSIZE_v3 8 	// IVSIZE_v3   is for CHACHA20 =  64 bits ( 64/8= 8 bytes)
#define HASHSIZE_v3 64 	// HASHSIZE_v3 is for KECCAK-512=512 bits (512/8=64 bytes)

#define MAX_PASSWORD_LENGTH 261 // maximum length of a password introduced with keyboard:
								// 260+1(\n) at minimum to make this value (user&code') backwards compatible:
								// MAX_PASSWORD_LENGTH must be >= MAX_PATH (260) > HASHSIZE_v3

typedef enum {	CheckKeyIsValid_FALSE=0,
				CheckKeyIsValid_TRUE=1,
				CheckKeyIsValid_TRUE_BUT_EMPTY=2
				} CheckKeyIsValid_Constants;
#ifndef WINDOWS_PLATFORM
typedef enum {	obtainTimestamp_ST_ATIME=0, // Most recent access (Windows) (or last time modified (DOS))
				obtainTimestamp_ST_MTIME=1, // Most recent modify
				obtainTimestamp_ST_CTIME=2  // Creation time (NTFS) or most recent change of state (POSIX)
				} obtainTimestamp_Constants;
#endif

typedef enum {	
				TRIOPS_V3=3
				} triops_Versions_Constants;

triops_Versions_Constants triopsVersion;

const char TRIOPS_V3_EXTENSION[]= ".$#3";

union KEY_v3
{
	DWORD	keyW [KEYSIZE_v3 / sizeof (DWORD)];
	BYTE	keyB [KEYSIZE_v3];
};

union HASHEDKEY_v3
{
	DWORD	keyW [HASHSIZE_v3 / sizeof (DWORD)];
	BYTE	keyB [HASHSIZE_v3];
};

// as IVSIZE_v3==64 bits => 64/8/4= 2 int
// uint32_t in order to assure 32 bits int
typedef struct tagIV_v3
{
	uint32_t 	rand1;
	uint32_t	fileTime;
} IV_v3, *LPIV_v3;

union unionIV_v3
{
	IV_v3	iv;
	BYTE	byteIV [sizeof (IV_v3)];
};



// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// functions



void print_help();
int process_file( char *szFile, char *szNewFile, char *szPass, BOOL bEncrypt, 
			BOOL bExplicitPassword, BOOL bOutputToTheSameFile, BOOL bDoNotStorePasswordHash );
void	truncateFile (char *);
BOOL	obtainPasswordFromKeyboard (char *szPass);
BOOL	obtainPassword (char *szFile, char *szPass, BOOL bExplicitPassword);
unsigned long long FileSize(char *);
void 	EliminatePassword (char *szVariable, int LENGTH);
#ifndef WINDOWS_PLATFORM
time_t 	obtainTimestampUnix (char *szFile, int iMarcaDeTiempo);
#else
void 	obtainTimestampWin (char *szFile, LPFILETIME lpLastWriteTime);
void 	writeTimestampWin (char *szFile, LPFILETIME lpLastWriteTime);
#endif

void	truncateFileBySize ( char *, unsigned long long );

void 	LoadIVandHash_v3 (FILE *, LPBYTE, LPBYTE, char *);
int 	CheckKeyIsValid_v3 (LPSTR, LPBYTE, LPBYTE, LPDWORD, BOOL);
void 	createIV_v3 (LPIV_v3, char *);
void	CreateUniqueKey_v3 (LPDWORD, LPBYTE, LPIV_v3);

#ifdef ANDROID_LIBRARY

//int local_triops(int argc, char* argv[]);
int local_triops(int argc, char* const argv[static 4]);




// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// JNI:




// http://stackoverflow.com/questions/22546444/how-to-use-jni-to-call-a-main-function-that-takes-an-array-of-character-pointe
// converted from C++ (new/delete) to C (malloc/free)
jint Java_com_example_triops_MainActivity_triops( JNIEnv*  env, jobject  thiz,  jcharArray jargv )
{    //jargv is a Java array of Java strings
	int argc = (*env)->GetArrayLength( env, jargv );
    //__android_log_print(ANDROID_LOG_DEBUG, "TRIOPS", "%d", argc);
    //typedef char* pchar;
    char **argv = (char**)malloc(argc);
    int i;
    jint result;
    for(i=0; i<argc; i++)
    {
        jstring js = (*env)->GetObjectArrayElement( env, jargv, i ); //A Java string
        const char *pjc = (*env)->GetStringUTFChars( env, js, NULL ); //A pointer to a Java-managed char buffer
        size_t jslen = strlen(pjc);
        argv[i] = (char*)malloc(jslen+1); //Extra char for the terminating null
        strcpy(argv[i], pjc); //Copy to *our* buffer. We could omit that, but IMHO this is cleaner. Also, const correctness.
        //(*env)->ReleaseStringUTFChars( env, js, pjc );	// IT'S MORE STABLE *WITHOUT* THIS LINE (???!!!)
        //__android_log_print(ANDROID_LOG_DEBUG, "TRIOPS", "%s", argv[i]);
    }

    //Call main
    result = local_triops(argc, argv);
    //__android_log_print(ANDROID_LOG_DEBUG, "TRIOPS", "%d", result);

    //Now free the array
    /* if (argv != NULL) {
		for(i=0;i<argc;i++) {
			free(argv[i]);
		}
		free(argv);
    }*/ // this code just raised a segfault ALWAYS (???!!!)

    return result;
}
#endif




// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// proper pure C code:




// converted from C main() to JNI function
#ifndef ANDROID_LIBRARY
int main (int argc, char* argv[])
#else
//int local_triops (int argc, char* argv[])
int local_triops (int argc, char* const argv[static 4])
#endif
{
	BOOL 		bOutputToTheSameFile;
	char		szPassFile 	[MAX_PATH];
	BOOL		bEncrypt;
	BOOL		bExplicitPassword;
	BOOL		bDoNotStorePasswordHash;
	BOOL 		bObligatoryKey;
	BOOL 		bBreakOnFirstError;
	char		szFile 		[MAX_PATH];
	char		szNewFile 	[MAX_PATH];
	char		szPass [MAX_PASSWORD_LENGTH];
	BOOL		bPass = FALSE;
	char		szPassv3	[MAX_PASSWORD_LENGTH];
	BOOL		bPassv3 = FALSE;
	int 		output;
	int 		i;

    // default options:
    bOutputToTheSameFile=TRUE;		// defined as global above
	szFile[0]=0x0;
	szNewFile[0]=0x0;
    szPassFile[0]=0x0;
    bEncrypt=FALSE;
    bExplicitPassword=FALSE;
    bDoNotStorePasswordHash=FALSE;
    bObligatoryKey=FALSE; 			// it is necessary to indicate a key
    bBreakOnFirstError=FALSE;
	triopsVersion=TRIOPS_V3;

    int opt = 0;
    // options: 
    //  * key: from keyboard (k), from cmdline (p), from file (P)
    //  * output file (o) [optional if decrypting and input is not stdin]
    //  * encryption (and method chosen) (e) [decryption, if not present]
    //  * decryption [optional, as it is the defaut action] (d)
    //  * store (1; or not: 0) the hash to verify the encryted file (H)
    //  * file(s) to encrypt/decrypt
    while ((opt = getopt(argc, argv, "hkp:P:o:e:dHb")) != -1)
        switch(opt) {
            // help
            case 'h':
                print_help();
                return 1;
            case 'k':
                bObligatoryKey=TRUE;
                break;
            case 'p':
                bObligatoryKey=TRUE;
                bExplicitPassword=TRUE;
                strcpy (szPassFile, optarg);
                break;
            case 'P':
                bObligatoryKey=TRUE;
                strcpy (szPassFile, optarg);
                break;
            case 'o':
                bOutputToTheSameFile=FALSE;
                strcpy (szNewFile, optarg);
                break;
            case 'e':
                bEncrypt=TRUE;
                if (strcmp(optarg, "3")!=0) {
                    printf ("Only '-e 3' is actually accepted ('%s' found)\n", optarg);
                    return 1;
                }
                break;
            case 'd':
                bEncrypt=FALSE;
                break;
            case 'H':
                bDoNotStorePasswordHash=TRUE;
                break;
            case 'b':
            	bBreakOnFirstError=TRUE;
            	break;
            case '?':
                if (isprint (optopt))
                    printf ("Unknown option `-%c'.\n", optopt);
                else
                    printf ("Unknown option character `\\x%x'.\n", optopt);
                //break;
                printf("Command aborted\n");
                return 1;
            default:
                abort();
        }

    if (bObligatoryKey==FALSE) {
        printf("ERROR: Key absent: it is obligatory to indicate a key for encryption/decryption.\n");
        return 1;
    }

    // obtain password from keyboard:
    if (bExplicitPassword==FALSE && 
    	strlen(szPassFile)==0) {
    	if (!obtainPasswordFromKeyboard(szPassFile)){
    		printf("ERROR: could not obtain password from keyboard.\nProcess aborted.\n");
    		return 1;
    	}
    	bExplicitPassword=TRUE;
    }
    // from now on only options are file to be hashed or explicit password from comdline


	// needed by createIV_v3
	srand((unsigned) time(NULL)); 


	// note: 
	// set output value and break to let the return be done later, 
	// because an EliminatePassword() call is convenient before exit.
    if (optind == argc) {
        // if no additional arguments are present
        // file input has not been indicated: error!
        printf("ERROR: no file input(s) has been indicated.\n");
        output = 1;
    } else {
        // If multiple file inputs are indicated, no single output file can be present
        // as output will be the overwriting of each one of them.
        if (bOutputToTheSameFile==FALSE && (optind+1)<argc) {
            printf("ERROR: When multiple input files are indicating they'll be overwritten\n\tso a single output file is invalid.\n");
            output = 1;
        } else {
	        for (i = optind; i < argc; i++) {
	        	if ( strlen(argv[i]) < (MAX_PATH-4) ) {
	        		strcpy (szFile, argv[i]);

				    // decrypting: so triops Version can be deduced from extension:
				    if (bEncrypt==FALSE) {
				                if (strcmp( szFile+(strlen(szFile)-4), TRIOPS_V3_EXTENSION ) == 0 )
				                    triopsVersion=TRIOPS_V3;
				                else {
				                    printf ("\nFile not processed:\nDecryption format could not be deduced from file extension: %s\n", szFile);
				                    if (bBreakOnFirstError==TRUE) {
					            		output=1;
					            		break;
						            } else
				                    	continue;
				                }
				        if (triopsVersion == TRIOPS_V3) {
				        	if (bPassv3 == FALSE && 
				        		!obtainPassword (szPassFile, szPassv3, bExplicitPassword)) {
								printf ("\nERROR: Could not obtain password.\nProcess aborted.\n\n");
			                    if (bBreakOnFirstError==TRUE) {
				            		output=1;
				            		break;
					            } else
			                    	continue;
							}
							bPassv3=TRUE;
							memcpy(szPass, szPassv3, MAX_PASSWORD_LENGTH);
						}
				    } else {
				    	// encrypting:
				    	// we need to obtainPassword() just once
				    	if (bPass==FALSE &&
				    		!obtainPassword (szPassFile, szPass, bExplicitPassword)) {
								printf ("\nERROR: Could not obtain password.\nProcess aborted.\n\n");
			                    if (bBreakOnFirstError==TRUE) {
				            		output=1;
				            		break;
					            } else
			                    	continue;
						}
						bPass=TRUE;
						// password isn't needed anymore: overwrite variable as a paranoic security measure:							
						EliminatePassword(szPassFile, MAX_PATH);
				    }

				    output=process_file( szFile, szNewFile, szPass, bEncrypt, 
	            				bExplicitPassword, bOutputToTheSameFile, bDoNotStorePasswordHash );
	            	
	        	} else {
	        		printf("\nFile not processed: path is too long for '%s'\n", argv[i]);
                    if (bBreakOnFirstError==TRUE) {
	            		output=1;
	            		break;
		            } else
                    	continue;
	        	}

            	if (output!=0) { 
            		if (bBreakOnFirstError==FALSE) {
						// print warning, but continue processing next files:
	            		printf("ERROR processing '%s'\n", szFile);
	            		output=0;
			        } else
			        	break;
			    }

	        }
	    }
    }

	// password hash isn't needed anymore: overwrite variable as a paranoic security measure:
	EliminatePassword(szPass, MAX_PASSWORD_LENGTH);
	EliminatePassword(szPassFile, MAX_PATH);
	EliminatePassword(szPassv3, MAX_PASSWORD_LENGTH);

	return output;

}


int 
process_file( char *szFile, char *szNewFile, char *szPass, BOOL bEncrypt, 
	BOOL bExplicitPassword, BOOL bOutputToTheSameFile, BOOL bDoNotStorePasswordHash ) 
{

	//char		szFile 		[MAX_PATH];		// defined as parameter
	//char		szNewFile 	[MAX_PATH];		// defined as parameter 
	//char		szPass [MAX_PASSWORD_LENGTH]; // defined as parameter
	//BOOL		bEncrypt;				 	// defined as parameter
	//BOOL		bDoNotStorePasswordHash;	// defined as parameter
	//BOOL		bOutputToTheSameFile; 		// defined as parameter
	unsigned long long	nBytesSoFar;
	unsigned long long	nBytesRead;
	FILE *      hFile;
	FILE *      hFileOut;
	FILE *      hFileTail;
	BYTE		lpFileBuffer[BUFFERSIZE];
	int 		i;
	unsigned long long	lFileSize;	// show progress bar
	BOOL		bProgressBar;			// show progress bar
	float		fBlockSize;				// show progress bar
#ifndef WINDOWS_PLATFORM
	struct utimbuf stTimes;
#else
	FILETIME	lLastWriteTime;
#endif
	BYTE		lpEncrypted [BUFFERSIZE];
	unsigned long long	lBlockTotal;		// counts total number of <=BUFFERSIZE blocks in hFileOut
	unsigned long long	lBlockNumber;		// counts number of <=BUFFERSIZE blocks processed in hFileOut
	unsigned long long	lSubtrahend=0;		// bytes to delete from last file block, as they're tail, not data.	
	// CHACHA20 + KECCAK-512
	union unionIV_v3 iv_v3;					// IV for v3 format (CHACHA20+KECCAK-512)
	union KEY_v3		uniqueKey_v3;		// KEY for v3 format (CHACHA20+KECCAK-512)
	union HASHEDKEY_v3	hashedKey_v3, key_v3;//HASH for v3 format (CHACHA20+KECCAK-512)
	BYTE 		matrix3[HASHSIZE_v3];	 	// temporary key v3 hash store
	ECRYPT_ctx  chacha_ctx;					// CHACHA20


#ifdef ANDROID_LIBRARY
	if (szFile[0] != '/') { // security measure
		printf ("\nPath to file not valid: %s.\n\n", szFile);
		return 1;
	}
#endif


	// if output is to the same file, modification timestamp is preserved
	if (bOutputToTheSameFile) {
#ifndef WINDOWS_PLATFORM
		stTimes.modtime=obtainTimestampUnix(szFile, obtainTimestamp_ST_MTIME);
		//stTimes.actime=time(NULL); // access time, to actual date-time: done at the end.
#else
		obtainTimestampWin(szFile, &lLastWriteTime);
#endif
	}

	// open the file
	if (bOutputToTheSameFile) {
		hFile = fopen(szFile, "r+b" );
	} else {
		hFile = fopen(szFile, "rb" );
	}

	if (hFile == NULL)
	{
		printf ("\nError opening %s\n\n", szFile);
		return 1;
	}


	// encrypting:
	// Add encrypted file extension to file's name if we're written to another file.
	// If we're written to the same file, this process is made at the end.
	if (bEncrypt && !bOutputToTheSameFile) {
		szNewFile[strlen(szNewFile)+4]=0x0; // the end of string after the extension addition
		if (triopsVersion==TRIOPS_V3)
			memcpy(szNewFile+strlen(szNewFile), TRIOPS_V3_EXTENSION, 4);
	}

	// encrypting/decrypting to a new file:
	// check that destination file does not exist yet (do not overwrite in that case):
	if (!bOutputToTheSameFile) {
		hFileOut = fopen(szNewFile, "rb" );
		if (hFileOut != NULL)
		{
			printf ("\nError: Destination file already exists: %s\n"
				"\tProcess aborted (nothing has been done).\n\n", szNewFile);
			fclose(hFileOut);
			return 1;
		}
		// once checked that destination file doesn't exist, open said destination file:
		// moved AFTER password has been checked, not to create a superfluous empty file.
		/*hFileOut = fopen(szNewFile, "wb" );
		if (hFileOut == NULL)
		{
			printf ("\nError opening %s\n\n", szNewFile);
			return 1;
		}*/
	}
	else 
	{
		// encrypting/decrypting to the "same" file: 
		// check that destination file does not exist yet (do not overwrite in that case):
		char szDestinationFile [MAX_PATH];
		strcpy(szDestinationFile, szFile);
		if (!bEncrypt) { 
			// !bEncrypt && bOutputToTheSameFile
			szDestinationFile[strlen(szDestinationFile)-4]=0x0;
		} else {
			//  bEncrypt && bOutputToTheSameFile
			if (triopsVersion==TRIOPS_V3)
				memcpy(szDestinationFile+strlen(szDestinationFile), TRIOPS_V3_EXTENSION, 4);			
			szDestinationFile[strlen(szDestinationFile)+4]=0x0;
		}
		// check that destination file does not exist yet (do not overwrite in that case):
		hFileOut = fopen(szDestinationFile, "rb" );
		if (hFileOut != NULL)
		{
			printf ( "\nError: Destination file exists: %s\n"
				"\tProcess aborted (nothing has been done).\n\n", szDestinationFile );
			fclose(hFileOut);
			return 1;
		}
	}


	if (!bEncrypt) {
		if (triopsVersion==TRIOPS_V3) 
			LoadIVandHash_v3 (hFile, iv_v3.byteIV, hashedKey_v3.keyB, szFile);
	} else {
		// if encrypting, then password hash and IV must be created:
		// CheckKeyIsValid returns in hashedKey.keyW the hash, if TRUE is passed as last argument:
		if (triopsVersion==TRIOPS_V3) {
			createIV_v3 (&iv_v3.iv, szFile);
			/* DEBUG: check value:*/
			/*printf ("IV: ");
			for (i=0; i<2; i++) printf(" %08lx",((DWORD *)&iv_v3.iv)[i]);*/
			// IN: szPass, lpIV; OUT: lpKey (for encrypting), lpHashedKey (for writing to file)
			CheckKeyIsValid_v3 (szPass, key_v3.keyB, iv_v3.byteIV, hashedKey_v3.keyW, TRUE);
		}
	}

	// check for validity of passphrase
	if (!bEncrypt) {
		if (triopsVersion==TRIOPS_V3)
			// IN: szPass, lpIV, lpHashedKey (read from file); OUT: lpKey (for decrypting)
			i=CheckKeyIsValid_v3 (szPass, key_v3.keyB, iv_v3.byteIV, hashedKey_v3.keyW, FALSE);
		switch (i) {
			case CheckKeyIsValid_FALSE:
				printf ("\nerror: file '%s' didn't pass password hash checking\n\n", szFile);
				return 1;
			case CheckKeyIsValid_TRUE_BUT_EMPTY:
				printf ("\nwarning: file '%s' decrypted without password hash checking\n", szFile);
		}
	}

	// AFTER password has been checked, (not to create a superfluous empty file), and 
	// once checked that destination file doesn't exist (upper code), open said destination file:
	if (!bOutputToTheSameFile) {
		hFileOut = fopen(szNewFile, "wb" );
		if (hFileOut == NULL)
		{
			printf ("\nError opening %s\n\n", szNewFile);
			return 1;
		}
	}

	// if process arrives here, the password has been checked as correct and 
	// it's gonna decrypt, so hash can be erased from tail now.
	if (!bEncrypt && bOutputToTheSameFile) {
		fclose (hFile);
		truncateFile (szFile);
		{
		hFile = fopen(szFile, "r+b" );
		if (hFile == NULL) {
			printf ("\nError opening %s\n\n", szFile);
			return (1); // exit (-1);
			}
		}
	}


	// use the IV to create a unique key for this file
	if (triopsVersion==TRIOPS_V3) {
		CreateUniqueKey_v3 (uniqueKey_v3.keyW, key_v3.keyB, &(iv_v3.iv));
		// it is not necessary to make a copy of the original IV, as CHACHA20 uses it as const *
		// memcpy(chacha20_iv, iv_v3.byteIV, IVSIZE_v3);
		/*printf ("\ncalculated key: ");
		for (i=0; i<KEYSIZE_v3/4; i++) printf(" %08lx",uniqueKey_v3.keyW[i]);*/
	}


	// .................................................
	// do CHACHA20 setup:
	// .................................................
	if (triopsVersion==TRIOPS_V3) {
		//ECRYPT_init();
		/*
		* Key setup. It is the user's responsibility to select the values of
		* keysize and ivsize from the set of supported values specified
		* above.      */
		/*
		void ECRYPT_keysetup(
			ECRYPT_ctx* ctx, 
			const u8* key, 
			u32 keysize,                // Key size in bits. 
			u32 ivsize);                // IV size in bits. 
		*/
		ECRYPT_keysetup( &chacha_ctx, (u8 *)uniqueKey_v3.keyB, (u32)(KEYSIZE_v3*8), (u32)(IVSIZE_v3*8) );
		/*
		* IV setup. After having called ECRYPT_keysetup(), the user is
		* allowed to call ECRYPT_ivsetup() different times in order to
		* encrypt/decrypt different messages with the same key but different
		* IV's.       */
		/*
		void ECRYPT_ivsetup(
			ECRYPT_ctx* ctx, 
			const u8* iv);
		*/
		ECRYPT_ivsetup( &chacha_ctx, (u8 *)iv_v3.byteIV );
	}
	// .................................................

	// .................................................
	// preparations to encrypt/decrypt the file
	nBytesSoFar = 0;
	i=0; 	// it'll be used as block counter, to show the progress bar.
	lFileSize=(unsigned long long)FileSize(szFile);
	if (lFileSize > 1048576L) {
		bProgressBar=TRUE;
		fBlockSize=(float)lFileSize/50.0;
		printf("\n----+----+----+----+---1/2---+----+----+----+----+ %.0f MiB\n",
			((float)lFileSize)/1048576.0f);
	} else {
		bProgressBar=FALSE;
	}

	// do a cycle reading BUFFERSIZE blocks until all of them have been read:
	lBlockNumber=0;
	lBlockTotal=lFileSize/(unsigned long long)BUFFERSIZE; // this truncates result so:
	if (bEncrypt || (!bEncrypt && bOutputToTheSameFile)) {
		if ( lFileSize % (unsigned long long)BUFFERSIZE != 0 )
			lBlockTotal++;
	}
	if (!bEncrypt && !bOutputToTheSameFile) {
		unsigned long long lTailSize=0;
		if ( triopsVersion==TRIOPS_V3 )
			lTailSize = ( HASHSIZE_v3 + IVSIZE_v3 );
		lSubtrahend = lTailSize;

		if ( lFileSize % (unsigned long long)BUFFERSIZE > lTailSize )
			lBlockTotal++;
		else
			// lFileSize % (unsigned long long)BUFFERSIZE <= lTailSize :
			// subtract tail from file size and 
			// recalculate number of blocks and tail to remove from the last of them. 
			lSubtrahend = lTailSize - (lFileSize%(unsigned long long)BUFFERSIZE);	
	}
	//printf(">>> %lld,%lld,%lld,%lld,%d",
	//	(lFileSize%BUFFERSIZE),lSubtrahend,lBlockTotal,lFileSize,BUFFERSIZE);

	// .................................................
	// encrypt/decrypt the file
	do
	{
		lBlockNumber++;
		// this is needed, because with open in update mode ('+'):
		// "output cannot be directly followed by input without
		// an intervening fseek or rewind ...
		// input cannot be directly followed by output without an intervening
		// fseek, rewind, or an input that encounters  end-of-file."
		if (bOutputToTheSameFile) {
			if (FSEEK(hFile, nBytesSoFar, SEEK_SET)!=0) {
				printf ("\nerror: couldn't move correctly inside '%s'\n"
				"\tProcess aborted.\n", szFile);
			}
		}

		// fill the buffer with file contents:
		nBytesRead = fread(lpFileBuffer, BUFFERSIZE, 1, hFile);
		// progress bar is updated only if file size >10MiB
		if (bProgressBar) {
			if ((float)nBytesSoFar/fBlockSize > (float)i) {
				i++;
				printf("#");
				fflush(stdout); // flash stdout!
			}
		}
		if (nBytesRead || feof(hFile) )
		{
			if (feof(hFile)) {
				nBytesRead = lFileSize % (unsigned long long)BUFFERSIZE;
			} else {
				// real nBytesRead, because nBytesRead is now just '1'
				nBytesRead = nBytesRead * (unsigned long long)BUFFERSIZE;
			}
			// when decrypting to another file, take care
			// to remove the triops tail, or :
			// TRIOPS_V3: Output File Size will be greater than original data file.
			if (!bEncrypt && 
				!bOutputToTheSameFile &&
				lBlockNumber==lBlockTotal)
				nBytesRead -= lSubtrahend;
			// encrypt or decrypt as required
			if (triopsVersion==TRIOPS_V3) {
				if (bEncrypt) {
					if (lBlockNumber==lBlockTotal)
						/*
						void ECRYPT_encrypt_bytes(
							ECRYPT_ctx* ctx, 
							const u8* plaintext, 
							u8* ciphertext, 
							u32 msglen);                // Message length in bytes.
						*/
						ECRYPT_encrypt_bytes (
							&chacha_ctx, 
						  	(const u8 *)lpFileBuffer, lpEncrypted, nBytesRead );					
					else
						/*
						#define ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
							ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,               \
							(blocks) * ECRYPT_BLOCKLENGTH) 
						*/
						/* The user is allowed to make multiple calls to
						*  ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
						*  but he is NOT allowed to make additional encryption calls once he
						*  has called ECRYPT_encrypt_bytes() (unless he starts a new message
						*  of course). */
						ECRYPT_encrypt_blocks ( 
						  	&chacha_ctx, 
						  	(const u8 *)lpFileBuffer, lpEncrypted, BUFFERSIZE/ECRYPT_BLOCKLENGTH );
				} else {
					//printf("%lld, %lld, %lld, %hhd",lBlockNumber,lBlockTotal,nBytesRead);
					if (lBlockNumber==lBlockTotal)			
						/*
						void ECRYPT_decrypt_bytes(
							ECRYPT_ctx* ctx, 
							const u8* ciphertext, 
							u8* plaintext, 
							u32 msglen);                // Message length in bytes. 
						*/ 
						ECRYPT_decrypt_bytes(
							&chacha_ctx, 
						  	(const u8 *)lpFileBuffer, lpEncrypted, nBytesRead);					
					else
						/* 
						#define ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
							ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,               \
							(blocks) * ECRYPT_BLOCKLENGTH) 
						*/
						ECRYPT_decrypt_blocks(
							&chacha_ctx, 
						  	(const u8 *)lpFileBuffer, lpEncrypted, BUFFERSIZE/ECRYPT_BLOCKLENGTH );
				}
				memcpy(lpFileBuffer, lpEncrypted, nBytesRead);
			}
			// reset the file pointer for the write
			if (bOutputToTheSameFile) {
				if (FSEEK(hFile, nBytesSoFar, SEEK_SET)!=0) {
					printf ("\nerror: couldn't move correctly inside '%s'\n"
					"\tProcess aborted.\n", szFile);
				}
			}
			// write the buffer
			if (bOutputToTheSameFile) {
				fwrite(lpFileBuffer, nBytesRead, 1, hFile );
			} else {
				fwrite(lpFileBuffer, nBytesRead, 1, hFileOut );
			}
			// increment byte count
			nBytesSoFar += nBytesRead;
		}
	} while (lBlockNumber<lBlockTotal);
	// .................................................

	// if encrypting, IV + password hash must be stored:
	if (bEncrypt) {
		if (bOutputToTheSameFile) {
			hFileTail=hFile;
		} else {
			hFileTail=hFileOut;
		}
		// IV:
		if (triopsVersion==TRIOPS_V3)
			fwrite(iv_v3.byteIV, IVSIZE_v3, 1, hFileTail );
		// ~ password hash:
		if (!bDoNotStorePasswordHash) {
			if (triopsVersion==TRIOPS_V3)
				memcpy(matrix3, hashedKey_v3.keyB, HASHSIZE_v3);
		/*printf ("calculated tail: ");
		for (i=0; i<HASHSIZE_v3/4; i++) printf(" %08lx",hashedKey_v3.keyW[i]);*/
		} else {
			// the space destined to the hash is filled with all zeros value:
			if (triopsVersion==TRIOPS_V3)
				for (i=0; i < HASHSIZE_v3; i++) { matrix3[i]=0x0; }
		}
		if (triopsVersion==TRIOPS_V3)
			fwrite(matrix3, HASHSIZE_v3, 1, hFileTail );
	}

	// close the file
	fclose(hFile);

	// if output is to the same file, modification timestamp is preserved
	if (bOutputToTheSameFile) {
#ifndef WINDOWS_PLATFORM
		stTimes.actime=time(NULL); // with access time, the actual date
		if ( utime(szFile, &stTimes) != 0 )	{
			printf("warning: could not modify time attributes for '%s'.\n", szFile);
		}
#else
		writeTimestampWin(szFile, &lLastWriteTime);
#endif
	}

	if (!bOutputToTheSameFile)
		fclose(hFileOut);

	// rename the file to remove the encryption extension
	if (!bEncrypt) {
		if (bOutputToTheSameFile) {
			strcpy(szNewFile, szFile);
			szNewFile[strlen(szNewFile)-4]=0x0;
			if (rename (szFile, szNewFile) != 0) {
				printf ("\nwarning: couldn't rename '%s' to '%s'\n"
				"\tthough '%s' has been sucessfully decrypted!!!\n", szFile, szNewFile, szFile);
			}
		}
	}

	// Add encrypted file extension to file's name if we're written to the same file.
	// If we're written to the another file, this process has already been done.
	if (bEncrypt && bOutputToTheSameFile) {
		strcpy(szNewFile, szFile);
		szNewFile[strlen(szNewFile)+4]=0x0; // the end of string after the extension addition
		if (triopsVersion==TRIOPS_V3)
			memcpy(szNewFile+strlen(szNewFile), TRIOPS_V3_EXTENSION, 4);

		if (rename (szFile, szNewFile) != 0) {
			printf ("\nwarning: couldn't rename '%s' to '%s'\n"
			"\tthough '%s' has been sucessfully encrypted!!!\n", szFile, szNewFile, szFile);
		}
	}

	if (bProgressBar) printf(" 100%c\n",37);
	printf("\n'%s' processed\n\n", szFile);

	// finish
	return 0;
}


void 
print_help() {
    // options: 
    //  * key: from keyboard (k), from cmdline (p), from file (P)
    //  * output file (o) [optional if decrypting and input is not stdin]
    //  * encryption (and method chosen) (e) [decryption, if not present]
    //  * decryption [optional, as it is the defaut action] (d)
    //  * store (1; or not: 0) the hash to verify the encryted file (H)
    //  * file(s) to encrypt/decrypt

		printf ("\n%s v%s.  (goo.gl/lqT5eP) (wp.me/p2FmmK-7Q)\n"
			"\nEncrypt and decrypt files with secure password checking and\n"
			"data overwriting, using CHACHA20 and KECCAK-512 algorithms.\n"
			"\n$ %s {-kpP} [-oedHbh] <file> ...\n\n"
			"\t<file> ... : one or more files to encrypt/decrypt\n"
			"\t-k : read passphrase from keyboard\n"
			"\t-p <password> : password is indicated in cmdline\n"
			"\t\t(beware of shell history!)\n"
			"\t-P <password_file> : use hashed <password_file> as password\n"
			"\t-o <output_file>: do not overwrite, but write to <output_file>\n"
			"\t\tThis option is not possible with multiple input files.\n"
			"\t-e <type>: encrypt. "
			"\n\t\tActually only '-e 3' value is allowed (file extension '%s').\n"
			"\t\tOther algorithms can be available in the future.\n"
			"\t-d : decrypt. This is the default action.\n"
			"\t\tDecryption type is guessed from file extension.\n"
			"\t\tActually the only decryption extension available is '%s'\n"
			"\t-H : do not store password hash hint when encrypting\n"
			"\t\tNote that this way, an incorrect decryption password\n"
			"\t\twith data overwrting, will render the file unusable.\n"
			"\t-b : break actions on first error encountered\n"
			"\t-h : print this help\n\n"
				,PROGRAM_NAME, TRIOPS_VERSION, PROGRAM_NAME
				,TRIOPS_V3_EXTENSION, TRIOPS_V3_EXTENSION
			);
		return;
}


// returns the size of the file in bytes
unsigned long long FileSize( char *szFile )
{
#ifdef WINDOWS_PLATFORM
  // large file support in Windows
  struct _stati64 fileStat;
  int err = _stati64( szFile, &fileStat );
#else
  struct stat fileStat;
  int err = stat( szFile, &fileStat );
#endif  
  if (0 != err) {
	printf ("Error while reading file. Nothing changed.\n");
    exit (-3);
  }
  return (unsigned long long) fileStat.st_size;
}

// truncates the size of the file, deleting the encrypted file's data tail 
// (or its equivalent size, which is the same).
void 
truncateFile ( char *szFile )
{
	long int bytesToTruncate;
	if (triopsVersion==TRIOPS_V3)
		bytesToTruncate=(unsigned long long)( sizeof(IV_v3) + HASHSIZE_v3 );

	truncateFileBySize ( szFile, bytesToTruncate);
}

// truncates the size of the file, deleting bytesToTruncate bytes from the encrypted file's tail 
// (or its equivalent size, which is the same).
void 
truncateFileBySize ( char *szFile, unsigned long long bytesToTruncate )
{
	// this check is needed because the file to truncate can be smaller !
	if ( FileSize(szFile) < bytesToTruncate ) {
		printf ("File '%s' is too small to contain encrypted information.\nProcess aborted.\n", szFile);
		exit (-3);
	}

#ifndef WINDOWS_PLATFORM
    {
        if (truncate(szFile, FileSize(szFile) - bytesToTruncate )) {
            printf ("Error while modifying file. Hope nothing changed, but can't assure that.\n");
            exit (-3);
        }
    }
	//
#else
    {
        int iFile;
		if ((iFile=_open(szFile,_O_WRONLY))==0) {
            printf ("\nError opening %s\n", szFile);
            exit (-1);
		}
        if (_chsize_s(iFile, FileSize(szFile) - bytesToTruncate )) {
            printf ("Error while modifying file. Hope nothing changed, but can't assure that.\n");
            close (iFile);
            exit (-3);
        }
        close (iFile);
    }
    //
#endif

}

// obtain user's password from the keyboard:
BOOL
obtainPasswordFromKeyboard (char *szPass) 
{
#ifndef ANDROID_LIBRARY
	int 		i, c;

	// the user wants to insert the password from the keyboard:
	printf("\n\nEnter password and press [enter]: ");
	fflush(stdout); // flash stdout
	i=0;
	while ( i<(MAX_PASSWORD_LENGTH-1) && (c = getch()) != 13 ) { // read chars until "\n"
		if (c!=8 && c!=127) {
			szPass[i]=(char)c;
			i++;
			putchar('*');
		} else { // backspace char pressed: delete previous char!
			if (i>0) {
				i--;
				szPass[i]=0x0;
				// put caret backwards and erase previous '*'
				putchar(8); // backspace
				putchar(32); // space (and so, one char forward)
				putchar(8); // backspace again
			}
		}
		fflush(stdout);
	}
	szPass[i]=0x0; // important!!! to mark the end of the string
	// delusion eavesdropping password length!
	for (i = 0;  i < strlen(szPass);  i++, putchar(8), putchar(32), putchar(8));
	printf("\n\n");
	// if password length reaches MAX_PASSWORD_LENGTH, input ends abruptly, warn it!
	if ( i==(MAX_PASSWORD_LENGTH-1) ) {
		printf ("WARNING: password exceeded max length, and it was truncated to %i chars.\n",
			MAX_PASSWORD_LENGTH);
		printf ("Should process continue (y/n)? : ");
		c=getch();
		if (c!=121) { 	// anything different from "y"
			printf ("n\n\n");
			return FALSE;
		} else {		// ok, continue
			printf ("y\n\n");
		}
	}

	return TRUE;

#else	// #ifndef ANDROID_LIBRARY
	return TRUE;
#endif	// #ifndef/#else ANDROID_LIBRARY
}

// modification for using binary files as passwords:
// returns the hash calculated from the contents 
// of the file passed as a fs path (*szFile).
// If bExplicitPassword==TRUE the *szFile is the password itself.
BOOL
obtainPassword (char *szFile, char *szPass, BOOL bExplicitPassword)
{
	FILE *      hFile;
	unsigned long long 	  nBytesRead;
	BYTE		lpFileBuffer [BUFFERSIZE];
	int 		i, c;
	unsigned long long 	  lFileSize;
	sph_keccak512_context mc;

	// obtain password either from keyboard (strlen(szFile)==0) 
	// or from the passed string szFile directly (bExplicitPassword==TRUE)
	if (bExplicitPassword==TRUE) {
		// obtain password from the passed string szFile directly
		strcpy(szPass, szFile);

		// and now, directly calculate hash here:
		if (triopsVersion == TRIOPS_V3) {
			crypto_hash((unsigned char *)szPass, (unsigned char *)szPass, strlen(szPass));
			/* DEBUG: check value:
			printf ("calculated hash from password: ");
			for (i=0; i<16; i++) printf(" %08lx",((LPDWORD)szPass)[i]);
			*/
		}


	} else {
	// ! (bExplicitPassword==TRUE)
	// obtain password from the file path passed in szFile

		hFile = fopen(szFile, "rb" );
		if (hFile == NULL)
		{
			printf ("\nError opening '%s'\n", szFile);
			return FALSE;
		}

		lFileSize=(unsigned long long)FileSize(szFile);
		if (lFileSize == 0)
		{
			fclose (hFile);
			printf ("\nError: file '%s' is empty!\n", szFile);
			return FALSE;
		}

		// prepare environment to read the contents of the file used as password,
		// and calculate its hash.
		unsigned long long	lBlockTotal;	// counts total number of <=BUFFERSIZE blocks in hFile
		unsigned long long	lBlockNumber;	// counts number of <=BUFFERSIZE blocks processed in hFile
		lBlockNumber=0;
		lBlockTotal=lFileSize/(unsigned long long)BUFFERSIZE; // this truncates result so:
		if ( lFileSize % (unsigned long long)BUFFERSIZE != 0 )
			lBlockTotal++;

		if (triopsVersion == TRIOPS_V3) {
			sph_keccak512_init(&mc);
		}
		
		// read the contents of the file used as password.
		// it can contain plain text password (no final \n or it'll be included) or binary data.
		do
		{
			lBlockNumber++;
			// size_t fread(void *ptr, size_t size, size_t n, FILE *stream);
			nBytesRead=(unsigned long long)fread(lpFileBuffer, BUFFERSIZE, 1, hFile);
			if (nBytesRead || feof(hFile) )
			{
				if (feof(hFile)) {
					nBytesRead = lFileSize % (unsigned long long)BUFFERSIZE;
				} else {
					// real nBytesRead, because nBytesRead is now just '1'
					nBytesRead = nBytesRead * (unsigned long long)BUFFERSIZE;
				}
				if (triopsVersion==TRIOPS_V3) {
					sph_keccak512(&mc, lpFileBuffer, (size_t)nBytesRead);
				}

			}
		} while (lBlockNumber<lBlockTotal);

		if (triopsVersion==TRIOPS_V3) {
			sph_keccak512_close(&mc,szPass);
			/* DEBUG: check value:
			printf ("calculated hash from file: ");
			for (i=0; i<16; i++) printf(" %08lx",((LPDWORD)szPass)[i]);
			*/
		}

		fclose (hFile);

	} // else ends ( if (bExplicitPassword==TRUE) )

	return TRUE;

}


// password is not needed anymore: variables are filled not to reside in memory,
// as a paranoic security measure:
void EliminatePassword(char *szVariable, int LENGTH)
{
	int i;

	// variable is refilled:
	for (i=0; i < LENGTH; i++) {
		//szVariable[i]=0xff;
		szVariable[i]=rand() % 256;
	}

}

#ifndef WINDOWS_PLATFORM
// obtain some time stamps from the file
time_t obtainTimestampUnix(char *szFile, int iMarcaDeTiempo)
{
	struct stat fileStat;

	if ( stat( szFile, &fileStat ) != 0 ) {
		//printf ("warning: error while reading file '%s' time attributes. (using actual time).\n",
		//		szFile);
		return ( (time_t) time(NULL) ); // this should occur only when file doesn't exist
	}
	switch (iMarcaDeTiempo) {
		case obtainTimestamp_ST_ATIME:
			return (fileStat.st_atime);
		case obtainTimestamp_ST_MTIME:
			return (fileStat.st_mtime);
		case obtainTimestamp_ST_CTIME:
			return (fileStat.st_ctime);
		default:
			return ( (time_t) time(NULL) ); // for completeness
	}

}
#else
// obtain, in windows, the modification time stamp
void obtainTimestampWin(char *szFile, LPFILETIME lpLastWriteTime)
{
	HANDLE hFile;

	hFile = CreateFile( szFile,			  // TEXT("myfile.txt"), // file to open
				   FILE_READ_ATTRIBUTES,  // open just in order to read attributes
				   FILE_SHARE_READ,       // share for reading
				   NULL,                  // default security
				   OPEN_EXISTING,         // existing file only
				   FILE_ATTRIBUTE_NORMAL, // normal file
				   NULL);                 // no attr. template
	if (hFile == INVALID_HANDLE_VALUE) {
		;	/*printf("warning: could not open attributtes for file '%s' (error: %d)\n",
			szFile, GetLastError());*/
	} else {
		if ( GetFileTime(
				hFile,	// identifies the file
				(LPFILETIME)NULL,	// address of creation time
				(LPFILETIME)NULL,	// address of last access time
				lpLastWriteTime 	// address of last write time
				)==0 )
			printf("warning: could not read file date for '%s'\n", szFile);
		CloseHandle(hFile);
	}
}

// write, in windows, the modification time stamp
void writeTimestampWin(char *szFile, LPFILETIME lpLastWriteTime)
{
	HANDLE hFile;

	hFile = CreateFile( szFile,			  // TEXT("myfile.txt"), // file to open
				   FILE_WRITE_ATTRIBUTES,  // open just in order to write attributes
				   0,                      // do not share
				   NULL,                   // default security
				   OPEN_EXISTING,          // existing file only
				   FILE_ATTRIBUTE_NORMAL,  // normal file
				   NULL);				   // no attr. template
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("warning: can't write attributtes for file '%s' (error: %d)\n",
			szFile, (int)GetLastError());
	} else {
		if ( SetFileTime(
				hFile,	// identifies the file
				(LPFILETIME)NULL,	// address of creation time
				(LPFILETIME)NULL,	// address of last access time
				lpLastWriteTime 	// address of last write time
				)==0 )
			printf("warning: could not change file date for '%s'\n", szFile);
		CloseHandle(hFile);
	}
}
#endif





// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// CHACHA20 and KECCAK-512
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------




void
LoadIVandHash_v3 (FILE *hFile, LPBYTE ivAsBytes, LPBYTE hashedKey, char *szFile)
{
	DWORD	nBytesRead;

	// this check is needed because the file to truncate can be smaller !
	if ( FileSize(szFile) < (unsigned long long)(IVSIZE_v3+HASHSIZE_v3) ) {
		printf ("File '%s' is too small to contain encrypted information.\nProcess aborted.", szFile);
		exit (-3);
	}

	// set the pointer to the beginning of the iv
	FSEEK(hFile, ZERO_LL-(IVSIZE_v3+HASHSIZE_v3), SEEK_END);

	// read the iv
	nBytesRead = fread(ivAsBytes, IVSIZE_v3, 1, hFile);
	
	// read the hashed Key
	nBytesRead = fread(hashedKey, HASHSIZE_v3, 1, hFile);

	/* DEBUG: check value: 
	{
	int i;
	printf ("\nstored: ");
	for (i=0; i<4; i++) printf(" %08lx",((int *)hashedKey)[i]);
	}
	*/


	// reset file pointer to the beginning of the file
	FSEEK(hFile, ZERO_LL, SEEK_SET);

	return;

}


int
CheckKeyIsValid_v3 (LPSTR szPass, LPBYTE lpKey, LPBYTE lpIV, LPDWORD lpHashedKey, BOOL bJustCalculate)
// lpKey will contain the hash used for encryption/decryption.
// if bJustCalculate == TRUE: 
//		calculate lpKey (for encrypting), and lpHashedKey (stored in file) from szPass and lpIV
// 		IN: szPass, lpIV; OUT: lpKey (for encrypting), lpHashedKey (for writing to file)
// if bJustCalculate == FALSE: 
//		check that the hash calculated from szPass and lpIV is lpHashedKey
//		IN: szPass, lpIV, lpHashedKey (read from file); OUT: lpKey (for decrypting)
{
	union HASHEDKEY_v3	testKey;
	char				szTemp [HASHSIZE_v3 + IVSIZE_v3];
	long int 			i;


	/* DEBUG: KECCAK-512:*/
	/*char *hex="b3c5e74b69933c2533106c563b4ca20238f2b6e675e8681e34a389894785bdade59652d4a73d80a5c85bd454fd1e9ffdad1c3815f5038e9ef432aac5c3c4fe840cc370cf86580a6011778bbedaf511a51b56d1a2eb68394aa299e26da9ada6a2f39b9faff7fba457689b9c1a577b2a1e505fdf75c7a0a64b1df81b3a356001bf0df4e02a1fc59f651c9d585ec6224bb279c6beba2966e8882d68376081b987468e7aed1ef90ebd090ae825795cdca1b4f09a979c8dfc21a48d8a53cdbb26c4db547fc06efe2f9850edd2685a4661cb4911f165d4b63ef25b87d0a96d3dff6ab0758999aad214d07bd4f133a6734fde445fe474711b69a98f7e2b";
	char *byte=(char *)szPass;
	while (*hex) { sscanf(hex, "%2hhx", byte++); hex += 2; }*/

	// calculate the theoretical hashedkey from the IV and passed password:
/*
	crypto_hash(testKey.keyB, (unsigned char *)szPass, strlen(szPass));
*/

	/* DEBUG: KECCAK-512:*/
	/*printf ("KECCAK-512: ");
	for (i=0; i<16; i++) printf(" %08lx",testKey.keyW[i]);*/

	// copy the key
/*	
	memcpy(lpKey, testKey.keyB, HASHSIZE_v3);
*/
	memcpy(lpKey, (LPBYTE)szPass, HASHSIZE_v3);
	memcpy(testKey.keyB, (LPBYTE)szPass, HASHSIZE_v3);

	/* DEBUG: check value:
	printf ("calculated: ");
	for (i=0; i<16; i++) printf(" %08lx",testKey.keyW[i]);
	*/

	// .................................................
	// "chain" password and IV to obtain the hash
	// used to compare with the one stored in the encrypted file:
	memcpy((LPBYTE)szTemp, testKey.keyB, HASHSIZE_v3);

	// some hashes more
	for (i=0; i<500; i++) {
		crypto_hash((unsigned char *)szTemp, (unsigned char *)szTemp, HASHSIZE_v3);
	}

	memcpy((LPBYTE)(szTemp+HASHSIZE_v3), lpIV, IVSIZE_v3);

	// hash again in hashedKey:
	crypto_hash(testKey.keyB, (unsigned char *)szTemp, HASHSIZE_v3 + IVSIZE_v3);
	// .................................................

	// now verify against the stored hashed key
	// if (bJustCalculate), that's because we don't have the hashkey yet:
	// we're encrypting and we want the test hash obtained here!
	if (!bJustCalculate) {
		// if it's all zeros, it is not a hash but a file without password hash stored,
		// so an OK must be returned:
		for (i=0; i<16; i++) {
			if (lpHashedKey[i] != 0x0) break;
		}
		if (i==16) 
			return CheckKeyIsValid_TRUE_BUT_EMPTY;

		for (i=0; i<16; i++) {
			if (lpHashedKey[i] != testKey.keyW[i]) break;
		}
		if (i!=16) {
			printf ("\nInvalid passphrase\n");
			/* DEBUG: check value:
			printf ("calculated: ");
			for (i=0; i<16; i++) printf(" %08lx",testKey.keyW[i]);
			printf ("\nstored: ");
			for (i=0; i<16; i++) printf(" %08lx",lpHashedKey[i]);
			printf ("\niv: ");
			for (i=0; i<8; i++) printf(" %02lx",lpIV[i]);
			*/
			return CheckKeyIsValid_FALSE;
		}
	} else {
		for (i=0; i<16; i++) {
			lpHashedKey[i] = testKey.keyW[i];
		}

	}

	return CheckKeyIsValid_TRUE;
}


// returns an initialization vector of 8*8=64 bits based on:
// 4 bytes: date from last access time to the passed file (it could be now(), which is ok)
// 4 bytes: random number
void 
createIV_v3 ( LPIV_v3 iv, char *szFile )
{
	struct stat fileStat;
	unsigned char cTempHash[HASHSIZE_v3];
	unsigned char cTempData[8+IVSIZE_v3];
	unsigned long long lFileSize;
	int i;

	// already done !
	//srand((unsigned) time(NULL));

	int err = stat( szFile, &fileStat );
	if (0 != err) {
		printf ("Error while reading file. Nothing changed.\n");
		exit (-3);
	}
	lFileSize=FileSize( szFile );
	iv->rand1=rand()*rand();
	/*printf("\n = %02lx",iv->rand1);*/
	iv->fileTime=fileStat.st_atime;
	/*printf("\n = %02lx",iv->fileTime);*/

	memcpy( cTempData, 		(unsigned char *)&lFileSize, 8 );
	memcpy( cTempData+8, 	(unsigned char *)&(iv->rand1), 4 );
	memcpy( cTempData+8+4, 	(unsigned char *)&(iv->fileTime), 4 );
	/*
	printf ("\niv: ");
	for (i=0; i<16; i++) printf(" %02lx",cTempData[i]);
	*/

	// ok, now let's hash iv in order to obscure IV:
	// hash from iv, in cTempHash:
	crypto_hash(cTempHash, cTempData, 8+IVSIZE_v3);

	// as KECCAK-512 produces 512 bits, let's get just some bytes:
	for (i=0; i < 8; i++) {
		((unsigned char*)iv)[i] = cTempHash[i*4];
	}
	/*
	printf ("\niv: ");
	for (i=0; i<2; i++) printf(" %02lx",((uint32_t*)iv)[i]);
	*/

	// test IV:
	//+++++++++++++++++++++++++++++++++++++++++++
	/*{
	uint8_t *byte=(unsigned char *)iv;
	char *hex="0001020304050607";
	//char *hex="0000000000000000";
	// hex chars to bytes
	while (*hex) { sscanf(hex, "%2hhx", byte++); hex += 2; }
	}*/
	//+++++++++++++++++++++++++++++++++++++++++++

	return;
}


void
CreateUniqueKey_v3 (LPDWORD uniqueKey, LPBYTE lpKey, LPIV_v3 lpiv)
{
	BYTE				buffer [HASHSIZE_v3 + IVSIZE_v3];
	long int 			i;

	// copy hash of passphrase
	memcpy(buffer, lpKey, HASHSIZE_v3);

	memcpy((LPBYTE)(buffer+HASHSIZE_v3), lpiv, IVSIZE_v3);

	// hash to create key for CHACHA20-256
	crypto_hash((unsigned char *)buffer, (unsigned char *)buffer, HASHSIZE_v3 + IVSIZE_v3);

	// some hashes more (reduced from the 20000 of SHA256 because ARMs are in general slower with KECCAK-512...)
	for (i=0; i<1000; i++) {
		crypto_hash((unsigned char *)buffer, (unsigned char *)buffer, HASHSIZE_v3);
	}

	//memcpy((LPBYTE)(uniqueKey), buffer, KEYSIZE_v3);
	for (i=0; i<KEYSIZE_v3; i++)
		((LPBYTE)(uniqueKey))[i] = buffer[i*2];

	// test key:
	//+++++++++++++++++++++++++++++++++++++++++++
	/*{
	uint8_t *byte=(LPBYTE)uniqueKey;
	char *hex="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	//char *hex="0000000000000000000000000000000000000000000000000000000000000000";
	// hex chars to bytes
	while (*hex) { sscanf(hex, "%2hhx", byte++); hex += 2; }
	}*/
	//+++++++++++++++++++++++++++++++++++++++++++

}




// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// specific *nix keyboard and screen functions,
// to obtain input from the keyboard without screen output. A getch() is defined.
// http://c-faq.com/osdep/kbhit.txt , lee@giaeb.cc.monash.edu.au
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
#ifndef WINDOWS_PLATFORM
#include <unistd.h>     // read()
#include <fcntl.h>      // setting keyboard flags
#include <sys/ioctl.h>
#include <termio.h>     // used to set terminal modes
#include <termios.h>

	//
	// two global variables for tty and keybrd control
	//
	static struct termio term_orig;
	static int kbdflgs;

	//
	// function :   system_mode
	// purpose  :   reset the system to what it was before input_mode was
	//              called
	//
	void system_mode(void)
	{
		if (ioctl(0, TCSETA, &term_orig) == -1) {
			return;
		}
		fcntl(0, F_SETFL, kbdflgs);
	}

	//
	// function :   input_mode
	// purpose  :   set the system into raw mode for keyboard i/o
	// returns  :   0 - error
	//              1 - no error
	//
	int input_mode(void)
	{
		struct termio term;    // to avoid ^S ^Q processing

		//
		// get rid of XON/XOFF handling, echo, and other input processing
		//
		if (ioctl(0, TCGETA, &term) == -1) {
			return (0);
		}
		(void) ioctl(0, TCGETA, &term_orig);
		term.c_iflag = 0;
		term.c_oflag = 0;
		term.c_lflag = 0;
		term.c_cc[VMIN] = 1;
		term.c_cc[VTIME] = 0;
		if (ioctl(0, TCSETA, &term) == -1) {
			return (0);
		}
		kbdflgs = fcntl(0, F_GETFL, 0);
		//
		// no delay on reading stdin
		//
		int flags = fcntl(0, F_GETFL);
		flags &= ~O_NDELAY;
		fcntl(0, F_SETFL, flags);
		return (1);
	}

	//
	// function :   getch
	// purpose  :   read a single character from the keyboard without echo
	// returns  :   the keybress character
	//
	int getch(void)
	{
		//
		// no delays on reading stdin
		//
		input_mode();
		//
		// do a simple loop and get the response
		//
		unsigned char ch;
		while (read(0, &ch, 1) != 1) ;

		system_mode();
		return (ch);
	}

#endif
