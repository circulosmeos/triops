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
// by circulosmeos, May 2015. June 2015. July 2016. August 2016.
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
//#define fprintf (...) __android_log_print(ANDROID_LOG_DEBUG, "TRIOPS", __VA_ARGS__);
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



#define TRIOPS_VERSION "9.0"
#define PROGRAM_NAME "triops"

#define BUFFERSIZE 16384 // for CHACHA20: multiple of 64 bytes to avoid bad implementation (http://goo.gl/DHCLz1)
						 // v9.0: BUFFERSIZE cannot be smaller than ( IVSIZE_v3 + HASHSIZE_v3 ) = 72 bytes
#define KEYSIZE_v3 32 	// KEYSIZE_v3  is for CHACHA20 = 256 bits (256/8=32 bytes)
#define IVSIZE_v3 8 	// IVSIZE_v3   is for CHACHA20 =  64 bits ( 64/8= 8 bytes)
#define HASHSIZE_v3 64 	// HASHSIZE_v3 is for KECCAK-512=512 bits (512/8=64 bytes)

#define MAX_PASSWORD_LENGTH 261+4 // maximum length of a password introduced with keyboard:
								// 260+1(\n) at minimum to make this value (user&code') backwards compatible:
								// MAX_PASSWORD_LENGTH must be >= MAX_PATH (260) > HASHSIZE_v3
								// v9.0: MAX_PASSWORD_LENGTH must be >= MAX_PATH cause it may temporarily
								// contain a password or path if input is stdin.
								// +4 'cause MAX_PATH can grow 4 chars for file extension

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
				TRIOPS_VERSION_UNKNOWN=0, // v9.0
				TRIOPS_V3=3,
				SIZE_OF_TRIOPS_VERSIONS_ENUM=4
				} triops_Versions_Constants;

triops_Versions_Constants triopsVersion;

const char TRIOPS_V3_EXTENSION[] =      ".$#3";
const char TRIOPS_GENERIC_EXTENSION[] = ".ooo"; // v9.0

// 2 variables to store different hashes for the hypothetical case when hash is obtained from a file
// so it is not read multiples times: bHashAlreadyObtained and szHashAlreadyObtained
BOOL	bHashAlreadyObtained[SIZE_OF_TRIOPS_VERSIONS_ENUM]; //initialize as {FALSE, FALSE, FALSE, FALSE}; @ process_file()
char 	szHashAlreadyObtained[SIZE_OF_TRIOPS_VERSIONS_ENUM][HASHSIZE_v3]; 

// optimization for the case when there's no need to obtain 
// multiple hashes on the fly from a hashed password file:
// obtain just the needed one:
BOOL bJustOneHashIsNeeded; // initialize as FALSE @ process_file()

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
int set_file_position (FILE * hFile, unsigned long long offset, int whence);
unsigned long long read_data_from_file(
	BYTE *lpFileBuffer, int iBufferSize, int iBlocks, FILE *hFile,
	BOOL bEncrypt, BOOL bUsingHeadMetadata, BOOL bOutputToTheSameFile,
	unsigned long long lFileSize, unsigned long long lMetadataSize, 
	unsigned long long lBlockNumber, unsigned long long lBlockTotal, 
	unsigned long long lSubtrahend );
int process_file( char *szFile, char *szNewFile, char *szPass, BOOL bEncrypt, 
			BOOL bExplicitPassword, BOOL bOutputToTheSameFile, BOOL bDoNotStorePasswordHash,
			int iUseSelectedMetadata );
int writeMetadata (FILE *hFileMetadata, 
                   BOOL bDoNotStorePasswordHash,
                   void *IV, int IV_SIZE, 
                   void *HASH, int HASH_SIZE);
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

BOOL 	LoadIVandHash_v3 (FILE *, LPBYTE, LPBYTE, char *, BOOL);
int 	CheckKeyIsValid_v3 (LPSTR, LPBYTE, LPBYTE, LPDWORD, BOOL);
void 	createIV_v3 (LPIV_v3, char *);
void	CreateUniqueKey_v3 (LPDWORD, LPBYTE, LPIV_v3);

#ifdef ANDROID_LIBRARY

//int local_triops(int argc, char* argv[]);
int local_triops(int argc, char* const argv[static 5]);




// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// -------------------------------------------------------------------------------
// JNI:




jint Java_com_example_triops_MainActivity_triops( JNIEnv*  env, jobject  thiz,  jcharArray jargv )
{    
	//jargv is a Java array of Java strings
	int argc = (*env)->GetArrayLength( env, jargv );
    char **argv = malloc(sizeof(char*)*(argc));
    int i;
    jint result;
    for(i=0; i<argc; i++)
    {
        jstring js = (*env)->GetObjectArrayElement( env, jargv, i ); //A Java string
        const char *pjc = (*env)->GetStringUTFChars( env, js, NULL ); //A pointer to a Java-managed char buffer
        argv[i] = strdup( pjc ); // Copy to local buffer
        (*env)->ReleaseStringUTFChars( env, js, pjc );
        (*env)->DeleteLocalRef( env, js );
    }

    //Call main
    result = (jint)local_triops(argc, argv);

    //Now free the array
    if (argv != NULL) {
		for(i=0;i<argc;i++) {
			free(argv[i]);
		}
		free(argv);
    }

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
int local_triops (int argc, char* const argv[static 5])
#endif
{
	BOOL 		bOutputToTheSameFile;
	// v9.0: from MAX_PATH to MAX_PASSWORD_LENGTH cause it can be used to 
	// store szPass in some cases:
	char		szPassFile 	[MAX_PASSWORD_LENGTH];
	BOOL		bEncrypt;
	BOOL		bExplicitPassword;
	BOOL		bDoNotStorePasswordHash;
	BOOL 		bObligatoryKey;
	BOOL 		bBreakOnFirstError;
	BOOL		bStdoutOutput;				// v9.0
	char		szFile 		[MAX_PATH+4];	// +4 'cause MAX_PATH can grow 4 chars for file extension
	char		szNewFile 	[MAX_PATH+4];	// +4 'cause MAX_PATH can grow 4 chars for file extension
	char		szPass [MAX_PASSWORD_LENGTH];
	int 		output;
	int 		i;
	int 		iUseSelectedMetadata = 0; // v9.0: 0 means not explicitely selected, 1: head, 2: tail

    // default options:
    bOutputToTheSameFile=TRUE;		// defined as global above
	szFile[0]=0x0;
	szNewFile[0]=0x0;
	bStdoutOutput=FALSE;
    szPassFile[0]=0x0;
    bEncrypt=FALSE;
    bExplicitPassword=FALSE;
    bDoNotStorePasswordHash=FALSE;
    bObligatoryKey=FALSE; 			// it is necessary to indicate a key
    bBreakOnFirstError=FALSE;
	triopsVersion=TRIOPS_V3;

	// this reset of bHashAlreadyObtained and bJustOneHashIsNeeded 
	// is important #ifdef ANDROID_LIBRARY
	// because they must be reset on each run of the library!
	bJustOneHashIsNeeded=FALSE;
	for (i=0; i<SIZE_OF_TRIOPS_VERSIONS_ENUM; i++)
		bHashAlreadyObtained[i]=FALSE;

    int opt = 0;
    optind = 0; // *must* be reset in order to use getopt() in a .so lib (#ifdef ANDROID_LIBRARY)
    // options: 
    //  * key: from keyboard (k), from cmdline (p), from file (P)
    //  * output file (o) [optional if decrypting and input is not stdin]
    //  * encryption (and method chosen) (e) [decryption, if not present]
    //  * decryption [optional, as it is the defaut action] (d)
    //  * store (1; or not: 0) the hash to verify the encryted file (H)
    //  * metadata location selection 'head' or 'tail' (m)
    //  * file(s) to encrypt/decrypt
    while ((opt = getopt(argc, argv, "hkp:P:i:o:Oe:dHbm:")) != -1) {
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
            case 'i':
            	// explicitely indicated input file
            	strcpy (szFile, optarg);
            	break;
            case 'o':
                bOutputToTheSameFile=FALSE;
                strcpy (szNewFile, optarg);
                break;
            case 'O':
                bStdoutOutput=TRUE;
                break;
            case 'e':
                bEncrypt=TRUE;
                if (strcmp(optarg, "3")!=0) {
                    fprintf (stderr, "Only '-e 3' is actually accepted ('%s' found)\n", optarg);
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
            case 'm':
            	if (strcmp(optarg, "head")==0) { 
            		iUseSelectedMetadata=1; // head
            		break;
            	} else {
            		if (strcmp(optarg, "tail")==0) {
            			iUseSelectedMetadata=2; // tail
            			break;
            		}
            	}
            	fprintf (stderr, "-m accepts only 'head' and 'tail' options\n");
            	return 1;
            case '?':
#ifndef ANDROID_LIBRARY
                if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                //break;
                fprintf (stderr, "Command aborted\n");
#endif
                return 1;
            default:
                return 1;
        }
    }

    if (bObligatoryKey==FALSE) {
        fprintf (stderr, "ERROR: Key absent: it is obligatory to indicate a key for encryption/decryption.\n");
        return 1;
    }

    // decryption reads file's own metadata, so no choice is possible
    if (!bEncrypt && iUseSelectedMetadata!=0) {
		fprintf (stderr, "warning: -m option ignored when decrypting.\n");
		iUseSelectedMetadata=0;
    }

    // it is not possible to choose both stdout and file output simultaneously
    if (bStdoutOutput==TRUE && strlen(szNewFile)!=0) {
        fprintf (stderr, "ERROR: if stdout output is selected, no output file can be indicated.\n");
        return 1;    	
    }

    // if -i indicated, check here its length:
	if ( strlen(szFile) >= MAX_PATH ) {
		fprintf (stderr, "\nFile not processed: path is too long for '%s'.\n", szFile);
		return 1;		
	}

    // exclude keyboard if stdin or stdout have been selected:
	/*if ( ((optind==argc && strlen(szFile)==0) || // stdin
			bStdoutOutput==TRUE) && 	// stdout
		strlen(szPassFile)==0 ) 		// keyboard password indicated
		{
		fprintf (stderr, "Password cannot be read from keyboard when using stdin or stdout.\n"
			"Process aborted.\n");
		return 1;
	}*/

	// set bOutputToTheSameFile=FALSE with stdout selected:
	if (bStdoutOutput) {
		// with stdin as input, output *cannot* be stdin ...
		bOutputToTheSameFile=FALSE;
	}

    // if stdin, some output must explicitely be indicated
    if ((optind==argc && strlen(szFile)==0) && // stdin
    	bOutputToTheSameFile) 
    	{
        fprintf (stderr, "ERROR: with stdin, some output must be indicated ('-o <file>' or '-O').\n");
        return 1;    	    	
    }

    // discard simultaneous -i <file> and ... <file> options of input files
    if ( ((optind+1)<=argc) && 	// 1 or more files after options
    	strlen(szFile)!=0 ) 	// and -i <file> has been indicated
    	{
		fprintf (stderr, "ERROR: It is not possible to indicate files \n"
			"\tsimultaneously with '-i' and after options.\n"
			"Process aborted.\n");
		return 1;
    }

	// If multiple file inputs are indicated, no single output file can be present
	// (whether it is sdtout or not)
	// as output will be the (mangled) concatenation of each one of them.
	if (bOutputToTheSameFile==FALSE && (optind+1)<argc) {
		fprintf (stderr, "ERROR: When multiple input files are indicated they'll be overwritten\n"
			"\tso a single output file is invalid.\n"
			"Process aborted.\n");
		return 1;
	}


	// from now on, no more errors from bad combination of parameters are allowed:
	// just processing:


	// optimization for the case when there's no need to obtain 
	// multiple hashes on the fly from a hashed password file:
	// obtain just the needed one:
	if (bEncrypt) { // encrypting, and so triopsVersion is fixed and known
		bJustOneHashIsNeeded=TRUE;
	}
	// note: another optimization with bJustCalculate later with !bEncrypt && !bStdinInput

    // obtain password from keyboard:
    if (bExplicitPassword==FALSE && 
    	strlen(szPassFile)==0) {
    	if (!obtainPasswordFromKeyboard(szPassFile)){
    		fprintf (stderr, "ERROR: could not obtain password from keyboard.\nProcess aborted.\n");
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
		// ++++++++++++++++++++++++++++++++++++++++++++++++
		// ++++++++++++++++++++++++++++++++++++++++++++++++
		// if no additional arguments are present
		// file input is stdin or just one file (-i)
		// ++++++++++++++++++++++++++++++++++++++++++++++++
		// ++++++++++++++++++++++++++++++++++++++++++++++++

		if (strlen(szFile)==0) { // stdin
			// a strlen(szFile)==0 marks input as stdin for process_file()
			szFile[0]=0x0; // superfluous
			// with stdin as input, output *cannot* be stdin ...
			bOutputToTheSameFile=FALSE;
			// mark input for type guessing from correct head metadata later:
			// as there's no file extension with stdin, file encryption type is unknown
			if (!bEncrypt)
				triopsVersion=TRIOPS_VERSION_UNKNOWN;
		} else {
			// there's just one file to process:

			// decrypting: so triops Version may be deduced from extension:
			if (!bEncrypt) {
						if (strlen(szFile)>4 && 
							strcmp( szFile+(strlen(szFile)-strlen(TRIOPS_V3_EXTENSION)), TRIOPS_V3_EXTENSION ) == 0)
						    triopsVersion=TRIOPS_V3;
						else
						    triopsVersion=TRIOPS_VERSION_UNKNOWN;
			}
			// optimization for the case when there's no need to obtain 
			// multiple hashes on the fly from a hashed password file:
			// obtain just the needed one:
			if (!bEncrypt &&			// decrypting, and 
				triopsVersion!=TRIOPS_VERSION_UNKNOWN	// AND triopsVersion is known
				)
				bJustOneHashIsNeeded=TRUE;

		}

		// if (bEncrypt) delay obtainPassword() to group the use of that function on process_file()
		// if (!bEncrypt) BUT password cannot be hashed yet because with stdin 
		// triopsVersion must be dynamically determined from input content
		// so let's copy the password/path and delay this to process_file()
		memcpy(szPass, szPassFile, MAX_PASSWORD_LENGTH);

		// password isn't needed anymore: overwrite variable as a paranoic security measure:							
		EliminatePassword(szPassFile, MAX_PASSWORD_LENGTH);

		if ( process_file( szFile, szNewFile, szPass, bEncrypt, 
					bExplicitPassword, bOutputToTheSameFile, bDoNotStorePasswordHash,
					iUseSelectedMetadata ) != 0 
			) {
			if (strlen(szFile)==0) {
				fprintf (stderr, "ERROR processing stdin\n");
			} else {
				fprintf (stderr, "ERROR processing '%s'\n", szFile);
			}
			output=1; // error
		} else
			output=0;

	} else { // if (optind == argc)
		for (i = optind; i < argc; i++) {
			if ( strlen(argv[i]) < MAX_PATH ) {
				strcpy (szFile, argv[i]);
				// decrypting: so triops Version may be deduced from extension:
				if (!bEncrypt) {
							if (strlen(szFile)>4 && 
								strcmp( szFile+(strlen(szFile)-strlen(TRIOPS_V3_EXTENSION)), TRIOPS_V3_EXTENSION ) == 0)
							    triopsVersion=TRIOPS_V3;
							else {
							    /*fprintf (stderr, "\nFile not processed:\nDecryption format could not be deduced from file extension: %s\n", szFile);
							    if (bBreakOnFirstError==TRUE) {
									output=1;
									break;
							    } else
							    	continue;*/
							    triopsVersion=TRIOPS_VERSION_UNKNOWN;
							}
				}

				// optimization for the case when there's no need to obtain 
				// multiple hashes on the fly from a hashed password file:
				// obtain just the needed one:
				if (!bEncrypt &&			// decrypting, and 
					(optind+1) == argc && 	// there's just one input file to decrypt (and it is not stdin)
					triopsVersion!=TRIOPS_VERSION_UNKNOWN	// AND triopsVersion is known
					) {
					bJustOneHashIsNeeded=TRUE;
				}

				// delay obtainPassword() to group the use of that function on process_file()
				// even if triopsVersion has already been determined
				memcpy(szPass, szPassFile, MAX_PASSWORD_LENGTH);


				output=process_file( szFile, szNewFile, szPass, bEncrypt, 
							bExplicitPassword, bOutputToTheSameFile, bDoNotStorePasswordHash,
							iUseSelectedMetadata );
				
			} else {
				fprintf (stderr, "\nFile not processed: path is too long for '%s'.\n", argv[i]);
				if (bBreakOnFirstError==TRUE) {
					output=1; // error
					break;
				} else
					continue;
			}

			if (output!=0) { 
				if (bBreakOnFirstError==FALSE) {
					// print warning, but continue processing next files:
					fprintf (stderr, "ERROR processing '%s'.\n", szFile);
					output=0; // clear output for next file to process
				} else
					break;
			}

		}
	}

	// password hash isn't needed anymore: overwrite variable as a paranoic security measure:
	EliminatePassword(szPass, MAX_PASSWORD_LENGTH);
	EliminatePassword(szPassFile, MAX_PASSWORD_LENGTH);
	// password isn't needed anymore: overwrite variable as a paranoic security measure:
	for (i=0; i<SIZE_OF_TRIOPS_VERSIONS_ENUM; i++) {
		EliminatePassword(szHashAlreadyObtained[i], MAX_PASSWORD_LENGTH);
	}

	return output;

}


int 
process_file( char *szFile, char *szNewFile, char *szPass, BOOL bEncrypt, 
	BOOL bExplicitPassword, BOOL bOutputToTheSameFile, BOOL bDoNotStorePasswordHash, 
	int iUseSelectedMetadata ) 
{

	//char		szFile 		[MAX_PATH];		// defined as parameter
	//char		szNewFile 	[MAX_PATH];		// defined as parameter 
	//char		szPass [MAX_PASSWORD_LENGTH]; // defined as parameter
	//BOOL		bEncrypt;				 	// defined as parameter
	//BOOL		bDoNotStorePasswordHash;	// defined as parameter
	//BOOL		bOutputToTheSameFile; 		// defined as parameter
	unsigned long long	nBytesSoFar;
	unsigned long long	nBytesRead;
	unsigned long long	nBytesRead2; // v9.0
	FILE *      hFile;
	FILE *      hFileOut;
	BYTE		cFileBuffer [BUFFERSIZE];  // v9.0: constant pointer renamed
	BYTE		cFileBuffer2[BUFFERSIZE];  // v9.0
	BYTE *		lpFileBuffer;              // v9.0: use intermediate pointers to speed buffer swapping
	BYTE *		lpFileBuffer2;             // v9.0
	// v9.0: make cMetadata[] size as big as the bigger metadata 
	// from all encryption methods.
	BYTE		cMetadata   [HASHSIZE_v3+IVSIZE_v3]; // v9.0	
	int 		i;
	int 		iError;					// to store FSEEK or other function results
	unsigned long long	lFileSize=0;	// show progress bar
	BOOL		bStdinInput=FALSE;		// v9.0
	BOOL		bStdoutOutput=FALSE;	// v9.0
	BOOL		bProgressBar;			// show progress bar
	float		fBlockSize;				// show progress bar
#ifndef WINDOWS_PLATFORM
	struct utimbuf stTimes;
#else
	FILETIME	lLastWriteTime;
#endif
	// v9.0: use head or tail metadata: bUsingHeadMetadata
	BOOL bUsingHeadMetadata=FALSE;
	triops_Versions_Constants triopsVersionOriginal;
	BOOL bContinueLoop;
	BYTE		lpEncrypted [BUFFERSIZE];
	unsigned long long	lBlockTotal;		// counts total number of <=BUFFERSIZE blocks in hFileOut
	unsigned long long	lBlockNumber;		// counts number of <=BUFFERSIZE blocks processed in hFileOut
	unsigned long long	lSubtrahend;		// bytes to delete from last file block, as they're tail, not data.	
	unsigned long long  lMetadataSize;		// size of the Metadata (head or tail) added to encrypted files
	// CHACHA20 + KECCAK-512
	union unionIV_v3 iv_v3;					// IV for v3 format (CHACHA20+KECCAK-512)
	union KEY_v3		uniqueKey_v3;		// KEY for v3 format (CHACHA20+KECCAK-512)
	union HASHEDKEY_v3	hashedKey_v3, key_v3;//HASH for v3 format (CHACHA20+KECCAK-512)
	ECRYPT_ctx  chacha_ctx;					// CHACHA20


#ifdef ANDROID_LIBRARY
	if (szFile[0] != '/') { // security measure
		fprintf (stderr, "\nPath to file not valid: '%s'.\n\n", szFile);
		return 2;
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
		if (strlen(szFile)==0) { // v9.0
			// input is stdin
			bStdinInput=TRUE;
			SET_BINARY_MODE(STDIN); // sets binary mode for stdin in Windows
			hFile = stdin;
		} else {
			hFile = fopen(szFile, "rb" );
		}
	}

	if (hFile == NULL)
	{
		if (!bStdinInput) { // v9.0
			fprintf (stderr, "\nError opening '%s'.\n\n", szFile);
		} else {
			fprintf (stderr, "\nError opening stdin.\n\n");
		}
		return 1;
	}

	// v9.0:
	if (strlen(szNewFile)==0) {
		bStdoutOutput=TRUE;
	}

	// encrypting:
	// Add encrypted file extension to file's name if we're written to another file.
	// If we're written to the same file, this process is made at the end.
	if (bEncrypt && !bOutputToTheSameFile) {
		if (!bStdoutOutput) {
			szNewFile[strlen(szNewFile)+strlen(TRIOPS_GENERIC_EXTENSION)]=0x0; // the end of string after the extension addition
			/*if (triopsVersion==TRIOPS_V3)
				memcpy(szNewFile+strlen(szNewFile), TRIOPS_V3_EXTENSION, 4);*/
			memcpy(szNewFile+strlen(szNewFile), TRIOPS_GENERIC_EXTENSION, strlen(TRIOPS_GENERIC_EXTENSION));

		}
	}

	// encrypting/decrypting to a new file:
	// check that destination file does not exist yet (do not overwrite in that case):
	if (!bOutputToTheSameFile) {
		if (!bStdoutOutput) {
			hFileOut = fopen(szNewFile, "rb" );
			if (hFileOut != NULL)
			{
				fprintf (stderr, "\nError: Destination file already exists: '%s'\n"
					"\tProcess aborted (nothing has been done).\n\n", szNewFile);
				fclose(hFileOut);
				return 1;
			}
			// once checked that destination file doesn't exist, open said destination file:
			// moved AFTER password has been checked, not to create a superfluous empty file.
			/*hFileOut = fopen(szNewFile, "wb" );
			if (hFileOut == NULL)
			{
				fprintf (stderr, "\nError opening %s\n\n", szNewFile);
				return 1;
			}*/
		}
	}
	else 
	{
		// encrypting/decrypting to the "same" file: 
		// check that destination file does not exist yet (do not overwrite in that case):
		char szDestinationFile [MAX_PATH];
		strcpy(szDestinationFile, szFile);
		if (!bEncrypt) { 
			// !bEncrypt && bOutputToTheSameFile
			// well, here, the subtraction should depend on original file extension:
			// nonetheless, as all extensions used by now have the same length (3+1=4), I
			// use -strlen(TRIOPS_GENERIC_EXTENSION) here:
			szDestinationFile[strlen(szDestinationFile)-strlen(TRIOPS_GENERIC_EXTENSION)]=0x0;
		} else {
			//  bEncrypt && bOutputToTheSameFile
			szDestinationFile[strlen(szDestinationFile)+strlen(TRIOPS_GENERIC_EXTENSION)]=0x0;
			/*if (triopsVersion==TRIOPS_V3)
				memcpy(szDestinationFile+strlen(szDestinationFile), TRIOPS_V3_EXTENSION, 4);*/
			memcpy(szDestinationFile+strlen(szDestinationFile), TRIOPS_GENERIC_EXTENSION, strlen(TRIOPS_GENERIC_EXTENSION));
		}
		// check that destination file does not exist yet (do not overwrite in that case):
		hFileOut = fopen(szDestinationFile, "rb" );
		if (hFileOut != NULL)
		{
			fprintf (stderr,  "\nError: Destination file exists: '%s'\n"
				"\tProcess aborted (nothing has been done).\n\n", szDestinationFile );
			fclose(hFileOut);
			return 1;
		}
	}
	// this is not needed because a hFileOut!=NULL would have trigger a fclose && return
	//fclose(hFileOut);

	// Load the IV and Hash from file 
	// using bUsingHeadMetadata to point to the right location of both:
	// This is needed from v9.0 on, as tail or head can be used to store metadata,
	// and will be the checking of the password hash hint the only way to determine
	// which of them were used to store the metadata.
	triopsVersionOriginal=triopsVersion;
	if (triopsVersion==TRIOPS_VERSION_UNKNOWN) {
		// tentatively check versions
		triopsVersion=TRIOPS_V3;
	}
	if (!bEncrypt) {

		// first check Head just to be able to use stdin as input
		bContinueLoop=TRUE;
		bUsingHeadMetadata=TRUE;

		do {
			// Load the IV and Hash from file 
			if (bStdinInput) {
				unsigned long long nBytesRead;
				unsigned long long nActualMetadataSize;
				// input is stdin, so file type must be tentatively guessed 
				// from smaller to bigger metadata sizes whilst not moving fseek too far away...
				if (triopsVersion==TRIOPS_V3) {
					nActualMetadataSize = HASHSIZE_v3 + IVSIZE_v3;
					nBytesRead = fread (cMetadata, 1, nActualMetadataSize, hFile);
				}
				// error checking:
				// we're not going to raise error, as this cases can occur with small files
				// when checking first for bUsingHeadMetadata, but metadata in in tail...
				/*if (nBytesRead < nActualMetadataSize) {
					fprintf(stderr, "Error while processing encrypted stdin: input size too small.\n"
						"Process aborted.\n");
					return EXIT_FAILURE;
				}*/
				// now, point IV and hashedKey to each proper data
				if (triopsVersion==TRIOPS_V3) {
					memcpy(iv_v3.byteIV,((union unionIV_v3 *)cMetadata)->byteIV,IVSIZE_v3);
					memcpy(hashedKey_v3.keyB,((union HASHEDKEY_v3 *)(cMetadata+IVSIZE_v3))->keyB,HASHSIZE_v3);
				}
			} else { // if (bStdinInput)
				if (triopsVersion==TRIOPS_V3) 
					LoadIVandHash_v3 (hFile, iv_v3.byteIV, hashedKey_v3.keyB, szFile, bUsingHeadMetadata);
			}

			// calculate hash password with actual triopsVersion,
			if (!bHashAlreadyObtained[triopsVersion]) {
				if ( 
					!obtainPassword(szPass, szHashAlreadyObtained[triopsVersion], bExplicitPassword)
					) {
					fprintf(stderr, "ERROR: Could not obtain password.\nProcess aborted.\n\n");
					// close input file:
					fclose(hFile);
					// and say goodbye :-(
					return 1;
				}
			}
	

			// check if password is valid for the head|tail read
			if (triopsVersion==TRIOPS_V3)
			  // IN: szPass, lpIV, lpHashedKey (read from file); OUT: lpKey (for decrypting)
			  iError=CheckKeyIsValid_v3 ( szHashAlreadyObtained[triopsVersion], 
		    			key_v3.keyB, iv_v3.byteIV, hashedKey_v3.keyW, FALSE );

			
			// if check is ok, continue; if not, read the other Metadata location and end here again:
			if (iError == CheckKeyIsValid_FALSE) {
				if (!bStdinInput) {
					if (triopsVersionOriginal==TRIOPS_VERSION_UNKNOWN) {
						if (triopsVersion==TRIOPS_V3) {
							bUsingHeadMetadata=!bUsingHeadMetadata;
							if (bUsingHeadMetadata==TRUE)
								// TRIOPS_V3 is the last version type to check and head and tail were already checked:
								bContinueLoop=FALSE; 
						} 
					} else {
						bUsingHeadMetadata=!bUsingHeadMetadata;
						if (bUsingHeadMetadata==TRUE)
							bContinueLoop=FALSE;
					}
				} else {
					// bStdinInput: 
					// note that only bUsingHeadMetadata==TRUE is possible with bStdinInput
					if (triopsVersion==TRIOPS_V3)
							// TRIOPS_V3 is the last version type to check
							bContinueLoop=FALSE; 
				}
			}
			if (iError == CheckKeyIsValid_TRUE_BUT_EMPTY ||
				iError == CheckKeyIsValid_TRUE)
					break; // bUsingHeadMetadata value MUST be conserved!
		} while (bContinueLoop);

		switch (iError) {
			case CheckKeyIsValid_FALSE:
				if (!bStdinInput)
					fprintf (stderr, "\nerror: file '%s' didn't pass password hint checking.\n\n", szFile);
				else 
					fprintf (stderr, "\nerror: stdin input didn't pass password hint checking\n"
						"or input is not suitable for decrypting from stdin.\n");
				// close input file:
				fclose(hFile);
				return 1;
			case CheckKeyIsValid_TRUE_BUT_EMPTY:
				if (!bStdinInput)
					fprintf (stderr, "\nwarning: file '%s' decrypted without password hint checking.\n", szFile);
				else
					fprintf (stderr, "\nwarning: decrypting stdin input without password hint checking.\n");
				// correct, continue
				//break; // NO!: check first also next case for bStdinInput, triopsVersion==TRIOPS_V2
			case CheckKeyIsValid_TRUE:
				if (bStdinInput) {
					// reestablish correct value with stdin: *must* be Head metadata always... (if encrypting)
					bUsingHeadMetadata=TRUE;
				}
				break;
		}

	} else { // if (!bEncrypt) {

		// calculate hash password with actual triopsVersion,
		if (!bHashAlreadyObtained[triopsVersion]) {
			if ( 
				!obtainPassword(szPass, szHashAlreadyObtained[triopsVersion], bExplicitPassword)
				) {
				fprintf(stderr, "ERROR: Could not obtain password.\nProcess aborted.\n\n");
				// close input file:
				fclose(hFile);
				// and say goodbye :-(
				return 1;
			}
		}

		// if encrypting, then password hash and IV must be created:
		// CheckKeyIsValid returns in hashedKey.keyW the hash, if TRUE is passed as last argument:
		if (triopsVersion==TRIOPS_V3) {
			createIV_v3 (&iv_v3.iv, szFile);
			/* DEBUG: check value:*/
			/*fprintf (stderr, "IV: ");
			for (i=0; i<2; i++) fprintf (stderr, " %08lx",((DWORD *)&iv_v3.iv)[i]);*/
			// IN: szPass, lpIV; OUT: lpKey (for encrypting), lpHashedKey (for writing to file)
			CheckKeyIsValid_v3 ( szHashAlreadyObtained[triopsVersion], 
							key_v3.keyB, iv_v3.byteIV, hashedKey_v3.keyW, TRUE );
		}

		// in v9.0 metadata is in head by default
		bUsingHeadMetadata=TRUE;
		if (iUseSelectedMetadata != 0) {
			if (iUseSelectedMetadata==2) {
				bUsingHeadMetadata=FALSE;
			}
		}

	} // if (!bEncrypt)



	// AFTER password has been checked, (not to create a superfluous empty file), and 
	// once checked that destination file doesn't exist (upper code), open said destination file:
	if (!bOutputToTheSameFile) {
		if (!bStdoutOutput) {
			hFileOut = fopen(szNewFile, "wb" );
		} else {
			SET_BINARY_MODE(STDOUT); // sets binary mode for stdout in Windows
			hFileOut = stdout;
		}
		if (hFileOut == NULL)
		{
			fprintf (stderr, "\nError opening '%s'.\n\n", szNewFile);
			return 1;
		}
	}


	// use the IV to create a unique key for this file
	if (triopsVersion==TRIOPS_V3) {
		CreateUniqueKey_v3 (uniqueKey_v3.keyW, key_v3.keyB, &(iv_v3.iv));
		// it is not necessary to make a copy of the original IV, as CHACHA20 uses it as const *
		// memcpy(chacha20_iv, iv_v3.byteIV, IVSIZE_v3);
		/*fprintf (stderr, "\ncalculated key: ");
		for (i=0; i<KEYSIZE_v3/4; i++) fprintf (stderr, " %08lx",uniqueKey_v3.keyW[i]);*/
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
	i           = 0; // it'll be used as block counter, to show the progress bar.
	bProgressBar=FALSE;
	// show progress bar only if !bStdinInput: with stdin it's best to remain quiet
	if (!bStdinInput) {
		lFileSize   = (unsigned long long)FileSize(szFile);
		// progress bar initialization
		if (lFileSize > 1048576L) {
			bProgressBar=TRUE;
			fBlockSize=(float)lFileSize/50.0;
			fprintf (stderr, "\n----+----+----+----+---1/2---+----+----+----+----+ %.0f MiB\n",
				((float)lFileSize)/1048576.0f);
		} 
	}

	// do a cycle reading BUFFERSIZE blocks until all of them have been read:
	lBlockNumber= 0;
	lSubtrahend = 0;
	lMetadataSize=0;

	// calculate the size of the Metadata (head or tail) added to encrypted files
	if ( triopsVersion==TRIOPS_V3 )
		lMetadataSize = ( HASHSIZE_v3 + IVSIZE_v3 );

	// position file pointer for first read 
	nBytesSoFar = ZERO_LL;
	iError = 0;
	if (bUsingHeadMetadata) {
		if (!bEncrypt) {
			nBytesSoFar = lMetadataSize;
		} 
		// else, metadata must be written, but only after first BUFFERSIZE block has been read!!!
	} else {
		if (!bEncrypt)
			iError = set_file_position(hFile, nBytesSoFar, SEEK_SET);
	}
	if (iError != 0) {
		fprintf (stderr, "No file was modified.\n");
		return EXIT_FAILURE;
	}

	if (!bStdinInput) {
		if (bEncrypt) {
			lBlockTotal = lFileSize/(unsigned long long)BUFFERSIZE; // this truncates result so:
			if ( lFileSize % (unsigned long long)BUFFERSIZE != 0 )
				lBlockTotal++;
				// and there'll be and EOF while reading the file
		} else {
			lBlockTotal = (lFileSize-lMetadataSize)/(unsigned long long)BUFFERSIZE; // this truncates result so:
			if ( (lFileSize-lMetadataSize) % (unsigned long long)BUFFERSIZE != 0 )
				lBlockTotal++;
				// and there'll be and EOF while reading the file
		}
	} else {
		// start reading one block + one buffer block, and will see when stdin finishes...
		lBlockTotal=1;
	}

	if (!bEncrypt && !bUsingHeadMetadata) {
		// size of data to discard from last data read: lSubtrahend

		unsigned long long lRest = (
			( (unsigned long long)BUFFERSIZE - 
				( (lFileSize-lMetadataSize) % (unsigned long long)BUFFERSIZE ) )
			% BUFFERSIZE ); // lRest must be in Mod BUFFERSIZE arithmetic !
		lSubtrahend = lMetadataSize;

		if ( lRest < lMetadataSize ) {
			lSubtrahend = lRest;
			// and there'd be and EOF while reading the file, but as 
			// there's a tail that exceeds last data block, in reality there'll be no EOF
		}
	}


	// initialize buffers
	lpFileBuffer = cFileBuffer;
	lpFileBuffer2= cFileBuffer2;

	// .................................................
	// encrypt/decrypt the file
	if (lBlockTotal!=0) 
	do
	{
		lBlockNumber++;

		// fill the buffer with file contents:
		if (lBlockNumber==1) {
			if (bOutputToTheSameFile &&
				set_file_position(hFile, nBytesSoFar, SEEK_SET)!=0) {
				return EXIT_FAILURE;
			}
			nBytesRead = read_data_from_file(
				lpFileBuffer, BUFFERSIZE, 1, hFile,
				bEncrypt, bUsingHeadMetadata, bOutputToTheSameFile, lFileSize,
				lMetadataSize, lBlockNumber, lBlockTotal, lSubtrahend
				);
			// if encrypting and bUsingHeadMetadata, 
			// IV + password hash must be stored now:
			if (bEncrypt && bUsingHeadMetadata) {

				if (bOutputToTheSameFile &&
					set_file_position(hFile, ZERO_LL, SEEK_SET)!=0) {
					return EXIT_FAILURE;
				}				

				// write now head metadata
				if (triopsVersion==TRIOPS_V3)
					writeMetadata ( (bOutputToTheSameFile)?hFile:hFileOut, 
						bDoNotStorePasswordHash, &iv_v3, IVSIZE_v3, &hashedKey_v3, HASHSIZE_v3 );
				
				// set the read pointer at its proper place again:
				if (bOutputToTheSameFile &&
					nBytesRead > lMetadataSize &&
					set_file_position(hFile, nBytesRead, SEEK_SET)!=0) {
					return EXIT_FAILURE;
				}				
			
			}		

		} else {
			BYTE *lpFileBufferBackup;
			nBytesRead = nBytesRead2;
			//lpFileBuffer = memcpy(lpFileBuffer, lpFileBuffer2, BUFFERSIZE);
			// quick swap:
			lpFileBufferBackup = lpFileBuffer;
			lpFileBuffer       = lpFileBuffer2;
			lpFileBuffer2      = lpFileBufferBackup;
			// this is needed, because with open in update mode ('+'):
			// "output cannot be directly followed by input without
			// an intervening fseek or rewind ...
			// input cannot be directly followed by output without an intervening
			// fseek, rewind, or an input that encounters  end-of-file."
			// Note that this FSEEK revert the last writing positioning - this is compulsory!
			if (bOutputToTheSameFile &&
				set_file_position(hFile, nBytesSoFar + nBytesRead, SEEK_SET)!=0) {
				return EXIT_FAILURE;
			}
		}

		// v9.0:
		// next block is read in advance, because if 
		// bEncrypt && bUsingHeadMetadata, second block 
		// is overwritten before it could've been read.
		//
		// Note also that in v9.0 
		// this block of code must not be entered if the maximum number of blocks have already been read: 
		//  	(lBlockNumber+1<=lBlockTotal && !bStdinInput)
		// This is because with tail metadata (!bStdinInput), there must be no data read after the last block or lSubtrahend 
		// will not fix the bytes read in excess, as it is not calculated in read_data_from_file for lBlockNumber>lBlockTotal, 
		// (even though this could be implemented). Anyhow, it is a good implementation not to read after lBlockTotal :-)
		// This prevention do not apply if bStdinInput, because size of input is not known in advance (and no tail input will be processed
		// if bStdinInput, because this possibility is discarded as unfeasible from the very start).
		//
		if ( nBytesRead==BUFFERSIZE && !feof(hFile) &&
			 ((lBlockNumber+1<=lBlockTotal && !bStdinInput) || bStdinInput )
			 ) {
			nBytesRead2 = read_data_from_file(
				lpFileBuffer2, BUFFERSIZE, 1, hFile,
				bEncrypt, bUsingHeadMetadata, bOutputToTheSameFile, lFileSize,
				lMetadataSize, lBlockNumber+1, lBlockTotal, lSubtrahend
				);

			// revert file pointer: if bEncrypt || feof(), this is important
			if (bOutputToTheSameFile &&
				set_file_position(hFile, nBytesSoFar + nBytesRead, SEEK_SET)!=0) {
				return EXIT_FAILURE;
			}

		} else {
			// this will mark an empty second buffer, so nothing rests to be read from file/stdin
			nBytesRead2=0;
		}

		// progress bar is updated only if file size >10MiB
		if (bProgressBar) {
			if ((float)nBytesSoFar/fBlockSize > (float)i) {
				i++;
				fprintf (stderr, "#");
				fflush(stdout); // flash stdout!
			}
		}

		if ( nBytesRead || feof(hFile) )
		{
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
				//memcpy(lpFileBuffer, lpEncrypted, nBytesRead);
			}
			// Set the file pointer for the write.
			// This positioning will be reversed at the beginning of this cycle
			// using nBytesRead.
			iError=0;
			if (!bUsingHeadMetadata) {
				// TAIL
				if (bOutputToTheSameFile) {
					iError = set_file_position(hFile, nBytesSoFar, SEEK_SET);
				}
			} else {
				// HEAD
				if (bOutputToTheSameFile) {
					if (bEncrypt) {
						iError = set_file_position(hFile, nBytesSoFar+lMetadataSize, SEEK_SET);
					} else {
						iError = set_file_position(hFile, nBytesSoFar-lMetadataSize, SEEK_SET);
					}
				}
			}
			if (iError!=0) {
				return EXIT_FAILURE;
			}
			// write the buffer
			if (bOutputToTheSameFile) {
				fwrite(lpEncrypted, nBytesRead, 1, hFile );
			} else {
				fwrite(lpEncrypted, nBytesRead, 1, hFileOut );
			}
			// increment byte count
			nBytesSoFar += nBytesRead;
			// v9.0: if using stdin input, increment lBlockNumber dynamically
			if ( bStdinInput && 
				(!feof(hFile) || 
					// in case second buffer is not empty, there rests still another loop
					// even if feof() was reached (in fact it was reached while reading lpFileBuffer2)
					// (Note that first condition !feof(hFile) is compulsory, 'cause stdin can
					// be smaller (or equal) than just one BUFFERSIZE.)
					nBytesRead2!=0) 
				) {
				lBlockTotal++;
			}
		}
	} while (lBlockNumber<lBlockTotal);
	// .................................................

	// if encrypting, IV + password hash must be stored:
	if (bEncrypt && 
			( !bUsingHeadMetadata 
			|| lBlockTotal==0 )
		) {

		if (triopsVersion==TRIOPS_V3)
			writeMetadata ( (bOutputToTheSameFile)?hFile:hFileOut, 
				bDoNotStorePasswordHash, &iv_v3, IVSIZE_v3, &hashedKey_v3, HASHSIZE_v3 );

	}

	// close the origin file 
	// (it's also the destination file if bOutputToTheSameFile)
	fclose(hFile);

	// size must be reduced: either (part of) a tail (!bUsingHeadMetadata) or 
	// encrypted data (bUsingHeadMetadata) is abandoned in the cluster: but both 
	// of them can be safely considered random garbage, so no overwriting is required.
	if (!bEncrypt && bOutputToTheSameFile) {
		// file handles should be closed
		truncateFile (szFile);
	}

	// dispose (lpFileBuffer)s contents, so no relevnat data is left in memory
	EliminatePassword((char *)lpFileBuffer , BUFFERSIZE);
	EliminatePassword((char *)lpFileBuffer2, BUFFERSIZE);

	// if output is to the same file, modification timestamp is preserved
	if (bOutputToTheSameFile) {
#ifndef WINDOWS_PLATFORM
		stTimes.actime=time(NULL); // with access time, the actual date
		if ( utime(szFile, &stTimes) != 0 )	{
			fprintf (stderr, "warning: could not modify time attributes for '%s'.\n", szFile);
		}
#else
		writeTimestampWin(szFile, &lLastWriteTime);
#endif
	}

	// close the destination file 
	// (only if origin/destination is not the same file)
	if (!bOutputToTheSameFile)
		fclose(hFileOut);

	// rename the file to remove the encryption extension
	if (!bEncrypt) {
		if (bOutputToTheSameFile) {
			strcpy(szNewFile, szFile);
			szNewFile[strlen(szNewFile)-4]=0x0;
			if (rename (szFile, szNewFile) != 0) {
				fprintf (stderr, "\nwarning: couldn't rename '%s' to '%s'\n"
				"\tthough '%s' has been sucessfully decrypted!!!\n", szFile, szNewFile, szFile);
			}
		}
	}

	// Add encrypted file extension to file's name if we're written to the same file.
	// If we're written to the another file, this process has already been done.
	if (bEncrypt && bOutputToTheSameFile) {
		strcpy(szNewFile, szFile);
		szNewFile[strlen(szNewFile)+strlen(TRIOPS_GENERIC_EXTENSION)]=0x0; // the end of string after the extension addition
		/*if (triopsVersion==TRIOPS_V3)
			memcpy(szNewFile+strlen(szNewFile), TRIOPS_V3_EXTENSION, 4);*/
		memcpy(szNewFile+strlen(szNewFile), TRIOPS_GENERIC_EXTENSION, strlen(TRIOPS_GENERIC_EXTENSION));

		if (rename (szFile, szNewFile) != 0) {
			fprintf (stderr, "\nwarning: couldn't rename '%s' to '%s'\n"
			"\tthough '%s' has been sucessfully encrypted!!!\n", szFile, szNewFile, szFile);
		}
	}

	if (bProgressBar) {
		fprintf (stderr, " 100%c\n",37);
	}
	if (!bStdinInput) {
		fprintf (stderr, "\n'%s' processed\n\n", szFile);
	} else {
		fprintf (stderr, "\nstdin input processed\n\n");
	}

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

		fprintf (stderr, "\n%s v%s.  (goo.gl/lqT5eP) (wp.me/p2FmmK-7Q)\n"
			"\nEncrypt and decrypt files with secure password checking and\n"
			"data overwriting, using CHACHA20 and KECCAK-512 algorithms.\n"
			"\n$ %s {-kpP} [-oOiedHbh] <file> ...\n\n"
			"\t<file> ... : one or more files to encrypt/decrypt\n"
			"\t\tIf no file is indicated, stdin is used.\n"
			"\t-k : read passphrase from keyboard\n"
			"\t-p <password> : password is indicated in cmdline\n"
			"\t\t(beware of shell history!)\n"
			"\t-P <password_file> : use hashed <password_file> as password\n"
			"\t-o <output_file>: do not overwrite, but write to <output_file>\n"
			"\t-O : write output to stdout.\n"
			"\t\t-o or -O options aren't possible with multiple input files.\n"
			"\t-i <file> : input file (do not indicate more files at the end)\n"
			"\t-e <type>: encrypt. "
			"\n\t\tActually only '-e 3' is allowed\n"
			"\t\tFile extension will be '%s' ('%s' for triops < v9.0)\n"
			"\t\tOther algorithms could be available in the future.\n"
			"\t-d : decrypt. This is the default action.\n"
			"\t-H : do not store password hint when encrypting\n"
			"\t\tNote that this way, an incorrect decryption password\n"
			"\t\twith data overwrting, will render the file unusable.\n"
			"\t-b : break actions on first error encountered\n"
			"\t-h : print this help\n\n"
				,PROGRAM_NAME, TRIOPS_VERSION, PROGRAM_NAME
				, TRIOPS_GENERIC_EXTENSION, TRIOPS_V3_EXTENSION
			);
		return;
}


// set file position: wrapper of FSEEK
int set_file_position (FILE * hFile, unsigned long long offset, int whence) {

	if (FSEEK(hFile, offset, whence)!=0) {
		fprintf (stderr, "\nerror: couldn't move correctly inside file\n"
				"\tProcess aborted.\n");
		return 1;
	}

	return 0;

}


// Read data from file and return a correct nBytesRead value
// v9.0
unsigned long long read_data_from_file(
	BYTE *lpFileBuffer, int iBufferSize, int iBlocks, FILE *hFile,
	BOOL bEncrypt, BOOL bUsingHeadMetadata, BOOL bOutputToTheSameFile,
	unsigned long long lFileSize, unsigned long long lMetadataSize, 
	unsigned long long lBlockNumber, unsigned long long lBlockTotal, 
	unsigned long long lSubtrahend
	) {
	unsigned long long	nBytesRead = ZERO_LL;

	if (lFileSize!=ZERO_LL) {
		nBytesRead = fread(lpFileBuffer, iBufferSize, iBlocks, hFile);
	} else {
		// v9.0: stdin must be read one by one char ...
		int iBytesRead;
		do {
			if (iBytesRead=fread(lpFileBuffer+nBytesRead, 1, iBufferSize, hFile))
				nBytesRead+=iBytesRead;
		} while ( iBytesRead>0 && nBytesRead<(iBufferSize*iBlocks) && !feof(hFile) );
	}
	if ( lFileSize!=ZERO_LL &&
		(nBytesRead || feof(hFile)) ) {
		if (feof(hFile)) {
			if (!bEncrypt && bUsingHeadMetadata) {
				nBytesRead = (lFileSize-lMetadataSize) % (unsigned long long)iBufferSize;
			} else {
				nBytesRead = lFileSize % (unsigned long long)iBufferSize;
			}
		} else {
			// real nBytesRead, because nBytesRead is now just '1'
			nBytesRead = nBytesRead * (unsigned long long)iBufferSize;
		}
	}
	// when decrypting, take care
	// to remove the triops tail (if !bUsingHeadMetadata), or :
	// TRIOPS_V3: Output File Size will be greater than original data file.
	// Note that it is not possible bStdinInput && !bUsingHeadMetadata as it has
	// been banned as unfeasible from the very beginning.
	// NOTE: with tail metadata (!bStdinInput) there must be no data read after the last block or lSubtrahend 
	//     will not fix the bytes read in excess, as it is not calculated in read_data_from_file for lBlockNumber>lBlockTotal, 
	//     (even though this could be implemented). Anyhow, it is a good implementation not to read after lBlockTotal :-)
	//     In fact, the implementation would be: if (lBlockNumber>lBlockTotal) nBytesRead=0;
	//     because the only possible case would be a tail exceeding an entire BUFFERSIZE block, read in the advance buffer 
	//     lpFileBuffer2, so this advance read will return in fact 0 bytes, which is equivalent to the actual behaviour
	//     in which the advance read do not occur at all.
	if (!bEncrypt && 
		!bUsingHeadMetadata &&
		lBlockNumber==lBlockTotal)
		nBytesRead -= lSubtrahend;

	return nBytesRead;
}


// write Metadata (IV and hint Hash) to hFile
// v9.0
int writeMetadata (FILE *hFileMetadata, 
                   BOOL bDoNotStorePasswordHash,
                   void *IV, int IV_SIZE, 
                   void *HASH, int HASH_SIZE) {

	int  i;
	BYTE matrix[HASH_SIZE];	 	// temporary hash store


	// IV:
	if (triopsVersion==TRIOPS_V3)
		fwrite( ((union unionIV_v3 *)IV)->byteIV, IV_SIZE, 1, hFileMetadata );
	// ~ password hash:
	if (!bDoNotStorePasswordHash) {
		if (triopsVersion==TRIOPS_V3)
			memcpy(matrix, ((union HASHEDKEY_v3 *)HASH)->keyB, HASH_SIZE);
	/*fprintf (stderr, "calculated tail: ");
	for (i=0; i<HASH_SIZE/4; i++) fprintf (stderr, " %08lx",(union *HASHEDKEY_v3)HASH->keyW[i]);*/
	} else {
		// the space destined to the hash is filled with all zeros value:
		for (i=0; i < HASH_SIZE; i++) { matrix[i]=0x0; }
	}

	fwrite(matrix, HASH_SIZE, 1, hFileMetadata );

	return 0;

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
	fprintf (stderr, "Error while reading file. Nothing changed.\n");
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
		fprintf (stderr, "File '%s' is too small to contain encrypted information.\nProcess aborted.\n", szFile);
		exit (-3);
	}

#ifndef WINDOWS_PLATFORM
    {
        if (truncate(szFile, FileSize(szFile) - bytesToTruncate )) {
            fprintf (stderr, "Error while modifying file. Hope nothing changed, but can't assure that.\n");
            exit (-3);
        }
    }
	//
#else
    {
        int iFile;
		if ((iFile=_open(szFile,_O_WRONLY))==0) {
            fprintf (stderr, "\nError opening %s\n", szFile);
            exit (-1);
		}
        if (_chsize_s(iFile, FileSize(szFile) - bytesToTruncate )) {
            fprintf (stderr, "Error while modifying file. Hope nothing changed, but can't assure that.\n");
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
	fprintf (stderr, "\n\nEnter password and press [enter] (no key aborts): ");
	fflush(stdout); // flash stdout
	i=0;
	while ( i<(MAX_PASSWORD_LENGTH-1) && (c = getch()) != 13 ) { // read chars until "\n"
		if (c!=8 && c!=127) {
			szPass[i]=(char)c;
			i++;
			putc('*',stderr);
		} else { // backspace char pressed: delete previous char!
			if (i>0) {
				i--;
				szPass[i]=0x0;
				// put caret backwards and erase previous '*'
				putc(8,stderr); // backspace
				putc(32,stderr); // space (and so, one char forward)
				putc(8,stderr); // backspace again
			}
		}
		fflush(stderr);
	}
	szPass[i]=0x0; // important!!! to mark the end of the string
	// delusion eavesdropping password length!
	for (i = 0;  i < strlen(szPass);  i++, putc(8,stderr), putc(32,stderr), putc(8,stderr));
	fprintf (stderr, "\n\n");
	// if password length is zero length, exit: provides a clean way to abort here
	if ( i==0 ) {
		//fprintf (stderr, "Process aborted.\n\n");
		return FALSE;
	}
	// if password length reaches MAX_PASSWORD_LENGTH, input ends abruptly, warn it!
	if ( i==(MAX_PASSWORD_LENGTH-1) ) {
		fprintf (stderr, "WARNING: password exceeded max length, and it was truncated to %i chars.\n",
			MAX_PASSWORD_LENGTH);
		fprintf (stderr, "Should process continue (y/n)? : ");
		c=getch();
		if (c!=121) { 	// anything different from "y"
			fprintf (stderr, "n\n\n");
			return FALSE;
		} else {		// ok, continue
			fprintf (stderr, "y\n\n");
		}
	}

	return TRUE;

#else	// #ifndef ANDROID_LIBRARY
	return TRUE;
#endif	// #ifndef/#else ANDROID_LIBRARY
}

// modification for using binary files as passwords:
// returns in *szPass the hash calculated from the contents 
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
	sph_keccak512_context keccak_context;


	// obtain password either from keyboard (strlen(szFile)==0) 
	// or from the passed string szFile directly (bExplicitPassword==TRUE)
	if (bExplicitPassword==TRUE) {
		// obtain password from the passed string szFile directly
		strcpy(szPass, szFile);

		// and now, directly calculate hash here:
		if (triopsVersion == TRIOPS_V3) {
			if (!bHashAlreadyObtained[triopsVersion])
				crypto_hash( (unsigned char *)szHashAlreadyObtained[triopsVersion], 
					(unsigned char *)szPass, strlen(szPass) );
			memcpy(szPass, szHashAlreadyObtained[triopsVersion], HASHSIZE_v3);
			/* DEBUG: check value:
			fprintf (stderr, "calculated hash from password: ");
			for (i=0; i<16; i++) fprintf (stderr, " %08lx",((LPDWORD)szPass)[i]);
			*/
		}


	} else {
	// ! (bExplicitPassword==TRUE)
	// obtain password from the file path passed in szFile

	  // If the hash for all methods has already been obtained, 
	  // it is already available in the szHashAlreadyObtained array:
	  // there's no need to parse the password file again in that case.
	  if (!bHashAlreadyObtained[TRIOPS_V3])
	  	{
		hFile = fopen(szFile, "rb" );
		if (hFile == NULL) {
			fprintf (stderr, "\nError opening '%s'\n", szFile);
			return FALSE;
		}

		lFileSize=(unsigned long long)FileSize(szFile);
		if (lFileSize == 0)	{
			fclose (hFile);
			fprintf (stderr, "\nError: file '%s' is empty!\n", szFile);
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

		// optimization for the case when there's no need to obtain 
		// multiple hashes on the fly from a hashed password file:
		// obtain just the needed one:
		if (bJustOneHashIsNeeded) {
			// fill bHashAlreadyObtained[] with fool values as only 
			// the actual 'triopsVersion' hash value will be needed and used:
			if (triopsVersion!=TRIOPS_V3)
				bHashAlreadyObtained[TRIOPS_V3]=TRUE;
		}

		if (!bHashAlreadyObtained[TRIOPS_V3]) {
			sph_keccak512_init(&keccak_context);
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
				// Now obtain *all* hashes available for all encrypted file types:
				// for now, only available hash is for only available encryption type '3':			
				if (!bHashAlreadyObtained[TRIOPS_V3]) {
					sph_keccak512(&keccak_context, lpFileBuffer, (size_t)nBytesRead);
				}

			}
		} while (lBlockNumber<lBlockTotal);

		fclose (hFile);

	  }

		if (!bHashAlreadyObtained[TRIOPS_V3]) {
			sph_keccak512_close(&keccak_context,szHashAlreadyObtained[TRIOPS_V3]);
			/* DEBUG: check value:
			fprintf (stderr, "calculated hash from file: ");
			for (i=0; i<16; i++) fprintf (stderr, " %08lx",((LPDWORD)szHashAlreadyObtained[TRIOPS_V3])[i]);
			*/
			bHashAlreadyObtained[TRIOPS_V3]=TRUE;
		}
		if (triopsVersion==TRIOPS_V3) {
			memcpy(szPass, szHashAlreadyObtained[TRIOPS_V3], HASHSIZE_v3);
		}


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
		//fprintf (stderr, "warning: error while reading file '%s' time attributes. (using actual time).\n",
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
		;	/*fprintf (stderr, "warning: could not open attributtes for file '%s' (error: %d)\n",
			szFile, GetLastError());*/
	} else {
		if ( GetFileTime(
				hFile,	// identifies the file
				(LPFILETIME)NULL,	// address of creation time
				(LPFILETIME)NULL,	// address of last access time
				lpLastWriteTime 	// address of last write time
				)==0 )
			fprintf (stderr, "warning: could not read file date for '%s'\n", szFile);
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
		fprintf (stderr, "warning: can't write attributtes for file '%s' (error: %d)\n",
			szFile, (int)GetLastError());
	} else {
		if ( SetFileTime(
				hFile,	// identifies the file
				(LPFILETIME)NULL,	// address of creation time
				(LPFILETIME)NULL,	// address of last access time
				lpLastWriteTime 	// address of last write time
				)==0 )
			fprintf (stderr, "warning: could not change file date for '%s'\n", szFile);
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




BOOL
LoadIVandHash_v3 (FILE *hFile, LPBYTE ivAsBytes, LPBYTE hashedKey, char *szFile, BOOL bUsingHeadMetadata)
{
	DWORD	nBytesRead;

	// v9.0: be sure not to return 0x0 in hashedKey (in that case hash is ignored and decryption proceeds!)
	int i;
	for (i=0; i<HASHSIZE_v3; i++) 
		hashedKey[i]=0xff;

	// this check is needed because the file to truncate can be smaller !
	if ( FileSize(szFile) < (unsigned long long)(IVSIZE_v3+HASHSIZE_v3) ) {
		//fprintf (stderr, "File '%s' is too small to contain encrypted information.\nProcess aborted.", szFile);
		return FALSE; // v9.0: do not print error as this could be valid: see process_file()
	}

	// set the pointer to the beginning of the iv
	// v9.0: use bUsingHeadMetadata for FSEEK positioning
	if (!bUsingHeadMetadata) {
		if (set_file_position(hFile, ZERO_LL-(IVSIZE_v3+HASHSIZE_v3), SEEK_END)!=0)
			return FALSE;
	} else {
		// this is needed in case triopsVersion==TRIOPS_VERSION_UNKNOWN
		// (this can be done because with bStdinInput, LoadIVandHash_v3 is not called)
		if (set_file_position(hFile, ZERO_LL, SEEK_SET)!=0)
			return FALSE;		
	}

	// read the iv
	nBytesRead = fread(ivAsBytes, IVSIZE_v3, 1, hFile);
	
	// read the hashed Key
	nBytesRead = fread(hashedKey, HASHSIZE_v3, 1, hFile);

	/* DEBUG: check value: 
	{
	int i;
	fprintf (stderr, "\nstored: ");
	for (i=0; i<4; i++) fprintf (stderr, " %08lx",((int *)hashedKey)[i]);
	}
	*/


	// reset file pointer to the beginning of the file
	//set_file_position(hFile, ZERO_LL, SEEK_SET); // this will be done, if necessary, later on caller.

	return TRUE;

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

	// calculate the theoretical hashedKey from the IV and passed password:
/*
	crypto_hash(testKey.keyB, (unsigned char *)szPass, strlen(szPass));
*/

	/* DEBUG: KECCAK-512:*/
	/*fprintf (stderr, "KECCAK-512: ");
	for (i=0; i<16; i++) fprintf (stderr, " %08lx",testKey.keyW[i]);*/

	// copy the key
/*	
	memcpy(lpKey, testKey.keyB, HASHSIZE_v3);
*/
	memcpy(lpKey, (LPBYTE)szPass, HASHSIZE_v3);
	memcpy(testKey.keyB, (LPBYTE)szPass, HASHSIZE_v3);

	/* DEBUG: check value:
	fprintf (stderr, "calculated: ");
	for (i=0; i<16; i++) fprintf (stderr, " %08lx",testKey.keyW[i]);
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
			//fprintf (stderr, "\nInvalid passphrase\n");
			/* DEBUG: check value:
			fprintf (stderr, "calculated: ");
			for (i=0; i<16; i++) fprintf (stderr, " %08lx",testKey.keyW[i]);
			fprintf (stderr, "\nstored: ");
			for (i=0; i<16; i++) fprintf (stderr, " %08lx",lpHashedKey[i]);
			fprintf (stderr, "\niv: ");
			for (i=0; i<8; i++) fprintf (stderr, " %02lx",lpIV[i]);
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


// returns an initialization vector of 8*8=64 bits based on a KECCAK-512 hash of:
// 8 bytes: file size
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

	if (strlen(szFile)!=0) {
		int err = stat( szFile, &fileStat );
		if (0 != err) {
			fprintf (stderr, "Error while reading file. Nothing changed.\n");
			exit (-3);
		}
		lFileSize=FileSize( szFile );
		iv->fileTime=fileStat.st_atime;
	} else {
		// v9.0: stdin
		lFileSize=(unsigned long long)(rand()*rand())*(unsigned long long)(rand()*rand());
		rand();
		iv->fileTime=rand()*rand();
	}
	
	iv->rand1=rand()*rand();

	memcpy( cTempData, 		(unsigned char *)&lFileSize, 8 );
	memcpy( cTempData+8, 	(unsigned char *)&(iv->rand1), 4 );
	memcpy( cTempData+8+4, 	(unsigned char *)&(iv->fileTime), 4 );
	/*
	fprintf (stderr, "\niv: ");
	for (i=0; i<16; i++) fprintf (stderr, " %02lx",cTempData[i]);
	*/

	// ok, now let's hash iv in order to obscure IV:
	// hash from iv, in cTempHash:
	crypto_hash(cTempHash, cTempData, 8+IVSIZE_v3);

	// as KECCAK-512 produces 512 bits, let's get just some bytes:
	for (i=0; i < 8; i++) {
		((unsigned char*)iv)[i] = cTempHash[i*4];
	}
	/*
	fprintf (stderr, "\niv: ");
	for (i=0; i<2; i++) fprintf (stderr, " %02lx",((uint32_t*)iv)[i]);
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
