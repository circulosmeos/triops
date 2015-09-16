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
// Type ./triops to obtain command line help.
//
// Pure C99 code,
// by circulosmeos, May 2015. June 2015.
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



#define TRIOPS_VERSION "7.2.1"
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

BOOL bOutputToTheSameFile;

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



void	truncateFile (LPBYTE);
BOOL    obtainPassword (LPBYTE, LPBYTE);
unsigned long long FileSize(char *);
void 	EliminatePasswords (LPBYTE szPassFile, LPBYTE szPass);
#ifndef WINDOWS_PLATFORM
time_t 	obtainTimestampUnix (char *szFile, int iMarcaDeTiempo);
#else
void 	obtainTimestampWin (char *szFile, LPFILETIME lpLastWriteTime);
void 	writeTimestampWin (char *szFile, LPFILETIME lpLastWriteTime);
#endif

void	truncateFileBySize ( LPBYTE, unsigned long long );

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
	unsigned long long	nBytesSoFar;
	unsigned long long	nBytesRead, nBytesWritten;
	FILE *      hFile;
	FILE *      hFileOut;
	FILE *      hFileTail;
	char		szFile 		[MAX_PATH];
	char		szNewFile 	[MAX_PATH];
	char		szPass [MAX_PASSWORD_LENGTH];
	char		szPassFile 	[MAX_PATH];
	BYTE		lpFileBuffer[BUFFERSIZE];
	//BOOL		bOutputToTheSameFile; 		// defined as global above
	BOOL		bEncrypt;
	BOOL		bDoNotStorePasswordHash;
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

	triopsVersion=TRIOPS_V3;

	// check parameters
	// between 2 and 5 parameters:
	if ( argc < 3 || argc > 6 ) // #1 is the program name
	{
		printf ("\n%s v%s.  (goo.gl/lqT5eP) (wp.me/p2FmmK-7Q)\n"
			"\n$ %s {file with passphrase (remove '\\n' !) |"
			"\n\t\tbinary file to use as passphrase |"
			"\n\t\t_passphrase_ rounded by '_' |"
			"\n\t\t__ : read passphrase from keyboard}"
			"\n\t{file to encrypt/decrypt}"
			"\n\t{path to encrypted/decrypted file |"
			"\n\t\t'=' or empty if there's no 4th param : overwrite file}"
			"\n\t[3 (or any value): encrypt file (extension will be '.$#3') |"
			"\n\t\tempty : decrypt file]"
			"\n\t[1 (or any value): don't store password hint (be careful!)]"
			"\n\n", PROGRAM_NAME, TRIOPS_VERSION, PROGRAM_NAME);
		return 1;
	}

	//.................................................
	// (1) & 
	// (2)
	// get passphrase and filename
	/*
	lstrcpy (szPass, argv[1]);
	lstrcpy (szFile, argv[2]);
	*/
	strcpy (szPassFile, argv[1]);
	strcpy (szFile, argv[2]);
	//.................................................
	// (3)
	bOutputToTheSameFile=FALSE;
	if (argc==3)
		bOutputToTheSameFile=TRUE;
	else
		strcpy (szNewFile, argv[3]);
	if (strcmp(szNewFile, "=")==0) bOutputToTheSameFile=TRUE;
	//.................................................
	// (4)
	// encrypt or decrypt
	bEncrypt=FALSE;
	if (argc>=5) {
		bEncrypt=TRUE;
		if (strcmp(argv[4], "1")==0 ||
			strcmp(argv[4], "2")==0) {
			printf ("\n'%s' value is reserved.\nProcess aborted.\n", argv[4]);
			return 1;
		} 
	} else {
		// decrypting: so triops Version can be deduced from extension:
		if (strlen(szFile)>=4)
					if (strcmp( szFile+(strlen(szFile)-4), TRIOPS_V3_EXTENSION ) == 0 )
						triopsVersion=TRIOPS_V3;
					else {
						printf ("\nDecrypting, but format could not be deduced from file extension.\nProcess aborted.\n");
						return 1;
					}
	}
	//.................................................
	// (5)
	// do or do not store password hash
	bDoNotStorePasswordHash=FALSE;
	if (argc>=6) bDoNotStorePasswordHash=TRUE;
	//.................................................
	
	// needed by createIV_v3
	srand((unsigned) time(NULL)); 

#ifdef ANDROID_LIBRARY
	if (szFile[0] != '/') { // security measure
		printf ("\nPath to file not valid: %s.\n\n", szFile);
		return 1;
	}
#endif

	// obtain password from file:
	if (!obtainPassword (szPassFile, szPass))
	{
		printf ("\nCould not obtain password.\nAborted.\n\n");
		return 1;
	}

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
	if (bOutputToTheSameFile)
		hFile = fopen(szFile, "r+b" );
	else
		hFile = fopen(szFile, "rb" );

	if (hFile == NULL)
	{
		printf ("\nError opening %s\n\n", szFile);
		return 1;
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

	// password isn't needed anymore: overwrite variables as a paranoic security measure:
	EliminatePasswords(szPassFile, szPass);

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

	// Add encrypted file extension to file's name if we're written to another file.
	// If we're written to the same file, this process is made at the end.
	if (bEncrypt && !bOutputToTheSameFile) {
		szNewFile[strlen(szNewFile)+4]=0x0; // the end of string after the extension addition
		if (triopsVersion==TRIOPS_V3)
			memcpy(szNewFile+strlen(szNewFile), TRIOPS_V3_EXTENSION, 4);
	}

	// check that destination file does not exist yet (do not overwrite in that case):
	if (!bOutputToTheSameFile) {
		hFileOut = fopen(szNewFile, "rb" );
		if (hFileOut != NULL)
		{
			printf ("\nError: Destination file already exists: %s\n\n", szNewFile);
			fclose(hFileOut);
			return 1;
		}
		// once checked that destination file doesn't exist, open said destination file:
		hFileOut = fopen(szNewFile, "wb" );
		if (hFileOut == NULL)
		{
			printf ("\nError opening %s\n\n", szNewFile);
			return 1;
		}
	}

	// use the iv to create a unique key for this file
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
			if (fseek(hFile, nBytesSoFar, SEEK_SET)!=0) {
				printf ("\nerror: couldn't move correctly inside '%s'\n"
				"\tprocess aborted.\n", szFile);
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
				if (fseek(hFile, nBytesSoFar, SEEK_SET)!=0) {
					printf ("\nerror: couldn't move correctly inside '%s'\n"
					"\tprocess aborted.\n", szFile);
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
				for (i=0; i++; i<HASHSIZE_v3) { matrix3[i]=0x0; }
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
	printf("\ncompleted\n\n");

	// finish
	return 0;
}


// returns the size of the file in bytes
unsigned long long FileSize( char *szFile )
{
  struct stat fileStat;
  int err = stat( szFile, &fileStat );
  if (0 != err) {
	printf ("Error while reading file. Nothing changed.\n");
    exit (-3);
  }
  //return (long int) fileStat.st_size;
  return (unsigned long long) fileStat.st_size;
}

// truncates the size of the file, deleting the encrypted file's data tail 
// (or its equivalent size, which is the same).
void 
truncateFile ( LPBYTE szFile )
{
	long int bytesToTruncate;
	if (triopsVersion==TRIOPS_V3)
		bytesToTruncate=(unsigned long long)( sizeof(IV_v3) + HASHSIZE_v3 );

	truncateFileBySize ( szFile, bytesToTruncate);
}

// truncates the size of the file, deleting bytesToTruncate bytes from the encrypted file's tail 
// (or its equivalent size, which is the same).
void 
truncateFileBySize ( LPBYTE szFile, unsigned long long bytesToTruncate )
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
		if ((iFile=open(szFile,O_WRONLY))==0) {
            printf ("\nError opening %s\n", szFile);
            exit (-1);
		}
        if (chsize(iFile, filelength(iFile) - bytesToTruncate )) {
            printf ("Error while modifying file. Hope nothing changed, but can't assure that.\n");
            exit (-3);
        }
        close (iFile);
    }
    //
#endif

}

// modification for using binary files as passwords:
// returns the hash calculated from the contents 
// of the file passed as a fs path.
// if the fs path passed starts and ends with '_' char, 
// the enclosed string is the password itself.
BOOL
obtainPassword (LPBYTE szFile, LPBYTE szPass)
{
	FILE *      hFile;
	DWORD       nBytesRead;
	BYTE		lpFileBuffer [BUFFERSIZE];
	int 		i, c;
	unsigned long long 	  lFileSize;
	sph_keccak512_context mc;

	if (szFile[0]=='_' && szFile[strlen(szFile)-1]=='_') { // strlen(szFile)>0 always

#ifndef ANDROID_LIBRARY
		if (strlen(szFile)==2) {
			// in this case, the user wants to insert the password from the keyboard:
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
		} else {
			// ! (strlen(szFile)==2)
			memcpy(szPass, szFile+1, strlen(szFile)-2); // done !!!
			szPass[strlen(szFile)-2]=0x0; // important !!! to mark the end of the string
		}

#else	// #ifndef ANDROID_LIBRARY
		memcpy(szPass, szFile+1, strlen(szFile)-2); // done !!!
		szPass[strlen(szFile)-2]=0x0; // important !!! to mark the end of the string

#endif	// #ifndef/#else ANDROID_LIBRARY
		

		// and now, directly calculate hash here:
		if (triopsVersion == TRIOPS_V3) {
			crypto_hash((unsigned char *)szPass, (unsigned char *)szPass, strlen(szPass));
			/* DEBUG: check value:
			printf ("calculated hash from password: ");
			for (i=0; i<16; i++) printf(" %08lx",((LPDWORD)szPass)[i]);
			*/
		}


	} else {
	// ! (szFile[0]=='_' && szFile[strlen(szFile)-1]=='_') 

		hFile = fopen(szFile, "rb" );
		if (hFile == NULL)
		{
			fclose (hFile);
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
			nBytesRead=fread(lpFileBuffer, BUFFERSIZE, 1, hFile);
			if (nBytesRead || feof(hFile) )
			{
				if (feof(hFile)) {
					nBytesRead = lFileSize % (unsigned long long)BUFFERSIZE;
				} else {
					// real nBytesRead, because nBytesRead is now just '1'
					nBytesRead = nBytesRead * (unsigned long long)BUFFERSIZE;
				}
				if (triopsVersion==TRIOPS_V3) {
					sph_keccak512(&mc, lpFileBuffer, nBytesRead);
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

	} // else ends ( if (szFile[0]=='_' && szFile[strlen(szFile)-1]=='_') )

	return TRUE;

}


// password is not needed anymore: variables are filled not to reside in memory,
// as a paranoic security measure:
void EliminatePasswords(LPBYTE szPassFile, LPBYTE szPass)
{
	int i;

	// both variables are filled: szPassFile isn't needed anymore anyway.
	for (i=0; i++; i<MAX_PATH) {
		szPassFile[i]=0xff;
	}
	for (i=0; i++; i<MAX_PASSWORD_LENGTH) {
		szPass[i]=0xff;
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
			szFile, GetLastError());
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
	fseek(hFile, 0-(IVSIZE_v3+HASHSIZE_v3), SEEK_END);

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
	fseek(hFile, 0, SEEK_SET);

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
		crypto_hash(szTemp, szTemp, HASHSIZE_v3);
	}

	memcpy((LPBYTE)(szTemp+HASHSIZE_v3), lpIV, IVSIZE_v3);

	// hash again in hashedKey:
	crypto_hash(testKey.keyB, szTemp, HASHSIZE_v3 + IVSIZE_v3);
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
	int i;

	// already done !
	//srand((unsigned) time(NULL));

	int err = stat( szFile, &fileStat );
	if (0 != err) {
		printf ("Error while reading file. Nothing changed.\n");
		exit (-3);
	}
	iv->rand1=rand()*rand(); iv->rand1=rand()*rand();
	iv->fileTime=fileStat.st_atime;

	// ok, now let's hash iv in order to obscure IV:
	// hash from iv, in cTempHash:
	crypto_hash(cTempHash, (unsigned char *)iv, IVSIZE_v3);

	// as KECCAK-512 produces 512 bits, let's get just some bytes:
	for (i=0;i++;i<8) {
		((unsigned char*)iv)[i] = cTempHash[i*4];
	}

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
