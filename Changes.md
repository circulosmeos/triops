v9.0

* cmdline pipe safe; this implies a change in file format.   
  Note that previous ".$#3" files are recognized, but new encrypted files   
  will use ".ooo" as file extension and aren't backwards compatible.   
  
v8.0

* cmdline options à la POSIX. Now multiple input files are admitted. Check ./triops -h

v7.3

* Large file support (LFS): no limit on the size of the files read/written (up to 8 EiB = 2^63 bytes, or the max filesystem file size).
* patch: files to read/write are tested after password check and before any other operation, so no empty or overwritten file is created.
* patch: (since v7.2) invalid password files resulted in abnormal program termination (nothing were overwritten, though).

v7.2.2

* patches: password was not correctly overwritten in memory after it wasn't needed. IVs weren't as random as intended. Both failures didn't compromise security of the encrypted file, AFAIK.
* code cleaning to eliminate most of the compiler warnings.

v7.2.1

* no fixes, improvements or additions: just little code compatibility changes with Android and others.

v7.2

* Binary files can be used as passwords: for example jpg images, etc. Caution: do not lose this 'password' file and do not modify it!


v7.1 (initial release):

* Code can be compiled with any C99 compiler, no matter platform, endianness or word size (32-64 bits): it has been tested on Windows, linux, Solaris, HP-UX OS's and Intel/AMD, ARM and Itanium processors.
* Same content produces different encrypted outputs every time. This is attained with a random initialization vector (IV) stored within the encrypted file.
* Files are (by default) encrypted/decrypted on-the-fly, so content is overwritten. This is interesting from a security point of view, as no clear content is left on disk.
* When decrypting, if password is not the one used for encrypting, the process is aborted, so the file cannot be rendered unusable. This behaviour is achieved thanks to a password hash stored within the encrypted file. (This hash can optionally be erased when encrypting: in this case the file could end up being decrypted with an incorrect password, so its contents could be irrecoverable.)
* Mentioned hash used to check that the password for decryption is correct is *not* the same used to encrypt (obviously!). Separate hashes are used for both purposes, though both are derived via different ways from the password, using some 500-1000 concatenated KECCAK hashes.
* File modification time is maintained. File dates are important!
* Encrypted files are appended the extension .$#3 to filename, so they can be recognized.
* Password can be obtained from keyboard, command line or from a file. Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this). Also note that there's a limit on the number of characters that will be read from the file... that'd be about two hundred chars at least (!).
* Speed is extremely high, as CHACHA20 is a very fast encryption algorithm: it is as fast as RC4.
* Reduced program size: < 100 kiB on all platforms.
* easily portable to Android as a JNI library. Check "ANDROID_LIBRARY" in the source code.
* Licensed as GPL v3.