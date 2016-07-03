triops: a simple command line tool for encryption/decryption of files.   

It uses [CHACHA20](http://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) as algorithm for encryption/decryption and [KECCAK](http://en.wikipedia.org/wiki/SHA-3)-512 as hash algorithm.   

Executables for some platforms (linux, Windows, HP-UX, Solaris and [Android](https://www.github.com/circulosmeos/triops.apk)) are available [here](https://circulosmeos.wordpress.com/2015/05/18/triops-a-multiplatform-cmdline-encryption-tool-using-chacha20-keccak).    

Last version available and compiled is v8.0. Check [list of changes between versions](Changes.md).   

There's an [Android app available here](https://www.github.com/circulosmeos/triops.apk).   

Features:   

* Code can be compiled with any C99 compiler, no matter platform, endianness or word size (32-64 bits): it has been tested on Windows, linux, Solaris and HP-UX OS's and Intel/AMD, ARM, MIPS, SPARC and Itanium processors.
* Same content produces different encrypted outputs every time. This is attained with a random initialization vector (IV) stored within the encrypted file.
* Files are (by default) encrypted/decrypted on-the-fly, so content is overwritten. This is interesting from a security point of view, as no clear content is left on disk.
* When decrypting, if password is not the one used for encrypting, the process is aborted, so the file cannot be rendered unusable. This behaviour is achieved thanks to a password hint stored within the encrypted file. (This hint can optionally be not stored: in this case the file could end up being decrypted with an incorrect password, so its contents would be irrecoverable.)
* Mentioned hint used to check that the password for decryption is correct is *not* the same used to encrypt (obviously!). Separate hashes are used for both purposes, though both are derived via different ways from the password and IV, using some 500-1000 concatenated KECCAK hashes.
* File modification time is maintained. File dates are important!
* Encrypted files are appended the extension .$#3 to filename, so they can be recognized.
* Password can be obtained from keyboard, command line or from a file. Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this). Also note that there's a limit on v7.1 on the number of characters that will be read from the file: 255 chars. This limit disappears on v7.2.
* Binary files can be used as passwords (from v7.2): for example jpg images, etc. Caution: do not lose this 'password' file and do not modify it!
* From v7.3, there's no limit on the size on files read/written (up to 8 EiB = 2^63 bytes, or the max filesystem file size).
* Speed is extremely high, as CHACHA20 is a very fast encryption algorithm: it is as fast as RC4.
* Reduced program size: < 100 kiB on all platforms.
* [easily portable to Android](https://www.github.com/circulosmeos/triops.apk) as a JNI library. Check "ANDROID_LIBRARY" in the source code.
* Licensed as GPL v3.
   
   
Before compiling, check in triops.h that next values correctly adjust to your platform, modifying them as convenient:   

>    #undef WINDOWS_PLATFORM     // Compile for Unix or for Windows: #undef o #define   

>    #define LOCAL_LITTLE_ENDIAN    // it is important to undef in order to compile on Big Endian processors   

Compilation on linux with gcc: a one-line "Makefile" file is provided:   

>    $ bash Makefile   

For other compilers or platforms, modify the gcc command line contained in the Makefile file as convenient. Remember to use "-O3" ([fast executable optimizations](https://gcc.gnu.org/onlinedocs/gcc-4.7.1/gcc/Optimize-Options.html#Optimize-Options)). 
   
   
   
Examples of use:   

>    $ ./triops.exe -h   
       
    triops v8.0.  (goo.gl/lqT5eP) (wp.me/p2FmmK-7Q)   
       
    Encrypt and decrypt files with secure password checking and   
    data overwriting, using CHACHA20 and KECCAK-512 algorithms.   
       
    $ triops {-kpP} [-oedHbh] <file> ...   
   
        <file> ... : one or more files to encrypt/decrypt   
        -k : read passphrase from keyboard   
        -p <password> : password is indicated in cmdline   
                (beware of shell history!)   
        -P <password_file> : use hashed <password_file> as password   
        -o <output_file>: do not overwrite, but write to <output_file>   
                This option is not possible with multiple input files.   
        -e <type>: encrypt.   
                Actually only '-e 3' value is allowed (file extension '.$#3').   
                Other algorithms can be available in the future.   
        -d : decrypt. This is the default action.   
                Decryption type is guessed from file extension.   
                Actually the only decryption extension available is '.$#3'   
        -H : do not store password hash hint when encrypting   
                Note that this way, an incorrect decryption password   
                with data overwrting, will render the file unusable.   
        -b : break actions on first error encountered   
        -h : print this help   
   

Example of encryption: encrypt plaintext.txt file, overwriting it, using password stored in file "password.txt". Resulting file will be renamed plaintext.txt.$#3   

>    $ ./triops.exe -P password.txt -e 3 plaintext.txt   

Example of encryption: encrypt plaintext.txt file on encryptedtext.txt.$#3, using password stored in file "password.txt" (Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this)):   

>    $ ./triops.exe -P password.txt -e 3 -o encryptedtext.txt plaintext.txt   

Example of encryption: encrypt complexdata.tgz file, overwriting it, using the password introduced with keyboard:   

>    $ ./triops.exe -k -e 3 complexdata.tgz   

    Enter password and press [enter]:   

    ----+----+----+----+---1/2---+----+----+----+----+ 5293 MiB   
    ################################################## 100%   

    'complexdata.tgz' processed   

Example of encryption: encrypt plaintext.txt file, overwriting it, using the password "triops!":   

>    $ ./triops.exe -p triops! -e 3 plaintext.txt   
   
Example of encryption without storing password hash hint (-H):   

>    $ ./triops.exe -p triops! -H -e 3 plaintext.txt   
   
Example of encryption: encrypt plaintext.txt, gplv3.txt and A1.jpg, using the password "triops!":   
   
>    $ ./triops.exe -p triops! -e 3 plaintext.txt gplv3.txt A1.jpg   

Example of decryption: decrypt plaintext.txt.$#3 file, writing result to clear.txt, using the password "triops!":   
   
>    $ ./triops.exe -p triops! -d -o clear.txt plaintext.txt.\$#3   
   
Example of decryption: decrypt plaintext.txt.$#3, gplv3.txt.$#3 and A1.jpg.$#3, overwriting each of them, using the password introduced with keyboard:   
   
>    $ ./triops.exe -k -d plaintext.txt.\$#3 gplv3.txt.\$#3 A1.jpg.\$#3  
     
   
   
Algorithms are based on reference implementation of CHACHA20 implemented by algorithm's creator (D. J. Bernstein), and the implementation of KECCAK made by Thomas Pornin. Both can be found at this website:   

[http://hyperelliptic.org/ebats/supercop-20141124.tar.bz2](http://hyperelliptic.org/ebats/supercop-20141124.tar.bz2)   

    /supercop-20141124/crypto_stream/chacha20/e/ref/   

    /supercop-20141124/crypto_hash/keccakc512/sphlib/   

CHACHA20 algorithm has been tested against test vectors found here:   

[http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7)   

[http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2](http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2)   

KECCAK algorithm has been tested against test vectors found here:   

[http://keccak.noekeon.org/KeccakKAT-3.zip](http://keccak.noekeon.org/KeccakKAT-3.zip)   

    /KeccakKAT/ShortMsgKAT_512.txt   

