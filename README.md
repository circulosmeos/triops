triops: a simple command line tool for encryption/decryption of files.   

It uses [CHACHA20](http://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) as algorithm for encryption/decryption and [KECCAK](http://en.wikipedia.org/wiki/SHA-3)-512 as hash algorithm.   

Last version available and compiled is v9.0. Check [list of changes between versions](Changes.md).   

There's an [Android app available here](https://www.github.com/circulosmeos/triops.apk).   


Installation
------------

There is a PPA repository available for Ubuntu (contains versions from *precise* to *zesty*):

    $ sudo add-apt-repository ppa:roberto.s.galende/triops
    $ sudo apt-get update
    $ sudo apt-get install triops

Executables for some platforms (linux, Windows, HP-UX, Solaris and [Android](https://www.github.com/circulosmeos/triops.apk)) are available [here](https://circulosmeos.wordpress.com/2015/05/18/triops-a-multiplatform-cmdline-encryption-tool-using-chacha20-keccak).    

There's an [Android app available here](https://www.github.com/circulosmeos/triops.apk).   


Features:   
---------

* Code can be compiled with any C99 compiler, no matter platform, endianness or word size (32-64 bits): it has been tested on Windows, linux, Solaris and HP-UX OS's and Intel/AMD, ARM, MIPS, SPARC and Itanium processors.
* Same content produces different encrypted outputs every time. This is attained with a random initialization vector (IV) stored within the encrypted file.
* Files are (by default) encrypted/decrypted on-the-fly, so content is overwritten. This is interesting from a security point of view, as no clear content is left on disk. Anyway, also a different file output can be indicated.
* When decrypting, if password is not the one used for encrypting, the process is aborted, so the file cannot be rendered unusable. This behaviour is achieved thanks to a password hint stored within the encrypted file. (This hint can optionally be not stored: in this case the file could end up being decrypted with an incorrect password, so its contents would be irrecoverable.)
* Mentioned hint used to check that the password for decryption is correct is *not* the same used to encrypt (obviously!). Separate hashes are used for both purposes, though both are derived via different ways from the password and IV, using some 500-1000 concatenated KECCAK hashes.
* File modification time is maintained. File dates are important!
* **Encrypted files are appended the extension .ooo to filename**, so they can be recognized. (Yeah, it mimics the three eyes of a [triops](https://en.wikipedia.org/wiki/Triops#Taxonomy).)
* Password can be obtained from keyboard, command line or from a file. Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this). Also note that there's a limit on v7.1 on the number of characters that will be read from the file: 255 chars. This limit disappears on v7.2.
* Binary files can be used as passwords (from v7.2): for example jpg images, etc. Caution: do not lose this 'password' file and do not modify it!
* **From v9.0, files can be managed from stdin and to stdout on-the-fly.** See examples below. This has been achieved at the cost that files encrypted with version < 9.0 can be decrypted with greater versions, but in general files encrypted with version >=9.0 cannot be decrypted with previous versions. It's not that the format has changed so much, it's just that previous versions don't expect things the way v9.0 write them to be "cmdline-pipe-safe".
* From v7.3, there's no limit on the size on files read/written (up to 8 EiB = 2^63 bytes, or the max filesystem file size).
* Speed is extremely high, as CHACHA20 is a very fast encryption algorithm: it is as fast as RC4.
* Reduced program size: < 100 kiB on all platforms.
* [easily portable to Android](https://www.github.com/circulosmeos/triops.apk) as a JNI library. Check "ANDROID_LIBRARY" in the source code.
* Licensed as GPL v3.


File format and operation
-------------------------

Please [see post here describing triops' file format and general operation](https://circulosmeos.wordpress.com/2016/08/31/triops-operation-and-file-format-description-v9-0/).


Examples of use
---------------

>    $ ./triops.exe -h   
    
    triops v9.0.  (goo.gl/lqT5eP) (wp.me/p2FmmK-7Q)   
   
    Encrypt and decrypt files with secure password checking and   
    data overwriting, using CHACHA20 and KECCAK-512 algorithms.   
   
    $ triops {-kpP} [-oOiedHbh] <file> ...   
   
            <file> ... : one or more files to encrypt/decrypt   
                    If no file is indicated, stdin is used.   
            -k : read passphrase from keyboard   
            -p <password> : password is indicated in cmdline   
                    (beware of shell history!)   
            -P <password_file> : use hashed <password_file> as password   
            -o <output_file>: do not overwrite, but write to <output_file>   
            -O : write output to stdout.   
                    -o or -O options aren't possible with multiple input files.   
            -i <file> : input file (do not indicate more files at the end)   
            -e <type>: encrypt.   
                    Actually only '-e 3' is allowed   
                    File extension will be '.ooo' ('.$#3' for triops < v9.0)   
                    Other algorithms could be available in the future.   
            -d : decrypt. This is the default action.   
            -H : do not store password hint when encrypting   
                    Note that this way, an incorrect decryption password   
                    with data overwrting, will render the file unusable.   
            -b : break actions on first error encountered   
            -h : print this help   

   

Example of encryption: encrypt plaintext.txt file, overwriting it, using password stored in file "password.txt". Resulting file will be renamed automatically to plaintext.txt.ooo   

>    $ triops -P password.txt -e 3 plaintext.txt   

Example of encryption: encrypt plaintext.txt file on encryptedtext.txt.ooo, using password stored in file "password.txt" (Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this)). Note that password file can be *any* file (images, pdf, programs...) - see more examples below.   

>    $ triops -P password.txt -e 3 -o encryptedtext.txt plaintext.txt   

Example of encryption: encrypt complexdata.tgz file, overwriting it, using the password introduced with keyboard:   

>    $ triops -k -e 3 complexdata.tgz   

    Enter password and press [enter]:   

    ----+----+----+----+---1/2---+----+----+----+----+ 5293 MiB   
    ################################################## 100%   

    'complexdata.tgz' processed   

Example of encryption: encrypt plaintext.txt file, overwriting it, using the password "triops!":   

>    $ triops -p triops! -e 3 plaintext.txt   
   
Example of encryption without storing password hash hint (-H):   

>    $ triops -p triops! -H -e 3 plaintext.txt   
   
Example of encryption: encrypt plaintext.txt, gplv3.txt and A1.jpg, using the password "triops!":   
   
>    $ triops -p triops! -e 3 plaintext.txt gplv3.txt A1.jpg   

Example of decryption: decrypt plaintext.txt.ooo file, writing result to clear.txt, using the password "triops!":   
   
>    $ triops -p triops! -d -o clear.txt plaintext.txt.ooo   
   
Example of decryption: decrypt plaintext.txt.ooo, gplv3.txt.ooo and A1.jpg.ooo, overwriting each of them, using the password introduced with keyboard:   
   
>    $ triops -k -d plaintext.txt.ooo gplv3.txt.ooo A1.jpg.ooo   
     
Example of encryption from stdin:   
   
>    $ cat encryptedFile | triops -P password.jpg -e 3 -o decryptedOutput   
     
Example of decryption from stdin and to stdout:   
   
>    $ cat encryptedFile | triops -P password.jpg -d -O > decryptedOutput   
     
Testing the app on-the-fly using stdin and stdout :-o   
   
>    $ cat bigDataFile | triops -P password.tiff -e 3 -O | triops -P password.tiff -O | md5sum   
    
   
Compilation
-----------

Compilation on linux with gcc: a one-line script file is provided:   

>    $ bash Makefile   

For other compilers or platforms, modify the gcc command line contained in the Makefile file as convenient. Remember to use "-O3" ([fast executable optimizations](https://gcc.gnu.org/onlinedocs/gcc-4.7.1/gcc/Optimize-Options.html#Optimize-Options)). 
   
After compiling, **check that the provided encrypted file "gplv3.txt.ooo" decrypts correctly, to ensure that endianness determination has occured correctly**.

>    $ triops -p triops! -i gplv3.txt.ooo -O | md5sum   

>    3c34afdc3adf82d2448f12715a255122   

If the hash is different in your case, please #define or #undef LOCAL_LITTLE_ENDIAN in triops.h (it is a commented line: uncomment it - and comment the previous one, as set_endianness.h has failed) until the value obtained is "3c34afdc3adf82d2448f12715a255122".     

   
Testing
-------

There's a Perl script for triops executable testing against random content files. [See gist code](https://gist.github.com/circulosmeos/dfdbbadcb45e810babfee31945ba0172).   

For CHACHA20 and KECCAK testing see below.


CHACHA20 & KECCAK Algorithms
----------------------------

Algorithms are based on reference implementation of CHACHA20 implemented by algorithm's creator (D. J. Bernstein), and the implementation of KECCAK made by Thomas Pornin. Both can be found at this website:   

[http://hyperelliptic.org/ebats/supercop-20141124.tar.bz2](http://hyperelliptic.org/ebats/supercop-20141124.tar.bz2)   

    /supercop-20141124/crypto_stream/chacha20/e/ref/   

    /supercop-20141124/crypto_hash/keccakc512/sphlib/   

CHACHA20 algorithm has been tested against test vectors found here:   

[http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7)   

[http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2](http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2)   

Note that a skeleton for CHACHA20 testing is provided with triops' code, ready to compile as stand-alone: see [chacha20/chacha20_test.c](https://github.com/circulosmeos/triops/blob/master/chacha20/chacha20_test.c).   

KECCAK algorithm has been tested against test vectors found here:   

[http://keccak.noekeon.org/KeccakKAT-3.zip](http://keccak.noekeon.org/KeccakKAT-3.zip)   

    /KeccakKAT/ShortMsgKAT_512.txt   

Note that a skeleton for KECCAK testing is provided with triops' code, ready to compile as stand-alone: see [keccak/sha3_test.c](https://github.com/circulosmeos/triops/blob/master/keccak/sha3_test.c).   
