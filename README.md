crypty: a simple command line tool for encryption/decryption of files.   

It uses [CHACHA20](http://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) as algorithm for encryption/decryption and [KECCAK](http://en.wikipedia.org/wiki/SHA-3)-512 as hash algorithm.   

Executables for some platforms (linux, Windows, HP-UX and Solaris) are available [here](https://circulosmeos.wordpress.com/2015/05/18/crypty-a-versatile-multiplatform-encryption-tool-using-chacha20-keccak).   

Features:   

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

Known limitations:   

* Files higher than 4 GiB cannot be managed and will produce unexpected outputs: be warned!   

 

Compilation on linux with gcc: a one-line "Makefile" file is provided:   

>    $ bash Makefile   

For other compilers or platforms, modify the gcc command line contained in the Makefile file as convenient. Remember to use "-O3" ([fast executable optimizations](https://gcc.gnu.org/onlinedocs/gcc-4.7.1/gcc/Optimize-Options.html#Optimize-Options)). 

 

Examples of use:   

>    $ ./crypty.exe   

    Invalid parameters. Command line must be:   

    crypty <file with passphrase |   
    _passphrase rounded by '_' (__=>keyboard)_>   
    <file to decrypt> [path to decrypted file|=]   
    [*=encrypt .$#3] [*=don't store password hash (store IV+0x0's)]   

Example of encryption: encrypt plaintext.txt file, overwriting it, using password stored in file "password.txt". Resulting file will be renamed plaintext.txt.$#3   

>    $ ./crypty.exe password.txt plaintext.txt = 3   

Example of encryption: encrypt plaintext.txt file on encryptedtext.txt.$#3, using password stored in file "password.txt" (Caution: usually text files end with a "return" (line feed, \n, \r\n, \r) which will be used as the rest of chars in the file as part of the password. (Use $ cat > password + Ctrl+D to avoid this)):   

>    $ ./crypty.exe password.txt plaintext.txt encryptedtext.txt 3   

Example of encryption: encrypt plaintext.txt file, overwriting it, using the password introduced with keyboard:   

>    $ ./crypty.exe \_\_ plaintext.txt = 3   

    Enter password and press [enter]:   

    ----+----+----+----+---1/2---+----+----+----+----+ 1293 MiB   
    ################################################## 100%   

    completed   

Example of encryption: encrypt plaintext.txt file, overwriting it, using the password "crypty!":   

>    $ ./crypty.exe \_crypty!\_ plaintext.txt = 3   

Example of decryption: decrypt plaintext.txt.$#3 file, overwriting it, using the password "crypty!":   

>    $ ./crypty.exe \_crypty!\_ plaintext.txt.\$\\#3   

Example of encryption without storing password hash (add a 5th non-empty argument):   

>    $ ./crypty.exe \_crypty!\_ plaintext.txt = 3 1   

     

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

