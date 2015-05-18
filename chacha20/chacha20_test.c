// based on bigtest.c 
// @ http://cr.yp.to/snuffle/bigtest.c
//

// v7:
#define LOCAL_LITTLE_ENDIAN

#include <stdio.h>
// inttypes instead of stdint for Solaris compatibility
#include <inttypes.h>
#include <memory.h>
#include "ecrypt-sync.h"

#include "chacha.c"
#include "api.c"

u8 s[4096];
u8 m[4096];
u8 c[4096];
u8 d[4096];
u8 k[32];
u8 v[8];

// taken from chacha20-simple-1.0/test.c 
// @ http://chacha20.insanecoding.org/
void hex2byte(const char *hex, uint8_t *byte)
{
  while (*hex) { sscanf(hex, "%2hhx", byte++); hex += 2; }
}

main()
{

  ECRYPT_ctx x;
  int i;
  int bytes_plaintext;
  int bytes_key;
  int bytes_iv;
  //char *plaintext="0000000000000000000000000000000000000000000000000000000000000000";
  //char *key=      "0000000000000000000000000000000000000000000000000000000000000000";
  //char *iv=       "0100000000000000";
  char *plaintext="2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e";
  char *key="1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
  char *iv="0000000000000002";

  // iv
  memcpy(s,iv,strlen(iv)+1);
  bytes_iv=strlen(s)/2;
  hex2byte(s, v); // transforms from left (string) to right (bytes)
  for (i = 0;i < bytes_iv;++i) printf("%02x",v[i]); printf("\n"); fflush(stdout);
  // key
  memcpy(s,key,strlen(key)+1);
  bytes_key=strlen(s)/2;
  hex2byte(s, k); // transforms from left (string) to right (bytes)
  for (i = 0;i < bytes_key;++i) printf("%02x",k[i]); printf("\n"); fflush(stdout);
  // plaintext
  memcpy(s,plaintext,strlen(plaintext)+1);
  bytes_plaintext=strlen(s)/2;
  hex2byte(s, m); // transforms from left (string) to right (bytes)
  for (i = 0;i < bytes_plaintext;++i) printf("%02x",m[i]); printf("\n"); fflush(stdout);    

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
  ECRYPT_keysetup(&x,k,256,64);
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
  ECRYPT_ivsetup(&x,v);

  /*
   * Encryption/decryption of arbitrary length messages.
   *
   * For efficiency reasons, the API provides two types of
   * encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
   * (declared here) encrypts byte strings of arbitrary length, while
   * the ECRYPT_encrypt_blocks() function (defined later) only accepts
   * lengths which are multiples of ECRYPT_BLOCKLENGTH.
   * 
   * The user is allowed to make multiple calls to
   * ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
   * but he is NOT allowed to make additional encryption calls once he
   * has called ECRYPT_encrypt_bytes() (unless he starts a new message
   * of course). For example, this sequence of calls is acceptable:
   *
   * ECRYPT_keysetup();
   *
   * ECRYPT_ivsetup();
   * ECRYPT_encrypt_blocks();
   * ECRYPT_encrypt_blocks();
   * ECRYPT_encrypt_bytes();
   *
   * ECRYPT_ivsetup();
   * ECRYPT_encrypt_blocks();
   * ECRYPT_encrypt_blocks();
   *
   * ECRYPT_ivsetup();
   * ECRYPT_encrypt_bytes();
   * 
   * The following sequence is not:
   *
   * ECRYPT_keysetup();
   * ECRYPT_ivsetup();
   * ECRYPT_encrypt_blocks();
   * ECRYPT_encrypt_bytes();
   * ECRYPT_encrypt_blocks();
  */  /*
  void ECRYPT_encrypt_bytes(
    ECRYPT_ctx* ctx, 
    const u8* plaintext, 
    u8* ciphertext, 
    u32 msglen);                // Message length in bytes.
  */

  // use this to test http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04#appendix-A.2
  // when Initial Block Counter>0 ... Comment in any other case.
  ECRYPT_encrypt_blocks(&x,m,c,42); 

  ECRYPT_encrypt_bytes(&x,m,c,bytes_plaintext);
  
  for (i = 0;i < bytes_plaintext;++i) printf("%02x",c[i]); printf("\n"); fflush(stdout);

  /*
  void ECRYPT_decrypt_bytes(
    ECRYPT_ctx* ctx, 
    const u8* ciphertext, 
    u8* plaintext, 
    u32 msglen);                // Message length in bytes. 
  */ 
  ECRYPT_ivsetup(&x,v);
  ECRYPT_decrypt_bytes(&x,c,d,bytes_plaintext);

  for (i = 0;i < bytes_plaintext;++i) printf("%02x",d[i]); printf("\n"); fflush(stdout);

  return 0;
}
