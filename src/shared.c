#include "crypto_scalarmult_curve25519.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_sign_edwards25519sha512batch.h"

#define EXPORT __attribute__ ((visibility("default")))

EXPORT int export_crypto_box_curve25519xsalsa20poly1305(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e,const unsigned char * f) { return crypto_box_curve25519xsalsa20poly1305(a,b,c,d,e,f); }
EXPORT int export_crypto_box_curve25519xsalsa20poly1305_open(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e,const unsigned char * f) { return crypto_box_curve25519xsalsa20poly1305_open(a,b,c,d,e,f); }
EXPORT int export_crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char * a,unsigned char * b, unsigned char * c) { return crypto_box_curve25519xsalsa20poly1305_keypair(a,b,c); }
EXPORT int export_crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char * a,const unsigned char * b,const unsigned char * c) { return crypto_box_curve25519xsalsa20poly1305_beforenm(a,b,c); }
EXPORT int export_crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e) { return crypto_box_curve25519xsalsa20poly1305_afternm(a,b,c,d,e); }
EXPORT int export_crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char * a,const unsigned char * b,unsigned long long c,const unsigned char * d,const unsigned char * e) { return crypto_box_curve25519xsalsa20poly1305_open_afternm(a,b,c,d,e); }
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_BEFORENMYBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
EXPORT const int export_crypto_box_curve25519xsalsa20poly1305_KEYPAIRRANDOMBYTES = crypto_box_curve25519xsalsa20poly1305_KEYPAIRRANDOMBYTES;

EXPORT int export_crypto_scalarmult_curve25519(unsigned char * a,const unsigned char * b,const unsigned char* c) { return crypto_scalarmult_curve25519(a,b,c); }
EXPORT int export_crypto_scalarmult_curve25519_base(unsigned char * a,const unsigned char * b) { return crypto_scalarmult_curve25519_base(a,b); }
EXPORT const int export_crypto_scalarmult_curve25519_BYTES = crypto_scalarmult_curve25519_BYTES;
EXPORT const int export_crypto_scalarmult_curve25519_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES;

EXPORT int export_crypto_sign_edwards25519sha512batch_(unsigned char * a,unsigned long long * b,const unsigned char * c,unsigned long long d,const unsigned char * e) { return crypto_sign_edwards25519sha512batch(a,b,c,d,e); }
EXPORT int export_crypto_sign_edwards25519sha512batch_open(unsigned char * a,unsigned long long * b,const unsigned char * c,unsigned long long d,const unsigned char * e) { return crypto_sign_edwards25519sha512batch_open(a,b,c,d,e); }
EXPORT int export_crypto_sign_edwards25519sha512batch_keypair(unsigned char * a,unsigned char * b,unsigned char * c) { return crypto_sign_edwards25519sha512batch_keypair(a,b,c); }
EXPORT const int export_crypto_sign_edwards25519sha512batch_BYTES = crypto_sign_edwards25519sha512batch_BYTES;
EXPORT const int export_crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES = crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
EXPORT const int export_crypto_sign_edwards25519sha512batch_SECRETKEYBYTES = crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;
EXPORT const int export_crypto_sign_edwards25519sha512batch_KEYPAIRRANDOMBYTES = crypto_sign_edwards25519sha512batch_KEYPAIRRANDOMBYTES;
