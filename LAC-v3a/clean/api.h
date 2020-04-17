#ifndef API_H
#define API_H

#include <stdint.h>

#include  "lac_param.h"

#define CRYPTO_SECRETKEYBYTES SK_LEN+PK_LEN
#define CRYPTO_PUBLICKEYBYTES PK_LEN
#define CRYPTO_BYTES MESSAGE_LEN
#define CRYPTO_CIPHERTEXTBYTES CIPHER_LEN

#define CRYPTO_ALGNAME STRENGTH

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
