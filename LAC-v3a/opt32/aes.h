#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdlib.h>

#define AES128_KEYBYTES 16
#define AES192_KEYBYTES 24
#define AES256_KEYBYTES 32
#define AESCTR_NONCEBYTES 12
#define AES_BLOCKBYTES 16

typedef struct {
    uint64_t sk_exp[88];
} aes128ctx;

typedef struct {
    uint64_t sk_exp[104];
} aes192ctx;

typedef struct {
    uint64_t sk_exp[120];
} aes256ctx;



void aes128_keyexp(aes128ctx *r, const uint8_t *key);

void aes128_ecb(uint8_t *out, const uint8_t *in, size_t nblocks, const aes128ctx *ctx);

void aes128_ctr(uint8_t *out, size_t outlen, const uint8_t *iv, const aes128ctx *ctx);

void aes128_ctx_release(aes128ctx *r);


void aes192_keyexp(aes192ctx *r, const uint8_t *key);

void aes192_ecb(uint8_t *out, const uint8_t *in, size_t nblocks, const aes192ctx *ctx);

void aes192_ctr(uint8_t *out, size_t outlen, const uint8_t *iv, const aes192ctx *ctx);

void aes192_ctx_release(aes192ctx *r);


void aes256_keyexp(aes256ctx *r, const uint8_t *key);

void aes256_ecb(uint8_t *out, const uint8_t *in, size_t nblocks, const aes256ctx *ctx);

void aes256_ctr(uint8_t *out, size_t outlen, const uint8_t *iv, const aes256ctx *ctx);

void aes256_ctx_release(aes256ctx *r);


#endif
