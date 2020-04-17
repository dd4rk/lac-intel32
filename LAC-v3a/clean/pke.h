#ifndef PKE_H
#define PKE_H

#include <stdint.h>

int kg(uint8_t *pk, uint8_t *sk);

int pke_enc_seed(const uint8_t *pk, const uint8_t *m, unsigned long long mlen, uint8_t *c, unsigned long long *clen, uint8_t *seed);

int pke_dec(const uint8_t *sk, const uint8_t *c, unsigned long long clen, uint8_t *m, unsigned long long *mlen);

#endif
