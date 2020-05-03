#include <string.h>

#include "api.h"
#include "lac_param.h"
#include "pke.h"
#include "ecc.h"
#include "rand.h"

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    kg(pk, sk);
    return 0;
}

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    uint8_t buf[MESSAGE_LEN],seed[SEED_LEN],seed_buf[MESSAGE_LEN+SEED_LEN];
    unsigned long long clen;

    //generate random message m, stored in buf
    random_bytes(buf,MESSAGE_LEN);
    //compute seed=gen_seed(m|pk), add pk for multi key attack protection
    memcpy(seed_buf,buf,MESSAGE_LEN);
    memcpy(seed_buf+MESSAGE_LEN,pk,SEED_LEN);
    gen_seed(seed_buf,MESSAGE_LEN+SEED_LEN,seed);
    //encrypt m with seed
    pke_enc_seed(pk,buf,MESSAGE_LEN,ct,&clen,seed);

    //compute k=hash(m|c)
    hash_to_k(buf,MESSAGE_LEN,ss);

    return 0;
}

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    uint8_t buf[MESSAGE_LEN+CIPHER_LEN],seed[SEED_LEN],seed_buf[MESSAGE_LEN+SEED_LEN];
    unsigned long long mlen,clen;
    uint8_t c_v[CIPHER_LEN];
    const uint8_t *pk;
    pk=sk+SK_LEN;

    //compute m from c
    pke_dec(sk,ct,CIPHER_LEN, buf,&mlen);
    //compte k=hash(m|c)
    hash_to_k(buf,MESSAGE_LEN,ss);
    //re-encryption with seed=gen_seed(m|pk), add pk for multi key attack protection
    memcpy(seed_buf,buf,MESSAGE_LEN);
    memcpy(seed_buf+MESSAGE_LEN,pk,SEED_LEN);
    gen_seed(seed_buf,MESSAGE_LEN+SEED_LEN,seed);
    pke_enc_seed(pk,buf,MESSAGE_LEN,c_v,&clen,seed);

    //verify
    if(memcmp(ct,c_v,CIPHER_LEN)!=0)
    {
        //k=hash(hash(sk)|c)
        hash((uint8_t*)sk,SK_LEN,buf);
        hash(buf,MESSAGE_LEN+CIPHER_LEN,ss);
    }
    return 0;
}
