#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "rand.h"

#define CTESTS 10000
#define LOOP 1000

static void print_uint64(unsigned long long num)
{
	if(num>=10)
		print_uint64(num/10);
	printf("%u",(unsigned int)(num%10));
}

int main()
{
	uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[CRYPTO_SECRETKEYBYTES];
	uint8_t k1[CRYPTO_BYTES],k2[CRYPTO_BYTES],c[CRYPTO_CIPHERTEXTBYTES];
	size_t i,j;
	long long int  error_num=0;
	
	printf("correctness test of kem_fo:\n");
	for(j=0;j<LOOP;j++)
	{
		crypto_kem_keypair(pk,sk);
		random_bytes(k1,CRYPTO_BYTES);
		for(i=0;i<CTESTS;i++)
		{
			crypto_kem_enc(c,k1,pk);
			crypto_kem_dec(k2,c,sk);
			
			if(memcmp(k1,k2,CRYPTO_BYTES)!=0)
			{
				error_num++;
			}
			
		}
		printf("test %lu error block:",j+1);
		print_uint64(error_num);
		printf("\n");
	}
	printf("\n");

	return error_num;
}
