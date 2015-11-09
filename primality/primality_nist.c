#include <stdio.h>
#include "primalityNist.h"
#include <math.h>
#include <openssl/rand.h>

#define primalityCheckEarlyReturn(Validity) (if(PRIMALITY_NIST_INVALID_LN == Validity) return Validity)

/**
 * Standard approved pair L and N(bit length if p and q, respectively)
 * NIST.FIPS.186-4 Section 4.2 Selection of Parameter Sizes and Hash Functions for DSA
 */
 typedef struct
 {
 	uint16_t ValidL;
 	uint16_t ValidN;
 }primalityNistValid_S;

typedef enum name
{
	PRIMALITY_NIST_VALID_LN		= 0x00,
	PRIMALITY_NIST_INVALID_LN 	= 0x01,
}primalityNistValid_E;


static primalityNistValid_S primalityNistValidLN[] = {{1024,160}, {2048,224}, {2048,256}, {3072,256}};

static primalityNistValid_E primalityNistCheckLN(uint16_t L, uint16_t N);


static primalityNistValid_E primalityNistCheckLN(uint16_t L, uint16_t N)
{
	primalityNistValid_E Validity = PRIMALITY_NIST_INVALID_LN;

	for(uint8_t primalityNistValidLNIndex = 0;
		primalityNistValidLNIndex < (sizeof(primalityNistValidLN)/sizeof(primalityNistValid_S);
		primalityNistValidLNIndex++ )
	{
		if((L == primalityNistValidLN[primalityNistValidLNIndex].ValidL) && 
		   (N == primalityNistValidLN[primalityNistValidLNIndex].ValidN))
		{
			Validity = PRIMALITY_NIST_VALID_LN;
			break;
		}
	}

	return Validity;
}

primalityNistStatus_E primalityNist_Generateprime(uint16_t L, uint16_t N, uint16_t seedLen, uint8_t *p, uint8_t *q, uint8_t *seed, uint16_t *counter)
{
	primalityNistValid_E Validity = PRIMALITY_NIST_INVALID_LN;

	/* Start of Process of generation of prime */
	// Step 1
	Validity = primalityNistCheckLN(L, N);
	primalityCheckEarlyReturn(Validity);

	//step 2
	Validity = (seedLen < N) ? PRIMALITY_NIST_INVALID_LN : PRIMALITY_NIST_VALID_LN;
	primalityCheckEarlyReturn(Validity);

	//step 3
	uint16_t n = (uint16_t)(ceil(L/8.0) - 1);

	//step 4
	b = L - 1 - (n * 8);

	//Step 5 : Get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
	// Include mouse movements for the seeding the openssl random function. But for now, use the openssl's
	// random function without seeding

	uint8_t seed[N/8];
	if(RAND_bytes(&seed, N/8))
	{
		printf("\n Random number successfully acquired ! \n");
		for(uint16_t i = 0; i < N/8; i++) printf("%d",seed[i]);
	}
	else
	{
		printf("\n Error in acquirung random number");
	}
}