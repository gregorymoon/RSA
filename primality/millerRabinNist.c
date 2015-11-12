/* *********************************************************************
 *
 * User level program to do Miller - Rabin primality test
 *
 * Program Name:        millerRabinNist
 * Target:              Intel 
 * Architecture:		x86
 * Compiler:            gcc
 * File version:        v1.0.0
 * Author:              Brahmesh S D Jain
 * Email Id:            Brahmesh.Jain@asu.edu
 **********************************************************************/

/* *************** INCLUDE DIRECTIVES FOR STANDARD HEADERS ************/
#include "millerRabinNist.h"
#include "generalNist.h"
#include <stdbool.h>
/* ***************** PREPROCESSOR DIRECTIVES **************************/


/* ***************** STRUCTURE DEFINITIONS **************************/

 /****************** ENUM DEFINITIONS *****************************/

primalityNistMrStatus_E millerRabinNistPrimality(const mpz_t w, unsigned int iterations)
{
	mpz_t m, w_1;
	mp_bitcnt_t	a = 0U;

	mpz_init(m);
	mpz_init_set(w_1, w);
	mpz_sub_ui(w_1,w_1,(unsigned long int)1U);
	
	// Step 1 : Let a be the largest integer such that 2^a divides w–1.
	while(mpz_divisible_2exp_p(w_1, a))
	{
		a++;
	}
	a--;

	//Step 2 : m = (w–1) / 2^a.
	mpz_fdiv_q_2exp(m, w_1, a);

#if DEBUG
	printf("\n MR 1 : Value of m = \n");
	mpz_out_str(stdout, 10, m);
	printf("\n a = %d",a);

#endif

	// Step 3 : wlen = len(w)
	// find the length of the space occupied by w in bits. Also the first msb bit whose value=1
	size_t wlen = mpz_sizeinbase(w,2);
#if DEBUG
	printf("\nSize of wlen = %d bits", wlen);
#endif

	// Step 4
	// Run through number of iterations as suggested by the NIST
	// Step 4.1
	for(unsigned int i = 0; i < iterations; i++)
	{

		mpz_t bMpz;

		// String to get the random bits
		char bInBinaryString[wlen + 1];
		do
		{
			// Get the randomly generated number from openssl and convert it to string
			generalNistGenerateRandomString(wlen, (char*)&bInBinaryString);

			// Set the bMpz to the value represented by string
			if(mpz_init_set_str(bMpz, (const char *)&bInBinaryString, 2))
			{
				printf("\n Failed to initialize bMpz ");
			}
			// Step 4.2 : If ((b ≤ 1) or (b ≥ w–1)), then go to step 4.1
		}while((0 >= mpz_cmp_ui(bMpz, 1U)) || (0 <= mpz_cmp(bMpz, w_1)));

#if DEBUG
		printf("\n MR 4.1 : Value of bMpz = \n");
		mpz_out_str(stdout, 10, bMpz);
		printf("\n MR 4.1 : Value of W = \n");
		mpz_out_str(stdout, 10, w);
		printf("\n");
#endif

		//Step 4.3 gcd = GCD(b, w).
		mpz_t gcd;
		mpz_init(gcd);
		mpz_gcd (gcd, bMpz, w);

		// Step 4.4 If (gcd > 1), then return PROVABLY COMPOSITE WITH FACTOR and the value of gcd.
		if((0 < mpz_cmp_ui(gcd, 1U)))
		{
#if DEBUG
			printf("\nMESSAGE :PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_WITH_FACTOR : gcd = ");
			mpz_out_str(stdout, 10, gcd);
			printf("\n");
#endif
			// clear all the loop variables
			mpz_clear(gcd);
			mpz_clear(bMpz);
			mpz_clear(w_1);
			mpz_clear(m);

			return PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_WITH_FACTOR;
		}

		//Step 4.5 z = b^m mod w.
		mpz_t z;
		mpz_init(z); 
		mpz_powm_sec(z, bMpz, m, w);

		//Step 4.6 If ((z = 1) or (z = w – 1)), then go to step 4.15.OR continue
		if((0 == mpz_cmp_ui(z, 1U)) || (0 == mpz_cmp(z, w_1)))
		{
			// continue with next iteration
#if DEBUG
			printf("\nMESSAGE :Continuing with next iteration ");
#endif
			mpz_clear(bMpz);
			mpz_clear(z);
			mpz_clear(gcd);
			continue;
		}

		// Step 4.7
		mpz_t x;
		mpz_init(x);
		bool toStep4_1_2 = false;
		bool toStep4_1_5 = false;
		for(mp_bitcnt_t	j = 1U; j < a; j++)
		{
			// Step 4.7.1 : Comment: x ≠ 1 and x ≠ w–1.
			mpz_set(x, z);

			//Step 4.7.2 : z= x^2 mod w.
			mpz_powm_ui (z, x, 2U, w);

			//Step 4.7.3 : If (z = w–1), then go to step 4.15.
			if(0 == mpz_cmp(z, w_1))
			{
				toStep4_1_5 = true;
				break;
			}

			//Step 4.7.4 : If (z = 1), then go to step 4.12.
			if(0 == mpz_cmp_ui(z, 1U))
			{
				toStep4_1_2 = true;
				break;
			}

		}

		if(toStep4_1_5)
		{
			mpz_clear(x);
			mpz_clear(bMpz);
			mpz_clear(z);
			mpz_clear(gcd);
			continue;
		}

		if(false == toStep4_1_2)
		{
			// Step 4.8 : Comment: x =b^(w-1)/2 and x ≠ w–1.
			mpz_set(x, z);

			//Step 4.9
			mpz_powm_ui (z, x, 2U, w);

			//Step 4.10 x = z.Comment: x = b^(w–1) mod w and x ≠ 1.
			if(0 != mpz_cmp_ui(z, 1U))
			{
				// Step 4.11 : x = z. Comment: x = b^(w–1) mod w and x ≠ 1.
				mpz_set(x, z);
			}
		}
		//Step 4.12 : g = GCD(x–1, w).
		mpz_t x_1;
		mpz_init(x_1);
		mpz_sub_ui(x_1,x,(unsigned long int)1U);
		mpz_gcd (gcd, x_1, w);

		// Step 4.13 If (gcd > 1), then return PROVABLY COMPOSITE WITH FACTOR and the value of gcd.
		if((0 < mpz_cmp_ui(gcd, 1U)))
		{
#if DEBUG
			printf("\nMESSAGE : Step 4.13 : PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_WITH_FACTOR : gcd = ");
			mpz_out_str(stdout, 10, gcd);
			printf("\n");
#endif
			mpz_clear(x_1);
			mpz_clear(x);
			mpz_clear(bMpz);
			mpz_clear(z);
			mpz_clear(gcd);
			mpz_clear(w_1);
			mpz_clear(m);
			return PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_WITH_FACTOR;
		}

		mpz_clear(x_1);
		mpz_clear(x);
		mpz_clear(bMpz);
		mpz_clear(z);
		mpz_clear(gcd);
		mpz_clear(w_1);
		mpz_clear(m);
		return PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_NOT_POWER_OF_PRIME;	
	}

	//Step 5 :
	mpz_clear(m);
	mpz_clear(w_1);
	return PRIMALITY_NIST_MR_PROVABLE_PRIME;
}