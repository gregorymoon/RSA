/* *********************************************************************
 *
 * User level program to generate a prime number
 *
 * Program Name:        primalityNist
 * Target:              Intel 
 * Architecture:		x86
 * Compiler:            gcc
 * File version:        v1.0.0
 * Author:              Brahmesh S D Jain
 * Email Id:            Brahmesh.Jain@asu.edu
 **********************************************************************/

/* *************** INCLUDE DIRECTIVES FOR STANDARD HEADERS ************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "primalityNist.h"
#include <math.h>
#include <openssl/rand.h>
#include <gmp.h>
#include "millerRabinNist.h"
#include "generalNist.h"
#include <sys/time.h>
#include <linux/input.h>
#include <sys/syscall.h>

/* ***************** PREPROCESSOR DIRECTIVES **************************/
#define TESTPRIME		0U
#define primalityCheckEarlyReturn(Validity) do { if(PRIMALITY_NIST_INVALID_LN == Validity) return Validity; }while(0);

/* ***************** STRUCTURE DEFINITIONS **************************/
/**
 * Standard approved pair L and N(bit length if p and q, respectively)
 * NIST.FIPS.186-4 Section 4.2 Selection of Parameter Sizes and Hash Functions for DSA
 */
 typedef struct
 {
 	uint16_t ValidL;
 	uint16_t ValidN;
 }primalityNistValid_S;

typedef union
{
	struct
	{
		uint8_t		Left_btn		:1;
		uint8_t		Right_btn		:1;
		uint8_t		Middle_btn		:1;
		uint8_t		Reserved		:1;
		uint8_t		X_sign			:1;
		uint8_t		X_value			:8;
		uint8_t		Y_value			:8;
		uint8_t		Y_sign			:1;
		uint8_t		X_overflow		:1;
		uint8_t		Y_overflow		:1;
	};
	uint8_t	byte[3];
}MouseData_U;

/****************** ENUM DEFINITIONS *****************************/
typedef enum
{
	PRIMALITY_NIST_VALID_LN		= 0x00,
	PRIMALITY_NIST_INVALID_LN 	= 0x01,
}primalityNistValid_E;


/* ***************** PRIVATE VARIABLES *****************************/
static primalityNistValid_S primalityNistValidLN[] = {{1024,160}, {2048,224}, {2048,256}, {3072,256}};

/* ***************** PRIVATE FUNCTION DECLARATIONS ********************/
static primalityNistValid_E primalityNistCheckLN(uint16_t L, uint16_t N);


/* *********************************************************************
 * NAME:             primalityNistCheckLN
 * CALLED BY:        primalityNist_Generateprime
 * DESCRIPTION:      Checks the boundary on the lengths of the requested
 *					 P and Q bit lengths
 * INPUT PARAMETERS: Bit lengths L and N
 * RETURN VALUES:    VALID or INVALID
 ***********************************************************************/
static primalityNistValid_E primalityNistCheckLN(uint16_t L, uint16_t N)
{
	primalityNistValid_E Validity = PRIMALITY_NIST_INVALID_LN;

	for(uint8_t primalityNistValidLNIndex = 0;
		primalityNistValidLNIndex < (sizeof(primalityNistValidLN)/sizeof(primalityNistValid_S));
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


void primalityNist_SeedPRG(uint16_t seedLen)
{
	int MouseEventFd;
	MouseData_U MousePacket;
	uint8_t Seed[seedLen];
	if((MouseEventFd = open("/dev/input/mice", O_RDONLY)) < 0)
	{
		perror("opening device");
	}

	while(seedLen && read(MouseEventFd, &MousePacket, 3))
	{
		if(MousePacket.X_sign)
		{
			MousePacket.X_value = 255U - MousePacket.X_value;
			if(MousePacket.X_value)
			{
				Seed[--seedLen] = MousePacket.X_value;
#if DEBUG
				printf("%d", MousePacket.X_value);
#endif
			}
		}
#if DEBUG
		printf("\n Left_BTN = %d, Right_BTN = %d, Middle_BTN = %d, Reseverd = %d, Xsign = %d, X value = %d, Ysign = %d, Y value = %d, X OVFL = %d, Y OVFL = %d", MousePacket.Left_btn, MousePacket.Right_btn, MousePacket.Middle_btn, MousePacket.Reserved, MousePacket.X_sign, MousePacket.X_value, MousePacket.Y_sign, MousePacket.Y_value, MousePacket.X_overflow, MousePacket.Y_overflow);
#endif
	}
#if DEBUG
	printf("\n Thank you");
#endif
}


primalityNistStatus_E primalityNist_Generateprime(uint16_t L, uint16_t N, uint16_t seedLen, unsigned int RM_iter, uint8_t *p, uint8_t *q, uint8_t *seed, uint16_t *counter)
{
	primalityNistValid_E Validity = PRIMALITY_NIST_INVALID_LN;

	/* Start of Process of generation of prime */
	// Step 1
#if DIGITAL_SIGNATURE
	Validity = primalityNistCheckLN(L, N);
#else
	Validity = PRIMALITY_NIST_VALID_LN;
#endif

	primalityCheckEarlyReturn(Validity);

	//step 2
	Validity = (seedLen < N) ? PRIMALITY_NIST_INVALID_LN : PRIMALITY_NIST_VALID_LN;
	primalityCheckEarlyReturn(Validity);

	//step 3
	uint16_t n = (uint16_t)(ceil(L/(GENERAL_NIST_OUTPUT_LEN * 1.0))- 1);

	//step 4
	uint16_t b = L - 1 - (n * GENERAL_NIST_OUTPUT_LEN);

	// Seed the Random number generator so that it generates truely random number
#if DEBUG
	printf("\nStart moving mouse to create the randomness to seed PRG ");
#endif
	primalityNist_SeedPRG(seedLen);
	do
	{
		// Define the domain_parameter as a single variable
		mpz_t domainParameterSeedMpz;
		mpz_t mod2N_1;
		mpz_t U;
		mpz_t qMpz;
		mpz_t Umod2;
		mpz_t Two;
		do
		{
			//Step 5 : Get an arbitrary sequence of seedlen bits as the domain_parameter_seed.
			// Include mouse movements for the seeding the openssl random function. But for now, use the openssl's
			// random function without seeding
			char domainParameterSeedString[seedLen + 1];
			generalNistGenerateRandomString(seedLen, (char*)&domainParameterSeedString);

			// Initialize the seed as one long integer as given by the string.
			if(!mpz_init_set_str(domainParameterSeedMpz, (const char *)&domainParameterSeedString, 2))
			{
#if DEBUG
				printf("Succefully set the random string to the big number\n");
				printf("In binary : \n");
				mpz_out_str(stdout, 2, domainParameterSeedMpz);
				printf("\n In decimal : \n");
				mpz_out_str(stdout, 10, domainParameterSeedMpz);
				printf("\n Size in limbs : %d",(int)mpz_size(domainParameterSeedMpz));
				printf("\n");
#endif
			}
			else
			{
				printf("Failed to set the random string to the big number\n");
			}

			//step 6 : Calculated the HASH of the number, not sure how to do that
			//U = HASH(domainParameterSeed) mod 2^(N-1)
			// TODO : Include hash function
			mpz_init(mod2N_1);
			mpz_ui_pow_ui(mod2N_1,(unsigned long int)2U,(unsigned long int)(N-1));
			//This function is designed to take the same time and have the same cache access patterns for any two same-size arguments, 
			//assuming that function arguments are placed at the same position and that the machine state is identical upon function entry. 
			//This function is intended for cryptographic purposes, where resilience to side-channel attacks is desired.
			//Source : https://gmplib.org/manual/Integer-Exponentiation.html
			mpz_init(U);
			mpz_powm_ui(U, domainParameterSeedMpz, (unsigned long int)1U, mod2N_1);
#if DEBUG
			printf("\n Step 6 : Value of U = \n");
			mpz_out_str(stdout, 10, U);
			printf("\n");
#endif

			//step7 : q = 2^(N-1) + U + 1 - (U mod 2)
			mpz_init(qMpz);
			mpz_init(Umod2);
			mpz_init_set_str(Two, "2", 10);
			mpz_powm_ui(Umod2, U,(unsigned long int)1U, Two);
			mpz_add(qMpz, mod2N_1, U);
			mpz_add_ui(qMpz, qMpz, (unsigned long int)1U);
			mpz_sub(qMpz, qMpz, Umod2);

#if DEBUG
			printf("\n Step 7 : Value of q = \n");
			mpz_out_str(stdout, 10, qMpz);
			printf("\n");
#endif
			//Step8 : Test whether or not q is prime as specified in Appendix C.3.
			//Step9 : If q is not a prime, then go to step 5.
#if DEBUG
			printf("\nRUN");
#endif
		}while(PRIMALITY_NIST_MR_PROVABLE_PRIME != millerRabinNistPrimality(qMpz,RM_iter));

#if DEBUG
		printf("\n PRIME FOUND q = \n");
		mpz_out_str(stdout, 10, qMpz);
		printf("\n");
#endif

		//Step 10 : offset = 1
		mpz_t offset;
		mpz_init_set_str(offset, "1", 10);

		// Step 11 : For counter = 0 to (4L – 1) do
		for(uint16_t counterIndex = 0; counterIndex < (4*L); counterIndex++)
		{
			mpz_t W;
			mpz_init_set_str(W, "0", 10);

			mpz_t modTwo_SeedLength;
			mpz_init(modTwo_SeedLength);
			mpz_ui_pow_ui(modTwo_SeedLength,(unsigned long int)2U,(unsigned long int)(seedLen-1));

			//Step 11.1 : For j = 0 to n do V j = Hash ((domain_parameter_seed + offset + j) mod 2^seedlen ).
			for(uint16_t j = 0; j < n; j++)
			{
				mpz_t V;
				mpz_init_set_str(V, "0", 10);
				mpz_add(V, domainParameterSeedMpz, offset);
				mpz_add_ui(V, V, (unsigned long int)j);
				// TODO: need to add hash to below function
				mpz_powm_ui(V, V, (unsigned long int)1U, modTwo_SeedLength);
				mpz_mul_2exp(V, V, (j*GENERAL_NIST_OUTPUT_LEN));
				mpz_add(W, W, V);
				mpz_clear(V);
			}
			// Step 11.2
			// One more extra(nth) step for the last term
			mpz_t V, modTwoB;
			mpz_init_set_str(V, "0", 10);
			mpz_init(modTwoB);
			mpz_ui_pow_ui(modTwoB,(unsigned long int)2U,(unsigned long int)b);
			mpz_add(V, domainParameterSeedMpz, offset);
			mpz_add_ui(V, V, (unsigned long int)n);
			// TODO: need to add hash to below function
			mpz_powm_ui(V, V, (unsigned long int)1U, modTwo_SeedLength);
			// take additional mod 2^b for the result
			mpz_powm_ui(V, V, (unsigned long int)1U, modTwoB);
			mpz_mul_2exp(V, V, (n*GENERAL_NIST_OUTPUT_LEN));
			mpz_add(W, W, V);
			mpz_clear(V);
			mpz_clear(modTwoB);
			mpz_clear(modTwo_SeedLength); // not used in subsequent steps so clear it

			//Step 11.3
			mpz_t X, mod2L_1, TwoqMpz, c, pMpz;
			mpz_init_set_str(X, "0", 10);
			mpz_init(mod2L_1);
			mpz_ui_pow_ui(mod2L_1,(unsigned long int)2U,(unsigned long int)(L-1));
			mpz_add(X, W, mod2L_1);
			mpz_clear(W); // Not used in subsequent steps, so clear
			
			//Step 11.4
			mpz_init(TwoqMpz);
			mpz_mul_ui(TwoqMpz,qMpz, 2U);
			mpz_init(c);
			mpz_powm_ui(c, X, (unsigned long int)1U, TwoqMpz);
			mpz_clear(TwoqMpz);

			// Step 11.5
			mpz_sub_ui(c,c, 1U);
			mpz_init(pMpz);
			mpz_sub(pMpz, X, c);
			mpz_clear(c);
			mpz_clear(X); // X is not used in subsequent steps
			// Step 11.6
			if(0 <= mpz_cmp(pMpz, mod2L_1))
			{
				//Step 11.7
				if(PRIMALITY_NIST_MR_PROVABLE_PRIME == millerRabinNistPrimality(pMpz,RM_iter))
				{
					//Step 11.8
					// clear all the variables before return All globals + mod2L_1 + pMpz
					// Send/write back pMpz, qmpz, domainParameterSeedMpz and counterIndex
#if DEBUG
					printf("\nPRIME PAIRS FOUND \n\nq = ");
					mpz_out_str(stdout, 10, qMpz);
					printf("\n\np = ");
					mpz_out_str(stdout, 10, pMpz);
					printf("\n\nSeed = ");
					mpz_out_str(stdout, 10, domainParameterSeedMpz);
					printf("\n\nCounter = %d\n\n",counterIndex);
#endif
					mpz_out_str(stdout, 10, pMpz);
					printf("\n");
					mpz_out_str(stdout, 10, qMpz);
					mpz_clear(domainParameterSeedMpz);
					mpz_clear(mod2N_1);
					mpz_clear(U);
					mpz_clear(qMpz);
					mpz_clear(Two);
					mpz_clear(Umod2);
					mpz_clear(offset);
					mpz_clear(mod2L_1);
					mpz_clear(pMpz);

					return PRIME_NIST_VALID;
				}
			}

			// Step 11.9
			mpz_add_ui(offset, offset, (unsigned long int)n);
			mpz_add_ui(offset, offset, 1U);
			mpz_clear(mod2L_1);
			mpz_clear(pMpz);
		}

		// Clear all the variables from mpz library
		mpz_clear(domainParameterSeedMpz);
		mpz_clear(mod2N_1);
		mpz_clear(U);
		mpz_clear(qMpz);
		mpz_clear(Two);
		mpz_clear(Umod2);
		mpz_clear(offset);
	}while(1);

	//Should not get here
	return PRIME_NIST_INVALID;
}

void main(int argc, char *argv[])
{
	uint8_t P[1024], Q[160], Seed[1024];
	uint16_t counter = 0U;
	unsigned int L, N, Seedlen, RM_iterations; 
	struct timeval before, after;
    long utime, secs, usecs;
	primalityNistStatus_E primeNumberStatus = PRIME_NIST_INVALID;

	if(5 == argc)
	{
		/* Copy the sizes */
		L = atoi(argv[1]);
		N = atoi(argv[2]);
		Seedlen = atoi(argv[3]);
		RM_iterations = atoi(argv[4]);
	}
	/* Take the start timestamp */
	gettimeofday(&before, NULL);
	// Generate prime number.
	// Seed length can be very long, but Q qill be reduced to length N
	primeNumberStatus = primalityNist_Generateprime(L, N, Seedlen, RM_iterations, (uint8_t *)&P, (uint8_t *)&Q, (uint8_t *)&Seed, &counter);

	/* Take the end time stamp */
	gettimeofday(&after, NULL);

	secs  = after.tv_sec  - before.tv_sec;
	usecs = after.tv_usec - before.tv_usec;
	utime = ((secs) * 1000000 + usecs);
#if DEBUG
 	printf("\nExecution Time %lu s and %lu us\n\n\n\n", secs, usecs);
 #endif
#if TESTPRIME
	mpz_t test;
	// Bug: start atleast with a number greater than 1 byte length
	mpz_init_set_str(test, "257", 10);
	printf("\n Prime numbers from 257-20000\n");
	for(unsigned int i = 1; i < 10000; i++)
	{
		mpz_add_ui(test, test, (unsigned long int)2U);
		if(PRIMALITY_NIST_MR_PROVABLE_PRIME == millerRabinNistPrimality(test,1000U))
		{
			printf("\t");
			mpz_out_str(stdout, 10, test);
		}
	}
	mpz_clear(test);
#endif
}