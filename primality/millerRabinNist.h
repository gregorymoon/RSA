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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/rand.h>
#include <gmp.h>
#include <stdint.h>
/* ***************** PREPROCESSOR DIRECTIVES **************************/


/* ***************** STRUCTURE DEFINITIONS **************************/

 /****************** ENUM DEFINITIONS *****************************/
typedef enum
{
	PRIMALITY_NIST_MR_PROVABLE_PRIME						= 0x00,
	PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_WITH_FACTOR		= 0x01,
	PRIMALITY_NIST_MR_PROVABLE_COMPOSITE_NOT_POWER_OF_PRIME	= 0x02,
}primalityNistMrStatus_E;

/* ***************** PUBLIC FUNCTION DECLARATIONS ********************/
extern primalityNistMrStatus_E millerRabinNistPrimality(const mpz_t w, unsigned int iterations);