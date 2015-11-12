/* *********************************************************************
 *
 * User level program to do general crypto operations
 *
 * Program Name:        generalNist
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

#define GENERAL_NIST_OUTPUT_LEN	8U
/* ***************** STRUCTURE DEFINITIONS **************************/

 /****************** ENUM DEFINITIONS *****************************/

/* ***************** PUBLIC FUNCTION DECLARATIONS ********************/
extern void generalNistGenerateRandomString(uint16_t byteCount, char* stringRandom);