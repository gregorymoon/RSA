/* *********************************************************************
 *
 * User level main program to generate the p and q prime using NIST
 * guidelines
 * Program Name:        primalityNist
 * Target:              Intel 
 * Architecture:		x86
 * Compiler:            gcc
 * File version:        v1.0.0
 * Author:              Brahmesh S D Jain
 * Email Id:            Brahmesh.Jain@asu.edu
 **********************************************************************/

/* *************** INCLUDE DIRECTIVES FOR STANDARD HEADERS ************/
#include <inttypes.h>

/* ***************** PREPROCESSOR DIRECTIVES **************************/


/* ***************** STRUCTURE DEFINITIONS **************************/

 /****************** ENUM DEFINITIONS *****************************/
typedef enum
{
	PRIME_NIST_VALID	= 0x00,
	PRIME_NIST_INVALID	= 0x01,
}primalityNistStatus_E;
/* ***************** PUBLIC FUNCTION DECLARATIONS ********************/