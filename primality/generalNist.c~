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
#include "generalNist.h"

/* ***************** PREPROCESSOR DIRECTIVES **************************/


/* ***************** STRUCTURE DEFINITIONS **************************/

 /****************** ENUM DEFINITIONS *****************************/



/* *********************************************************************
 * NAME:             generalNistGenerateRandomString
 * CALLED BY:        all other modules
 * DESCRIPTION:      Generates random string using openssl library
 *					 and returns as a string
 * INPUT PARAMETERS: Bit count requested and pointer to string
 * RETURN VALUES:    None
 ***********************************************************************/
void generalNistGenerateRandomString(uint16_t bitCount, char* stringRandom)
{
	unsigned char domainParameterSeed[bitCount/GENERAL_NIST_OUTPUT_LEN];

	//clear the string first
	strcpy(stringRandom,"");

	// get random string from the openssl library function
	if(RAND_bytes((unsigned char*)&domainParameterSeed, bitCount/GENERAL_NIST_OUTPUT_LEN))
	{
#if DEBUG
		printf("\nRandom number successfully acquired ! \n");
		printf("number when printed as digit in each byte\n");
#endif
		// Convert from array of numbers into the string
		for(uint16_t i = 0; i < (bitCount/GENERAL_NIST_OUTPUT_LEN); i++)
		{
			// STR30-C. Do not attempt to modify string literals
			// STR31-C. Guarantee that storage for strings has sufficient space for character data and the null terminator
			char byteInString[30]={0};
#if DEBUG
			printf("%d",domainParameterSeed[i]);
#endif
			// STR30-C. Do not attempt to modify string literals
			//STR31-C. Guarantee that storage for strings has sufficient space for character data and the null terminator
			unsigned char n = domainParameterSeed[i];
			// get each byte as a binary number/string
			for(int i = 7; i >= 0; i--)
			{
				char bitInString[30]={0};
				if(n & (1 << i))
				{
					sprintf(bitInString,"1");
				}
				else
				{
					sprintf(bitInString,"0");
				}
				strcat(byteInString, bitInString);
			}
			// Concatenate to the final string
			strcat(stringRandom, byteInString);
		}
#if DEBUG
		printf("\nnumber when printed as character in each byte\n");
		printf("%s\n",stringRandom);
#endif
	}
	else
	{
		printf("Error in acquirung random number\n");
	}

}
