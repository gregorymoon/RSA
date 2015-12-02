<?php
include_once("PrivateKey.php");
include_once("PublicKey.php");

abstract class Key{
	//The length of n is suggested to be either 1024, 2048, or 3072
	//bits in PKCS 1. In FIPS186-4 it is required that the length of 
	//n be either 1024 or 2048 bits. A 2048 bit length provides more
	//security so we used that as the length of n.
	private static $N_LENGTH = 2048;

	//The public modulus n common to a Public/Private key pair
	public $n;
	
	/*
	 * Constructor for the Key class.
	 * 
	 * $vals - an associative array containing different values
	 * 	based on what type of key is being created. All keys
	 * 	need to reference the modulus n, so n should always
	 * 	be in the array.
	 */
	protected function __construct($vals){
		$this->n = $vals["n"];
	}
	
	/*
	 * Public/Private Key pair generation
	 * 
	 * This function returns an associative array containing
	 * a PublicKey object for the key 'public' and a corresponding
	 * PrivateKey object for the key 'private'.
	 */
	public static function generateKeyPair(){
		//Initialize $vals with the values for p, q, n, and the totient of n
		$vals = Key::calculateModulus();
		
		//Create public key
		echo("Creating Public Key\n");
		$pubKey = new PublicKey($vals);
		
		$vals["e"] = $pubKey->e;
		
		//Create private key
		echo("Creating Private Key\n");
		$privKey = new PrivateKey($vals);
		
		return array(
			"private" => $privKey,
			"public" => $pubKey
		);
	}
	
	/*
	 * Calculating p, q, and n
	 * 
	 * This function calls the c executable 'output', which generates
	 * the primes p and q according to nist standards and outputs them 
	 * in an array.
	 * 
	 * Using the values for p and q generated using this executable,
	 * n and the totient of n are calculated and added returned to the caller
	 * in an associative array.
	 */
	private static function calculateModulus(){
		echo("Generating Random Primes\n");
		$command = "./output 2048 1024 1024 100";
		exec($command, $output);
		
		$p = gmp_init($output[0]);
		$q = gmp_init($output[1]);
		$n = gmp_mul($p, $q);
		
		$tempP = gmp_sub($p, gmp_init(1));
		$tempQ = gmp_sub($q, gmp_init(1));
		$totient = Key::lcm($tempP, $tempQ);
		
		return array(
			"p" => $p,
			"q" => $q,
			"n" => $n,
			"totient" => $totient
		);
	}
	
	/*
	 * Returns a probably prime number of length 
	 * $N_LENGTH/2 bits by generating random numbers of that length
	 * and checking if they are prime until a prime is found. Once a prime
	 * is found, it is returned.
	 * 
	 * ***This function was replaced by the 'output' executable referenced in the 
	 * calculateModulus method.
	 */
	private static function getPrime(){
		do{
			//gmp_random_bits returns positive int
			$rand = gmp_random_bits(Key::$N_LENGTH/2);
		}while(!gmp_prob_prime($rand));
		
		return $rand;
	}
	
	/*
	 * Get the number of bits in a gmp number.
	 * 
	 * This function works by simply converting a gmp value
	 * to a binary string and counting the number of bits.
	 */
	private static function getNumBits($gmp){
		$gmpString = gmp_strval($gmp, 2);	
		return strlen($gmpString);
	}
	
	/*
	 * Calculate the least common multple of two gmp values.
	 */
	private static function lcm($a, $b) {
		return gmp_mul(gmp_div($a, Key::gcf($a,$b)), $b);
	}
	
	/*
	 * calculate the greatest common factor of two gmp values.
	 */
	private static function gcf($a, $b) {
		if(gmp_cmp($b, gmp_init(0)) == 0){
			return $a;
		}
		else{
			$temp = gmp_mod($a, $b);
			return Key::gcf($b, $temp);
		}
	}
}