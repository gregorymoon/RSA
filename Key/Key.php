<?php
include_once("PrivateKey.php");
include_once("PublicKey.php");

abstract class Key{
	private static $N_LENGTH = 3072;

	public $n;
	
	protected function __construct($vals){
		$this->n = $vals["n"];
	}
	
	public static function generateKeyPair(){
		$vals = Key::calculateModulus();
		
		echo("Creating Public Key\n");
		$pubKey = new PublicKey($vals);
		
		$vals["e"] = $pubKey->e;
		
		echo("Creating Private Key\n");
		$privKey = new PrivateKey($vals);
		
		return array(
			"private" => $privKey,
			"public" => $pubKey
		);
	}
	
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
	
	private static function getPrime(){
		do{
			//gmp_random_bits returns positive int
			$rand = gmp_random_bits(Key::$N_LENGTH/2);
		}while(!gmp_prob_prime($rand));
		
		return $rand;
	}
	
	private static function getNumBits($gmp){
		$gmpString = gmp_strval($gmp, 2);	
		return strlen($gmpString);
	}
	
	//from http://blog.ideashower.com/post/15147136549/leastgreatest-common-mulitple-lcmgcm-in-php-and-javascri
	private static function lcm($a, $b) {
		return gmp_mul(gmp_div($a, Key::gcf($a,$b)), $b);
	}
	
	//from http://blog.ideashower.com/post/15147136549/leastgreatest-common-mulitple-lcmgcm-in-php-and-javascri
	private static function gcf($a, $b) {
		if(gmp_cmp($b, gmp_init(0)) == 0){
			return $a;
		}
		else{
			$temp = gmp_mod($a, $b);
			return Key::gcf($b, $temp);
		}
	
		//		return (gmp_cmp($b, gmp_init(0)) == 0) ? ($a) : (PublicKey::gcf($b, gmp_mod($a, $b)));
	}
}