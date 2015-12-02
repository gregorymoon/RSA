<?php
include_once("Key.php");
class PrivateKey extends Key{
	//private key exponent used in decryption
	public $d;
	
	//values used in Chinese Remainder Theorem encryption/decryption
	//calculations
	public $dp;
	public $dq;
	public $qInv;
	
	//primes used to generate modulus n
	public $p;
	public $q;
	
	/*
	 * Constructor for the PrivateKey class
	 * 
	 * Initializes all values necessary for implementation of ecnrytpion/decryption
	 * using the Chinese Remainder Theorem.
	 * 
	 * d, dp, dq, qInv, p, and q
	 */
	protected function __construct($vals){
		parent::__construct($vals);
		$this->p = $vals["p"];
		$this->q = $vals["q"];

		$this->calculateD($vals);
		$this->calculateDP();
		$this->calculateDQ();
		$this->calculateQInv();
	}
	
	/*
	 * Calculate the private key exponent d
	 * 
	 * d = e ** -1 mod totient(n)
	 */
	private function calculateD($vals){
		$this->d = PrivateKey::invmod($vals["e"], $vals["totient"]);
	}
	
	/*
	 * Calculate the Chinese Remainder Theorem intermediate factor d_p
	 * 
	 * d_p = d mod (p - 1)
	 */
	private function calculateDP(){
		$this->dp = gmp_mod($this->d, gmp_sub($this->p, gmp_init(1)));
	}

	/*
	 * Calculate the Chinese Remainder Theorem intermediate factor d_p
	 *
	 * d_q = d mod (q - 1)
	 */
	private function calculateDQ(){
		$this->dq = gmp_mod($this->d, gmp_sub($this->q, gmp_init(1)));
	}
	
	/*
	 * Calculate the Chinese Remainder Theorem intermediate factor qInv
	 *
	 * qInv = q ** -1 mod p
	 */
	private function calculateQInv(){
		$this->qInv = PrivateKey::invmod($this->q, $this->p);
	}
	
	/*
	 * Modular Multiplicative Inverse
	 * 
	 * $a - gmp integer value
	 * $n - gmp integer value
	 * 
	 * output = $a ** -1 mod $n
	 * 
	 * *This code is taken in large part from
	 * http://rosettacode.org/wiki/Modular_inverse#PHP
	 */
	private static function invmod($a,$n){
		$zero = gmp_init(0);
		$one = gmp_init(1);
		
		//if $n < 0, $n = -$n
		if (gmp_cmp($n, $zero) < 0){
			$n = gmp_neg($n);
		}

		//if $a < 0, $a = n - (-$a mod $n)
		if (gmp_cmp($a, 0) < 0){
			$a = gmp_sub($n, gmp_mod(gmp_neg($a), $n));
		}

		$t = $zero; 
		$nt = gmp_init(1);
		$r = $n;
		$nr = gmp_mod($a, $n);

		while (gmp_cmp($nr, $zero) != 0) {
			$quot= gmp_div($r, $nr);
			$tmp = $nt;  
			$nt = gmp_sub($t, gmp_mul($quot, $nt));  
			$t = $tmp;
			$tmp = $nr;  
			$nr = gmp_sub($r, gmp_mul($quot,$nr));
			$r = $tmp;
		}
		
		if (gmp_cmp($r, $one) > 0){
			return -1;
		}
		if (gmp_cmp($t, $zero) < 0){
			$t = gmp_add($t, $n);
		}
		
		return $t;
	}
}
?>