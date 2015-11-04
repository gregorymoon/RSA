<?php
include_once("PrivateKey.php");
include_once("PublicKey.php");

abstract class Key{
	public static function generate_key_pair($num_bytes){
		$p = Key::get_random_prime($num_bytes);
		
		do{
			$q = Key::get_random_prime($num_bytes);
		}while($p == $q);
		
		$n = gmp_mul($p, $q);
		$tn = gmp_mul(gmp_sub($p, 1), gmp_sub($q, 1));
		
		//echo("\ntn: $tn");
		
		do{
			$in_range = true;
			$e = Key::get_random_number($num_bytes);
		
			if(gmp_cmp($e, gmp_init("1")) <= 0 || gmp_cmp($e, $tn) >= 0){
				$in_range = false;
			}
		
		}while(gmp_gcd($e, $tn) != 1 || !$in_range);
		
		$d = Key::invmod($e, $tn);

		return array(
			"private" => new PrivateKey($p, $q, $d),
			"public" => new PublicKey($n, $e, $tn)
		);
	}

	/*
	 * From http://rosettacode.org/wiki/Modular_inverse#PHP
	 */
	protected static function invmod($a,$n){
		if (gmp_cmp($n, gmp_init("0")) < 0){
			$n = gmp_neg($n);
		}

		if (gmp_cmp($a, gmp_init("0")) < 0){
			$a = gmp_sub($n, gmp_mod(gmp_neg($a), $n));
		}
		;
		$t = gmp_init("0");
		$nt = gmp_init("1");
		$r = $n;
		$nr = gmp_mod($a, $n);

		while(gmp_cmp($nr, gmp_init("0")) != 0) {
			$quot = gmp_div($r, $nr);

			$tmp = $nt;  
			$nt = gmp_sub($t, gmp_mul($quot, $nt));
			$t = $tmp;
			
			$tmp = $nr;  
			$nr = gmp_sub($r, gmp_mul($quot, $nr));
			$r = $tmp;
		}

		if (gmp_cmp($r, gmp_init("1")) > 0){
			return gmp_init("-1");
		}
		;
		if (gmp_cmp($t, gmp_init("0")) < 0){
			$t = gmp_add($t, $n);
		}
		return $t;
	}
	
	protected static function gcf($a, $b) {
		return ($b == 0) ? ($a):(Key::gcf($b, $a % $b));
	}

	protected static function lcm($a, $b) {
		return ($a / Key::gcf($a, $b)) * $b;
	}

	protected static function get_random_number($bytes){
  		$prime = openssl_random_pseudo_bytes($bytes);
		$prime_string = strval(hexdec(unpack("H*", $prime)[1]));
		
		return gmp_init($prime_string, 10);
	}


	protected static function get_random_prime($bytes){
		$prime = Key::get_random_number($bytes);
	
		if(gmp_prob_prime($prime)){
			return $prime;
		}
		else{
			return Key::get_random_prime($bytes);
		}
	}
}
?>