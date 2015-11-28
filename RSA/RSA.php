<?php
include_once("Key/Key.php");
include_once("Math/BigInteger.php");

abstract class RSA{
	private static $MAX_INT;
	
	public static function decrypt($c, $priv_key){
		if(!isset(RSA::$MAX_INT)){
			RSA::$MAX_INT = gmp_init(strval(PHP_INT_MAX));
		}

		RSA::check_inputs($c, $priv_key, PrivateKey::class);

		$m1 = gmp_powm($c, $priv_key->d_p, $priv_key->p);
		$m2 = gmp_powm($c, $priv_key->d_q, $priv_key->q);
		$h = gmp_mod(gmp_mul($priv_key->q_inv, gmp_sub($m1, $m2)), $priv_key->p);
		
		return gmp_add($m2, gmp_mul($h, $priv_key->q));
	}

	public static function encrypt($m, $pub_key){
		RSA::check_inputs($m, $pub_key, PublicKey::class);
		return gmp_mod(gmp_pow($m, gmp_intval($pub_key->e)), $pub_key->n);
	}

	public static function generate_key_pair($num_bytes){
		return Key::generate_key_pair($num_bytes);
	}
	
	private static function I2OSP($x, $xLen)
	{
		$x = gmp_strval($x);
		$x = $x->toBytes();
		if (strlen($x) > $xLen) {
			user_error('Integer too large');
			return false;
		}
		return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
	}
	
	private static function OS2IP($x)
	{
		$temp = new Math_BigInteger($x, 256);
		return gmp_init($temp->toString());
	}
	
	private static function check_inputs($m, $key, $key_class){
		$err = false;
		
		if(is_int($m)){
			$m = gmp_init(strval($m));	
		}
		else if(is_string($m) && is_numeric($m)){
			$m = gmp_init($m);	
		}
		else if(!is_a($m, GMP::class)){
			echo("The message to be encrypted must be an integer, numeric string, or GMP object.\n");
			$err = true;
		}

		if(!is_a($key, $key_class)){
			echo("The key used for encryption must be a $key_class object.\n");
			$err = true;
		}
		
		if($err){
			exit;
		}
	}
}
?>