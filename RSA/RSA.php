<?php
include_once("Key/Key.php");
include_once("Math/BigInteger.php");
include_once("Hash/Hash.php");
include_once("Hash/Random.php");

abstract class RSA{
	const HASH = 'sha1';

	public static function generateKeyPair(){
		return Key::generateKeyPair();
	}

	protected static function MGF1($mgfSeed, $maskLen)
	{
		$mgfHash = new Crypt_Hash();
		$mgfHLen = $mgfHash->getLength();

		// if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.
	
		$t = '';
		$count = ceil($maskLen / $mgfHLen);
		for ($i = 0; $i < $count; $i++) {
			$c = pack('N', $i);
			$t.= $mgfHash->hash($mgfSeed . $c);
		}
	
		return substr($t, 0, $maskLen);
	}

	//integer to octet string primitive
	protected static function I2OSP($x, $xLen)
	{
		$x = RSA::getBytesForGMP($x);

		if (strlen($x) > $xLen) {
			user_error('Integer too large');
			return false;
		}
		return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
	}
	
	protected static function OS2IP($x)
	{
		$temp = new Math_BigInteger($x, 256);
		return gmp_init($temp->toString());
	}

	protected static function getBytesForGMP($num){
		$num = gmp_strval($num);
		$num = new Math_BigInteger($num);
		return $num->toBytes();
	}
	
	//encryption primative
	protected static function RSAEP($pubKey, $message, $sig = false){
		RSA::checkMessageInput($pubKey, $message, $sig);
		return gmp_powm($message, $pubKey->e, $pubKey->n);	
	}
	
	//decryption primative
	protected static function RSADP($privKey, $ciphertext, $sig = false){
		RSA::checkMessageInput($privKey, $ciphertext, $sig);
		
		$m1 = gmp_powm($ciphertext, $privKey->dp, $privKey->p);
		$m2 = gmp_powm($ciphertext, $privKey->dq, $privKey->q);
		$h = gmp_mod(gmp_mul($privKey->qInv, gmp_sub($m1, $m2)), $privKey->p);
		
		return gmp_add($m2, gmp_mul($h, $privKey->q));
	}
	
	//signature creation primative
	protected static function RSASP1($privKey, $message){
		return RSA::RSADP($privKey, $message, true);
	}
	
	//signature verification primative
	protected static function RSAVP1($pubKey, $signature){
		return RSA::RSAEP($pubKey, $signature, true);
	}
	
	private static function checkMessageInput($key, $message, $sig){
		$zero = gmp_init(0);
		$one = gmp_init(1);
		$check = gmp_sub($key->n, $one); 

		if(gmp_cmp($message, $zero) < 0 || gmp_cmp($message, $check) > 0){
			if(!$sig){
				if(is_a($key, PublicKey::class)){
					echo("message representative out of range\n");	
				}
				else{
					echo("ciphertext representative out of range\n");
				}
			}
			else{
				echo("signature representative out of range\n");	
			}
			
			exit;
		}
	}
}
?>