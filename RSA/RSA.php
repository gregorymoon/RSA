<?php
include_once("Key/Key.php");
include_once("Math/BigInteger.php");
include_once("Hash/Hash.php");
include_once("Hash/Random.php");

abstract class RSA{
	const HASH = 'sha1';

	/*
	 * Generate an RSA Public/Private Key Pair
	 * 
	 * The public/private key pair is returned as an associative array
	 * with key 'public' holding a PublicKey object and key 'private'
	 * holding a corresponding PricateKey object.
	 */
	public static function generateKeyPair(){
		return Key::generateKeyPair();
	}

	/*
	 * Mask Geneartion Function
	 * 
	 * This function was taken from the phpseclib1.0 library. It is used
	 * in the RSAES_OAEP scheme in order to produce padded messages to 
	 * enable nondeterministic encryption.
	 */
	protected static function MGF1($mgfSeed, $maskLen)
	{
		//the default function for the Crypt_Hash class is sha1
		$mgfHash = new Crypt_Hash();
		
		//Length of hash output in octets.
		//mgfHLen = 20 octets * 8 bits/octet = 160 bits = output length of sha1 in bits
		$mgfHLen = $mgfHash->getLength();

		$t = '';
		$count = ceil($maskLen / $mgfHLen);

		for ($i = 0; $i < $count; $i++) {
			//convert $i into a binary string
			$c = pack('N', $i);
			
			//hash $c ($i as a binary string) using sha1 with the $mgfSeed as the seed for the hash function.
			$t .= $mgfHash->hash($mgfSeed . $c);
		}
	
		return substr($t, 0, $maskLen);
	}

	/*
	 * Integer to Octet-String Conversion Primitive
	 * 
	 * Convert an integer to an octet strin where an octet in this
	 * context is an 8-bit byte.
	 * 
	 * $x - integer value to be converted
	 * $xLen - integer value indicating the desired length (in octets)
	 * of the output octet string.
	 */
	protected static function I2OSP($x, $xLen){
		//convert the gmp value $x to binary representstion
		$x = RSA::getBytesForGMP($x);

		//if the binary representation of $x requires more bits than the desired
		//output length then $x itself was too large or the ouput length was too small.
		if (strlen($x) > $xLen) {
			user_error('Integer too large');
			return false;
		}
		
		//the binary representation of $x may not be of length $xLength, so pad
		//the return value with leading zeros until it is of the proper length.
		return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
	}
	
	/*
	 * Octet-String to Integer Conversion Primitive
	 * 
	 * Convert an octet string to an integer where an octet
	 * string in this context is an 8-bit byte
	 * 
	 * $x - octet string to convert to an integer.
	 */
	protected static function OS2IP($x){
		//
		$temp = new Math_BigInteger($x, 256);
		return gmp_init($temp->toString());
	}

	/*
	 * Return the binary representation of a gmp value.
	 * 
	 * $num - the gmp value to convert to its binary representation.
	 */
	protected static function getBytesForGMP($num){
		$num = gmp_strval($num);
		$num = new Math_BigInteger($num);
		return $num->toBytes();
	}
	
	/*
	 * RSA Encrypion Primitive
	 * 
	 * RSAEP is the building block for any fully fledged RSA scheme. It performs
	 * deterministic encryption and is therefore insecure. Any properly implemented
	 * RSA scheme must provide message padding to overcome this.
	 * 
	 * $pubKey - the PublicKey object to be used to encrypt a message
	 * $mesage - the message to be encrypted
	 * $sig - boolean value indicating whether or not the message should be signed
	 * 	*we did not imlement signing so $sid should always be false
	 */
	protected static function RSAEP($pubKey, $message, $sig = false){
		//validate input parameters
		RSA::checkMessageInput($pubKey, $message, $sig);
		
		//return $message ^ $e mod $n
		return gmp_powm($message, $pubKey->e, $pubKey->n);	
	}
	
	/*
	 * RSA Decryption Primitive
	 * 
	 * RSADP is the bulding block for decryption in any fully-fledged RSA
	 * scheme. It performs decryption on any value encrypted using the correct
	 * public key with RSADP. If the cnryption function is modified to produce non-deterministic encryption
	 * then the decryption function must also be modified accordinly in order
	 * to accomodate that change. RSADP should not be used for decryption as is.
	 * 
	 * $privKey - PrivateKey to be used for decryption
	 * $ciphertext - $ciphertext to be decrypted
	 * $sig - boolean value indicating whether or not the message should be signed
	 * 	*we did not imlement signing so $sid should always be false
	 */
	protected static function RSADP($privKey, $ciphertext, $sig = false){
		RSA::checkMessageInput($privKey, $ciphertext, $sig);
		
		$m1 = gmp_powm($ciphertext, $privKey->dp, $privKey->p);
		$m2 = gmp_powm($ciphertext, $privKey->dq, $privKey->q);
		$h = gmp_mod(gmp_mul($privKey->qInv, gmp_sub($m1, $m2)), $privKey->p);
		
		return gmp_add($m2, gmp_mul($h, $privKey->q));
	}
	
	/*
	 * RSA Signature Primitive
	 */
	protected static function RSASP1($privKey, $message){
		return RSA::RSADP($privKey, $message, true);
	}
	
	/*
	 * RSA Signature VerificationPrimitive
	 */
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