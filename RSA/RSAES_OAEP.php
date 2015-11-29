<?php
include_once("RSA.php");

abstract class RSAES_OAEP extends RSA{
	
	public static function encrypt($pubKey, $m, $l = '')
	{
		$hash = new Crypt_Hash(RSA::HASH);
		$hlen = $hash->getLength();
		$k = strlen(RSA::getBytesForGMP($pubKey->n));
		$mLen = strlen($m);
	
		// Length checking
	
		// if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
		// be output.
	
		if ($mLen > $k - 2 * $hlen - 2) {
			user_error('Message too long');
			return false;
		}
	
		// EME-OAEP encoding
	
		$lHash = $hash->hash($l);
		$ps = str_repeat(chr(0), $k - $mLen - 2 * $hlen - 2);
		$db = $lHash . $ps . chr(1) . $m;
		$seed = crypt_random_string($hlen);
		$dbMask = RSA::MGF1($seed, $k - $hlen - 1);
		$maskedDB = $db ^ $dbMask;
		$seedMask = RSA::MGF1($maskedDB, $hlen);
		$maskedSeed = $seed ^ $seedMask;
		$em = chr(0) . $maskedSeed . $maskedDB;
	
		// RSA encryption
	
		$m = RSA::OS2IP($em);
		$c = RSA::RSAEP($pubKey, $m);
		$c = RSA::I2OSP($c, $k);
	
		// Output the ciphertext C
	
		return $c;
	}	
	
	public static function decrypt($privKey, $c, $l = '')
	{
		$hash = new Crypt_Hash(RSA::HASH);
		$hlen = $hash->getLength();
		$k = strlen(RSA::getBytesForGMP($privKey->n));
		// Length checking
	
		// if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
		// be output.
	
		if (strlen($c) != $k || $k < 2 * $hlen + 2) {
			user_error('Decryption error');
			return false;
		}
	
		// RSA decryption
	
		$c = RSA::OS2IP($c);
		$m = RSA::RSADP($privKey, $c);
		if ($m === false) {
			user_error('Decryption error');
			return false;
		}
		$em = RSA::I2OSP($m, $k);
	
		// EME-OAEP decoding
	
		$lHash = $hash->hash($l);
		$y = ord($em[0]);
		$maskedSeed = substr($em, 1, $hlen);
		$maskedDB = substr($em, $hlen + 1);
		$seedMask = RSA::MGF1($maskedDB, $hlen);
		$seed = $maskedSeed ^ $seedMask;
		$dbMask = RSA::MGF1($seed, $k - $hlen - 1);
		$db = $maskedDB ^ $dbMask;
		$lHash2 = substr($db, 0, $hlen);
		$m = substr($db, $hlen);
		if ($lHash != $lHash2) {
			user_error('Decryption error');
			return false;
		}
		$m = ltrim($m, chr(0));
		if (ord($m[0]) != 1) {
			user_error('Decryption error');
			return false;
		}
	
		// Output the message M
	
		return substr($m, 1);
	}
}
?>