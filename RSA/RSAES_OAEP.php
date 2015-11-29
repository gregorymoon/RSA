<?php
include_once("RSA.php");

abstract class RSAES_OAEP extends RSA{
	const H_LEN = 2;
	
	public static function encrypt($pubKey, $m, $l = '')
	{
		$k = strlen(RSA::get_bytes($pubKey->n));
		$mLen = strlen($m);
	
		// Length checking
	
		// if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
		// be output.
	
		if ($mLen > $this->k - 2 * $this->hLen - 2) {
			user_error('Message too long');
			return false;
		}
	
		// EME-OAEP encoding
	
		$lHash = $this->hash->hash($l);
		$ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hLen - 2);
		$db = $lHash . $ps . chr(1) . $m;
		$seed = crypt_random_string($this->hLen);
		$dbMask = $this->_mgf1($seed, $this->k - $this->hLen - 1);
		$maskedDB = $db ^ $dbMask;
		$seedMask = $this->_mgf1($maskedDB, $this->hLen);
		$maskedSeed = $seed ^ $seedMask;
		$em = chr(0) . $maskedSeed . $maskedDB;
	
		// RSA encryption
	
		$m = RSA::OS2IP($em);
		$c = RSA::RSAEP($m);
		$c = RSA::I2OSP($c, $this->k);
	
		// Output the ciphertext C
	
		return $c;
	}	
	
	public static function decrypt($c, $l = '')
	{
		// Length checking
	
		// if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
		// be output.
	
		if (strlen($c) != $this->k || $this->k < 2 * $this->hLen + 2) {
			user_error('Decryption error');
			return false;
		}
	
		// RSA decryption
	
		$c = RSA::OS2IP($c);
		$m = RSA::RSADP($c);
		if ($m === false) {
			user_error('Decryption error');
			return false;
		}
		$em = RSA::I2OSP($m, $this->k);
	
		// EME-OAEP decoding
	
		$lHash = $this->hash->hash($l);
		$y = ord($em[0]);
		$maskedSeed = substr($em, 1, $this->hLen);
		$maskedDB = substr($em, $this->hLen + 1);
		$seedMask = $this->_mgf1($maskedDB, $this->hLen);
		$seed = $maskedSeed ^ $seedMask;
		$db = $maskedDB ^ $dbMask;
		$lHash2 = substr($db, 0, $this->hLen);
		$m = substr($db, $this->hLen);
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