<?php
include_once("RSA.php");

abstract class RSAES_OAEP extends RSA{
	
	/*
	 * RSAES_OAEP Encryption
	 * *This function is taken in large part from phpseclib1.0
	 */
	public static function encrypt($pubKey, $m, $l = '')
	{
		$hash = new Crypt_Hash(RSA::HASH);
		$hlen = $hash->getLength();
		$k = strlen(RSA::getBytesForGMP($pubKey->n));
		$mLen = strlen($m);
	
		// if |$l| > 2000000 TB PKCS #1 suggests throwing a 'label too long' error. For our
		// purposes this is far outside the bounds of anything we could test on so we leave this out
		// but if it were to be implemented it should be imlemented here.
	
		if ($mLen > $k - 2 * $hlen - 2) {
			user_error('Message too long');
			return false;
		}
	
		/* 
		 * EME-OAEP encoding
		 * 
		 * This block of code pads the message to be encrypted in order to ensure
		 * non-deterministic encryption.
		 * 
		 * 1. First, the label is hashed using sha1
		 * 2. Generate the octet string ps as a string of 0s
		 * 3. concatenate lHash, ps, 0x01, and the message to create db
		 * 4. create a random string of length hlen to be the seed for the mask generation function
		 * 5. create a mask for db using the mask generation function using the seed from step 4
		 * 6. mask the db using dbMask
		 * 7. create a mask for the seed by using maskedDB as the seed for the mask generation function
		 * 8. mask the seed using the seedMask from 7
		 * 9. create em, the padded message by concatenating 0x00, maskedSeed and maskedDB
		 */
		$lHash = $hash->hash($l);
		$ps = str_repeat(chr(0), $k - $mLen - 2 * $hlen - 2);
		$db = $lHash . $ps . chr(1) . $m;
		$seed = crypt_random_string($hlen);
		$dbMask = RSA::MGF1($seed, $k - $hlen - 1);
		$maskedDB = $db ^ $dbMask;
		$seedMask = RSA::MGF1($maskedDB, $hlen);
		$maskedSeed = $seed ^ $seedMask;
		$em = chr(0) . $maskedSeed . $maskedDB;
	
		//ENCRYPTION
		
		//convert the padded message to an integer
		$m = RSA::OS2IP($em);
		
		//encrypt the new $m
		$c = RSA::RSAEP($pubKey, $m);
		
		//convert the ciphertext to an octet string
		$c = RSA::I2OSP($c, $k);
	
		return $c;
	}	
	
	/*
	 * RSAES_OAEP Decryption
	 * *This function is taken in large part from phpseclib1.0
	 */
	public static function decrypt($privKey, $c, $l = '')
	{
		$hash = new Crypt_Hash(RSA::HASH);
		$hlen = $hash->getLength();
		$k = strlen(RSA::getBytesForGMP($privKey->n));
		// Length checking
	
		// if |$l| > 2000000 TB PKCS #1 suggests throwing a 'label too long' error. For our
		// purposes this is far outside the bounds of anything we could test on so we leave this out
		// but if it were to be implemented it should be imlemented here.
		
		if (strlen($c) != $k || $k < 2 * $hlen + 2) {
			user_error('Decryption error');
			return false;
		}
	
		//DECRYPTION
		
		//convert the ciphertext to an integer
		$c = RSA::OS2IP($c);
		
		//decrypt the ciphertext
		$m = RSA::RSADP($privKey, $c);

		if ($m === false) {
			user_error('Decryption error');
			return false;
		}

		$em = RSA::I2OSP($m, $k);
	
		/*
		 * EME-OAEP Decoding
		 * Now that the ciphertext has been decrypted, the padding must be removed to 
		 * recover the original message.
		 * 
		 * 1. First, the label is hashed
		 * 2. y is calculated by getting the ascii value of the first byte of em (ord is the opposite of chr)
		 * 3. the maskedSeed is recovered from em
		 * 4. the maskedDB is recovered from em
		 * 5. **The seedMask used in encryption is recalculated by using the maskedDB as a seed for the same
		 * 	mask generation function that was used to create the seedMask in the first place.
		 * 6. The seed is recovered by un-applying the seedMask
		 * 7. The dbMask is calculated by using the value of the recovered seed as the seed for the same
		 * 	mask generation function that was used to create dbMask in the first place.
		 * 8. db is recovered by un-applying the dbMask
		 * 9. Now that db has been recovered, the original message and the hash can simply be recovered from db.
		 * 
		 * **If a label was used the recipient of the ciphertext can check that the label on the message that they
		 * receive is what they expect it to be. If it is not then they know that something went wrong and should
		 * discard the message.
		 */
	
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
	
		return substr($m, 1);
	}
}
?>