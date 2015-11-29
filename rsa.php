<?php
include_once("RSA/RSAES_OAEP.php");

if (isset($_SERVER['HTTPS']) )
{
      echo "SECURE: This page is being accessed through a secure connection.\n\n";
}
else
{
      echo "UNSECURE: This page is being access through an unsecure connection.\n\n";
}

// Create the keypair
/*
$res = openssl_pkey_new();

if(!$res){
	echo("\n".openssl_error_string());
}


// Get private key
openssl_pkey_export($res, $privatekey);

*/
// Get public key
/*
$publickey=openssl_pkey_get_details($res);
$publickey=$publickey["key"];

echo "Private Key:$privatekey Public Key:$publickey\n";

$cleartext = '1234 5678 9012 3456';

echo "Clear text:$cleartext\n";

openssl_public_encrypt($cleartext, $crypttext, $publickey);

echo "Crypt text:$crypttext\n";

openssl_private_decrypt($crypttext, $decrypted, $privatekey);

echo "Decrypted text:$decrypted\n";
*/

$bytes = 1;
$message = 16;

$keys = RSA::generate_key_pair($bytes);
$pub_key = $keys["public"];
$priv_key = $keys["private"];

$c = RSAES_OAEP::encrypt($pub_key, $message);
$m = RSAES_OAEP::decrypt($priv_key, $c);
/*
$c = RSA::RSAEP($message, $pub_key);
$m = RSA::RSADP($c, $priv_key);
*/

echo("Plaintext:$message\n");
echo("Ciphertext:$c\n");
echo("Decrypted Text:$m\n");
?>
