<?php

if (isset($_SERVER['HTTPS']) )
{
      echo "SECURE: This page is being accessed through a secure connection.";
}
else
{
      echo "UNSECURE: This page is being access through an unsecure connection.";
}

// Create the keypair
$res=openssl_pkey_new();

// Get private key
openssl_pkey_export($res, $privatekey);

// Get public key
$publickey=openssl_pkey_get_details($res);
$publickey=$publickey["key"];

echo "Private Key:$privatekey Public Key:$publickey\n";

$cleartext = '1234 5678 9012 3456';

echo "Clear text:$cleartext\n";

openssl_public_encrypt($cleartext, $crypttext, $publickey);

echo "Crypt text:$crypttext\n";

openssl_private_decrypt($crypttext, $decrypted, $privatekey);

echo "Decrypted text:$decrypted\n";
?>
