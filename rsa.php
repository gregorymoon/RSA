<?php
include_once("RSA/RSAES_OAEP.php");

if(isset($_SERVER['HTTPS'])){
	echo "This page is being accessed through a secure connection.\n\n";
}
else{
	echo "This page is being access through an unsecure connection.\n\n";
}

$message = "Lorem ipsum dolor blah blah blah";

$keys = RSA::generateKeyPair();
$pub_key = $keys["public"];
$priv_key = $keys["private"];

$c = RSAES_OAEP::encrypt($pub_key, $message);
$m = RSAES_OAEP::decrypt($priv_key, $c);

echo("\nPlaintext:$message\n");
echo("Ciphertext:$c\n");
echo("Decrypted Text:$m\n");
?>
