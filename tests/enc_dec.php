<?php
include_once("../RSA/RSA.php");
$bytes = 3;

for($i = 0; $i < 100; $i++){
	$keys = Key::generate_key_pair($bytes);
	$pub_key = $keys["public"];
	$priv_key = $keys["private"];
	echo("$i:\n");

	for($j = 0; $j < 100; $j++){
		$message = rand(0, pow(2, $bytes * 8));
		$c = RSA::encrypt($message, $pub_key);
		$m = RSA::decrypt($c, $priv_key);

		if($message != $m){
			echo("\n\nMessage: ".$message);
			echo("\nCipher Text: ".gmp_strval($c));
			echo("\nDecrypted Text: ".gmp_strval($m));
			
			echo("\n\nPrivateKey:\n".$priv_key);
			echo("\n\nPublicKey:\n".$pub_key);
		}
		else{
			echo("\t$j: success!\n");	
		}
	}
}
?>
