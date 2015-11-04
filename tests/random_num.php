<?php
$num_bytes = 1;

$max = gmp_pow(strval(2), 8 * $num_bytes);
$nums = array();
echo("\nMax: ".$max);

for($i = 0; $i < $max; $i++){
  $prime = openssl_random_pseudo_bytes($num_bytes);
  $unpacked = unpack("H*", $prime);
  $num = gmp_init(hexdec($unpacked[1]));
  
  if(in_array($num, $nums)){
  	echo("\nNumber Repeated:$num");
  }
  else{
  	array_push($nums, $num);
	echo("\n".$num);
  }
}

?>