<?php
include_once("Key.php");
class PublicKey extends Key{
	public $e;
	
	protected function __construct($vals){
		parent::__construct($vals);
		$this->calculateExponent($vals["p"], $vals["q"], $vals["totient"]);
	}
	
	private function calculateExponent($p, $q, $totient){
		$min = gmp_init(3);
		$max = gmp_sub($this->n, gmp_init(1));
		$check = gmp_init(1);
		
		//RECOMMENDED IN docs/RSA-survey.pdf pg 6 section 4
		$e = gmp_init(65537);
		
		do{
			//something
		}while(gmp_cmp(gmp_gcd($e, $totient), $check) != 0);
		
		$this->e = $e;
	}
	
	//from http://blog.ideashower.com/post/15147136549/leastgreatest-common-mulitple-lcmgcm-in-php-and-javascri
	private static function lcm($a, $b) {
		return gmp_mul(gmp_div($a, PublicKey::gcf($a,$b)), $b);
	}
	
	//from http://blog.ideashower.com/post/15147136549/leastgreatest-common-mulitple-lcmgcm-in-php-and-javascri
	private static function gcf($a, $b) {
		if(gmp_cmp($b, gmp_init(0)) == 0){
			return $a;
		}
		else{
			$temp = gmp_mod($a, $b);	
			return PublicKey::gcf($b, $temp);
		}

//		return (gmp_cmp($b, gmp_init(0)) == 0) ? ($a) : (PublicKey::gcf($b, gmp_mod($a, $b)));
	}
}
?>