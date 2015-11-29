<?php
include_once("Key.php");
class PrivateKey extends Key{
	public $d;
	public $dp;
	public $dq;
	public $qInv;
	public $p;
	public $q;
	
	function __construct($vals){
		parent::__construct($vals);
		$this->p = $vals["p"];
		$this->q = $vals["q"];

		$this->calculateD($vals);
		$this->calculateDP();
		$this->calculateDQ();
		$this->calculateQInv();
	}
	
	private function calculateD($vals){
		$this->d = PrivateKey::invmod($vals["e"], $vals["totient"]);
	}
	
	private function calculateDP(){
		$this->dp = gmp_mod($this->d, gmp_sub($this->p, gmp_init(1)));
	}

	private function calculateDQ(){
		$this->dq = gmp_mod($this->d, gmp_sub($this->q, gmp_init(1)));
	}
	
	private function calculateQInv(){
		$this->qInv = PrivateKey::invmod($this->q, $this->p);
	}
	
	private static function invmod($a,$n){
		$zero = gmp_init(0);
		$one = gmp_init(1);
		
		if (gmp_cmp($n, $zero) < 0){
			$n = gmp_neg($n);
		}

		if (gmp_cmp($a, 0) < 0){
			$a = gmp_sub($n, gmp_mod(gmp_neg($a), $n));
		}

		$t = $zero; 
		$nt = gmp_init(1);
		$r = $n;
		$nr = gmp_mod($a, $n);

		while (gmp_cmp($nr, $zero) != 0) {
			$quot= gmp_div($r, $nr);
			$tmp = $nt;  
			$nt = gmp_sub($t, gmp_mul($quot, $nt));  
			$t = $tmp;
			$tmp = $nr;  
			$nr = gmp_sub($r, gmp_mul($quot,$nr));
			$r = $tmp;
		}
		
		if (gmp_cmp($r, $one) > 0){
			return -1;
		}
		if (gmp_cmp($t, $zero) < 0){
			$t = gmp_add($t, $n);
		}
		
		return $t;
	}
}
?>