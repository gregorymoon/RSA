<?php
class PrivateKey extends Key{
	public $d_p;
	public $d_q;
	public $p;
	public $q;
	public $q_inv;
	private $d;
	
	function __construct($p, $q, $d){
		$this->p = $p;
		$this->q = $q;
		$this->d = $d;
		
		$this->d_p = gmp_mod($d, gmp_sub($p, gmp_init("1")));
		$this->d_q = gmp_mod($d, gmp_sub($q, gmp_init("1")));
		$this->q_inv = parent::invmod($q, $p);
	}
	
	function __toString(){
		$ret = "p: $this->p\nq: $this->q\nd_p: $this->d_p\nd_q: $this->d_q\nq_inv: $this->q_inv\nd: $this->d";	
		
		return $ret;
	}
}
?>