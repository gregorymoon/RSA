<?php
class PublicKey extends Key{
	public $n;
	public $e;
	private $tn;
	
	function __construct($n, $e, $tn){
		$this->n = $n;
		$this->e = $e;
		$this->tn = $tn;
	}
	
	function __toString(){
		$ret = "n: $this->n\ne: $this->e\ntn: $this->tn";
		
		return $ret;
	}
}
?>