<?php

//we assume each post and request element is a string
//this ensures that assumption is valid

foreach($_POST as $k => $v) {
	$_POST[$k] = print_r($v, true);
}

foreach($_REQUEST as $k => $v) {
	$_REQUEST[$k] = print_r($v, true);
}

?>
